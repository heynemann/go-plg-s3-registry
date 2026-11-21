package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

func TestAdmissionRejectsWithoutDispatch(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	decision := "sha256:" + strings.Repeat("b", 64)
	scope := rollout.Scope{Registry: "test", Environment: "prod", Plugin: "eligibility", Epoch: "initial"}
	pin := Receipt{Version: 1, Registry: scope.Registry, Environment: scope.Environment, Plugin: scope.Plugin,
		Epoch: scope.Epoch, Digest: digest, Generation: 2, Decision: decision, SelectedAt: now, Lane: CandidateLane}
	tests := []struct {
		name   string
		change func(*Receipt, *authorityView)
		want   error
	}{
		{"other environment", func(r *Receipt, _ *authorityView) { r.Environment = "staging" }, ErrUnauthorized},
		{"receipt TTL boundary", func(r *Receipt, _ *authorityView) { r.SelectedAt = now.Add(-time.Hour) }, ErrReceiptExpired},
		{"quarantine before warm or proof", func(_ *Receipt, v *authorityView) {
			v.denied = map[string]struct{}{digest: {}}
			v.proof = lease{}
		}, ErrQuarantined},
		{"expired authority", func(_ *Receipt, v *authorityView) { v.proof.deadline = now }, ErrStale},
		{"older proof cannot start newly authorized pin", func(_ *Receipt, v *authorityView) { v.proof.generation = 1 }, ErrStale},
		{"not observed here", func(r *Receipt, _ *authorityView) { r.Generation++ }, ErrUnauthorized},
		{"digest not authorized by applied decision", func(r *Receipt, _ *authorityView) {
			r.Digest = "sha256:" + strings.Repeat("c", 64)
		}, ErrUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host[any]{scope: scope, cfg: Config{Now: func() time.Time { return now }, RetryHorizon: time.Hour, Unavailable: Hold}}
			r := pin
			d := rollout.Decision{ID: decision, Scope: scope, Generation: 2, At: now, State: rollout.State{
				Plan: rollout.Plan{Candidate: rollout.Ref{Version: "candidate", Digest: digest}}, Phase: "ramping", Rung: 500,
			}}
			v := &authorityView{observed: d, observedProof: makeProof(d), proof: lease{generation: 2,
				deadline: now.Add(time.Minute), monotonic: time.Now().Add(time.Minute), expired: new(atomic.Bool)}}
			tc.change(&r, v)
			h.view.Store(v)
			err := h.InvokeRetry(context.Background(), r, func(any) error { t.Fatal("blocked invocation ran the callback"); return nil })
			var blocked *AdmissionError
			if !errors.Is(err, tc.want) || !errors.As(err, &blocked) || blocked.Action != Hold {
				t.Fatalf("InvokeRetry: got %v, want hold with %v", err, tc.want)
			}
		})
	}
}

func TestLaggingRouteIntersectsLatestAuthority(t *testing.T) {
	baseline := rollout.Ref{Version: "baseline", Digest: "a"}
	candidate := rollout.Ref{Version: "candidate", Digest: "b"}
	plan := rollout.Plan{Baseline: baseline, Candidate: candidate}
	old := rollout.Decision{State: rollout.State{Plan: plan, PlanID: "old", Phase: "ramping", Rung: 500, Default: baseline}}
	effective := &route{decision: old, proof: makeProof(old)}
	rollback := rollout.Decision{State: rollout.State{Plan: plan, PlanID: "old", Phase: "rolled-back", Default: baseline}}
	v := &authorityView{observed: rollback, observedProof: makeProof(rollback), retired: map[rollout.Ref]struct{}{candidate: {}}}
	if !v.permitsAssignment(effective, baseline, BaselineLane) || v.permitsAssignment(effective, candidate, CandidateLane) {
		t.Fatal("observed rollback must stop assignment to the candidate before effective cutover")
	}
	if !v.callable(candidate) || v.callable(rollout.Ref{Version: "other", Digest: candidate.Digest}) {
		t.Fatal("rollback must preserve the exact retired binding, not just its digest")
	}
	v.denied = mergeDenies(v.denied, []string{baseline.Digest})
	if v.permitsAssignment(effective, baseline, BaselineLane) {
		t.Fatal("observed quarantine must override an otherwise ready and authorized baseline")
	}
	v.denied = mergeDenies(v.denied, nil)
	if !v.quarantined(baseline.Digest) {
		t.Fatal("a restoration without matching freshness must not remove local denies")
	}
}

func TestRetirementTimestampDoesNotExpireLivePin(t *testing.T) {
	at := time.Now().UTC()
	maxLease := time.Minute
	// The rollback CAS was delayed while the previous decision could still
	// be renewed and used for selection.
	selected := at.Add(2 * maxLease)
	now := selected.Add(time.Second)
	candidate := rollout.Ref{Version: "candidate", Digest: "sha256:" + strings.Repeat("a", 64)}
	previous := rollout.Decision{ID: "sha256:" + strings.Repeat("b", 64), Generation: 2, At: at.Add(-maxLease),
		Scope: rollout.Scope{Epoch: "initial"},
		State: rollout.State{Plan: rollout.Plan{Candidate: candidate}, Phase: "ramping", Rung: 500}}
	pin := Receipt{Epoch: previous.Scope.Epoch, Digest: candidate.Digest, Generation: previous.Generation,
		Decision: previous.ID, SelectedAt: selected, Lane: CandidateLane}
	v := &authorityView{
		observed: rollout.Decision{Generation: 3, At: at, State: rollout.State{
			Phase: "rolled-back", Retired: []rollout.Retired{{Release: candidate, At: at}},
		}},
		retired: map[rollout.Ref]struct{}{candidate: {}},
		proof: lease{generation: 3, deadline: now.Add(maxLease),
			monotonic: time.Now().Add(maxLease), expired: new(atomic.Bool)},
	}
	h := &Host[any]{cfg: Config{Now: func() time.Time { return now }, RetryHorizon: time.Hour,
		Trust: rollout.Trust{MaxLease: maxLease}}}
	if err := h.check(context.Background(), v, pin); err != nil {
		t.Fatalf("live receipt rejected: %v", err)
	}
	if ref, err := h.pinRef(v, pin, makeProof(previous)); err != nil || ref != candidate {
		t.Fatalf("pinRef: got (%v, %v), want (%v, nil)", ref, err, candidate)
	}
	v.denied = map[string]struct{}{candidate.Digest: {}}
	if err := h.check(context.Background(), v, pin); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantined receipt: got %v, want %v", err, ErrQuarantined)
	}
}

func TestExpiredProofDoesNotResurrectAfterClockRewind(t *testing.T) {
	wall := time.Now().UTC()
	l := lease{deadline: wall.Add(time.Minute), monotonic: time.Now().Add(time.Minute), expired: new(atomic.Bool)}
	if !l.fresh(wall) || l.fresh(wall.Add(time.Minute)) || l.fresh(wall) {
		t.Fatal("a proof must stop admitting at its deadline and remain expired across wall-clock rewind")
	}
}

func TestDispatchReferenceGuardsImmutableKey(t *testing.T) {
	r := &resident{}
	if !r.enter() || r.users.CompareAndSwap(0, retiredBit) {
		t.Fatal("a runtime key with a dispatch reference must not retire")
	}
	r.leave()
	if !r.users.CompareAndSwap(0, retiredBit) || r.enter() {
		t.Fatal("once marked for retirement a runtime key must not reacquire a reference")
	}
}
