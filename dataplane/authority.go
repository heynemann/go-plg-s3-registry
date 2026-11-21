package dataplane

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"
	"time"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

// observe moves only the verified floor. It does not wait on artifact I/O or
// runtime warm-up; callers staging an older revision cannot overwrite it.
func (h *Host[T]) observe(ctx context.Context) error {
	wall, monotonic := h.cfg.Now(), time.Now()
	obs, err := h.authority.Observe(ctx)
	if err != nil && obs.Decision.ID == "" {
		return err
	}
	d := obs.Decision
	if d.Scope != h.scope || d.Generation == 0 || !digestOK(d.ID) {
		return registry.ErrCorrupt
	}

	// Use both the wall deadline and a real monotonic deadline. Measured time
	// spent observing also counts: wall-clock corrections cannot buy a longer
	// lease, including when a delayed observation finishes after a newer one.
	deadline := obs.ExpiresAt.Add(-h.cfg.MaxClockSkew)
	now, end := h.cfg.Now(), time.Now()
	localDeadline := monotonic.Add(min(deadline.Sub(wall), h.cfg.Trust.MaxLease))
	localDeadline = minTime(localDeadline, end.Add(deadline.Sub(now)))
	fresh := err == nil && !obs.ProofAt.IsZero() && !obs.ExpiresAt.IsZero() && now.Before(deadline) && end.Before(localDeadline)

	for {
		if h.closed.Load() {
			return ErrClosed
		}
		// A proof read can fail after verifying the committed decision.
		// Do not lose direct-successor containment to cancellation or that error.
		prior := h.view.Load()
		p := prior.observed
		if d.Generation < p.Generation || d.Generation == p.Generation && d.ID != p.ID {
			return registry.ErrConflict
		}
		if p.ID != "" && d.Generation > p.Generation && (d.Previous != p.ID || d.Generation != p.Generation+1) {
			if _, err := h.authority.DecisionAt(ctx, p.ID, d.ID); err != nil {
				if errors.Is(err, registry.ErrNotFound) {
					return registry.ErrConflict
				}
				return err
			}
		}
		newProof := fresh && (prior.proof.proofAt.IsZero() || obs.ProofAt.After(prior.proof.proofAt) ||
			d.Generation > prior.proof.generation && obs.ProofAt.Equal(prior.proof.proofAt))
		if d.ID == p.ID && !newProof {
			if err != nil {
				h.failure(d.ID, reason(err))
			}
			return err
		}
		next := *prior
		next.observed = d
		if d.ID != p.ID {
			next.observedProof = makeProof(d)
			if len(d.State.Retired) != 0 {
				next.retired = make(map[rollout.Ref]struct{}, len(d.State.Retired))
				for _, r := range d.State.Retired {
					next.retired[r.Release] = struct{}{}
				}
			} else {
				next.retired = nil
			}
		}
		if newProof {
			next.proof = lease{generation: d.Generation, proofAt: obs.ProofAt, deadline: deadline, monotonic: localDeadline, expired: new(atomic.Bool)}
			// Clearing a local deny requires a live proof for the current
			// revision, never just an older still-valid lease.
			next.denied = mergeDenies(nil, d.State.Denied)
			if prior.effective != nil && prior.effective.decision.ID == d.ID {
				updated := *prior.effective
				updated.lease = next.proof
				next.effective = &updated
			}
		} else {
			next.denied = mergeDenies(prior.denied, d.State.Denied)
		}
		if err != nil {
			next.failure = reason(err)
		}
		if h.view.CompareAndSwap(prior, &next) {
			return err
		}
	}
}

func mergeDenies(prior map[string]struct{}, incoming []string) map[string]struct{} {
	if len(incoming) == 0 {
		return prior
	}
	var out map[string]struct{}
	for _, d := range incoming {
		if _, denied := prior[d]; denied {
			continue
		}
		if out == nil {
			out = make(map[string]struct{}, len(prior)+len(incoming))
			maps.Copy(out, prior)
		}
		out[d] = struct{}{}
	}
	if out == nil {
		return prior
	}
	return out
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (h *Host[T]) failure(revision, failure string) {
	for {
		prior := h.view.Load()
		if prior.observed.ID != revision || prior.failure == failure {
			return
		}
		next := *prior
		next.failure = failure
		if h.view.CompareAndSwap(prior, &next) {
			return
		}
	}
}

func (v *authorityView) quarantined(digest string) bool { _, ok := v.denied[digest]; return ok }

// permitsAssignment intersects a lagging route with what the highest observed
// state can authorize. A changed predicate/seed or a reduced rung cannot grant
// any of the old candidate's cohort on the strength of the old proof.
func (v *authorityView) permitsAssignment(r *route, ref rollout.Ref, lane Lane) bool {
	if ref == (rollout.Ref{}) || v.quarantined(ref.Digest) {
		return false
	}
	s := v.observed.State
	if ref == s.Default {
		return true
	}
	return lane == CandidateLane && ref == v.observedProof.candidate && s.PlanID == r.decision.State.PlanID && s.Rung >= r.decision.State.Rung
}

// callable checks reference membership after receipt freshness, quarantine and
// applied-decision evidence are checked. A retirement timestamp is assigned
// before the head CAS, so it cannot bound when the old route selected a pin.
func (v *authorityView) callable(ref rollout.Ref) bool {
	if ref == (rollout.Ref{}) {
		return false
	}
	if ref == v.observedProof.def || ref == v.observedProof.candidate {
		return true
	}
	_, found := v.retired[ref]
	return found
}

func revisionOf(d rollout.Decision) Revision {
	return Revision{Generation: d.Generation, Decision: d.ID, Epoch: d.Scope.Epoch}
}

func digestOK(v string) bool {
	if len(v) != 71 || v[:7] != "sha256:" {
		return false
	}
	for i := 7; i < len(v); i++ {
		b := v[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

// reason uses a closed vocabulary; storage/provider/guest/policy errors can
// contain application data and never enter SDK status or exporters verbatim.
func reason(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, ErrQuarantined):
		return "quarantined"
	case errors.Is(err, ErrReceiptExpired):
		return "expired_receipt"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrCapacity):
		return "capacity"
	case errors.Is(err, ErrPolicy):
		return "policy"
	case errors.Is(err, registry.ErrConflict):
		return "authority_conflict"
	case errors.Is(err, registry.ErrDenied), errors.Is(err, registry.ErrCorrupt), errors.Is(err, registry.ErrInvalid):
		return "verification"
	case errors.Is(err, registry.ErrNotFound):
		return "not_found"
	case errors.Is(err, errWarm):
		return "warm_failed"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	default:
		return "error"
	}
}
