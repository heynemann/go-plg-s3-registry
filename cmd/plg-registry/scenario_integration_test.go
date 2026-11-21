//go:build integration

package main_test

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/heynemann/go-plg-s3-registry/dataplane"
	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
	"github.com/heynemann/go-plg-s3-registry/internal/testcontract"
)

func TestRegistryLifecycle(t *testing.T) {
	f := startLifecycle(t)
	var nowA, nowB atomic.Int64
	o11y := newTelemetry(t)
	a := f.host(4*64<<20, &nowA, o11y.config("host-a"))
	b := f.host(64<<20, &nowB, o11y.config("host-b"))
	_, err := a.Select([]byte("user-2"), nil)
	var unavailable *dataplane.AdmissionError
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, dataplane.Hold, unavailable.Action)
	out, err := f.client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(environmentBucket)})
	require.NoError(t, err)
	require.Empty(t, out.Contents, "publishing releases must not write to the serving environment")

	plan := rollout.Plan{Scope: f.deployment.Scope, Candidate: f.first, Unavailable: "hold"}
	planID, approval := f.approve(plan)
	first := rollout.Command{ID: "initial", PlanID: planID, ApprovalID: approval, Reason: "first deployment"}
	f.control("proposer", 3, "rollout", "activate", "--command", f.file(first))
	f.control("decider", 3, "rollout", "activate", "--command", f.file(rollout.Command{
		ID: "unapproved-plan", PlanID: "sha256:" + strings.Repeat("b", 64), ApprovalID: approval, Reason: "approval does not match",
	}))
	initial := f.execute("decider", "rollout", "activate", first)
	require.Equal(t, uint64(1), initial.Generation)
	// A freshly committed and verified plan cannot serve until it has a lease.
	_ = a.Sync(t.Context())
	_, err = a.Select([]byte("user-2"), nil)
	require.ErrorIs(t, err, dataplane.ErrStale)
	short := decodeJSON[struct {
		Expiry time.Time `json:"expires_at"`
	}](t,
		f.control("renewer", 0, "freshness", "renew", "--duration", "1m")).Expiry
	require.NoError(t, a.Sync(t.Context()))
	firstPin := persisted(t, f.dir, selectReceipt(t, a, "US", f.first.Digest))
	require.Equal(t, short, a.Status().ExpiresAt)
	f.control("decider", 3, "freshness", "renew", "--duration", "10m")
	long := f.renew()
	require.True(t, long.After(short))
	require.NoError(t, a.Sync(t.Context()))
	require.NoError(t, b.Sync(t.Context()))
	require.Equal(t, long, a.Status().ExpiresAt)
	invokeRule(t, a, firstPin, false, false)
	invokeRule(t, b, selectReceipt(t, b, "US", f.first.Digest), false, false)

	upgrade := rollout.Plan{Scope: f.deployment.Scope, Candidate: f.second, Baseline: f.first, Unavailable: "hold",
		Target: target.Spec{Version: 1, Expression: `region == "EU"`, Attributes: map[string]string{"region": "string"}, Seed: strings.Repeat("0", 64)},
		Rungs:  []uint16{2500, 10000}, Evidence: []string{"https://example.com/adoption"}, StopConditions: []string{"incorrect outcome"}}
	planID, approval = f.approve(upgrade)
	warm := f.execute("decider", "rollout", "activate", rollout.Command{ID: "upgrade", Expected: initial.DecisionID,
		PlanID: planID, ApprovalID: approval, Reason: "warm the candidate at zero"})
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	require.Equal(t, "warming", a.Status().Phase)
	require.Len(t, a.Status().Residents, 2, "candidate must actually be warm at zero")
	invokeRule(t, a, selectReceipt(t, a, "EU", f.first.Digest), false, false)
	require.Error(t, b.Sync(t.Context()), "one resident fits but the two version overlap does not")
	require.Equal(t, warm.DecisionID, b.Status().Observed.Decision)
	require.Equal(t, initial.DecisionID, b.Status().Effective.Decision)
	invokeRule(t, b, selectReceipt(t, b, "EU", f.first.Digest), false, false)

	preview := decodeJSON[struct{ target.Result }](t, f.control("", 0, "rollout", "preview", "--plan", f.file(upgrade),
		"--subject", "user-2", "--attrs", f.file(map[string]string{"region": "EU"}), "--rung", "2500"))
	require.Equal(t, target.Result{Match: true, Bucket: 2006, Candidate: true}, preview.Result)
	paused := f.execute("responder", "rollout", "pause", rollout.Command{ID: "pause", Expected: warm.DecisionID, Reason: "freeze while checking", Incident: "incident-1"})
	f.control("decider", 2, "rollout", "advance", "--command", f.file(rollout.Command{ID: "paused-advance", Expected: paused.DecisionID, ApprovalID: approval,
		Rung: 2500, Reason: "should not apply", Evidence: upgrade.Evidence}))
	resumed := f.execute("decider", "rollout", "resume", rollout.Command{ID: "resume", Expected: paused.DecisionID, ApprovalID: approval, Reason: "ready to ramp"})
	advance := rollout.Command{ID: "first-rung", Expected: resumed.DecisionID, ApprovalID: approval, Rung: 2500,
		Reason: "manual after evidence review", Evidence: upgrade.Evidence}
	jump := advance
	jump.ID, jump.Rung = "skip-rung", 10000
	f.control("decider", 2, "rollout", "advance", "--command", f.file(jump))
	winner := f.raceRung(advance)
	replay := decodeJSON[appliedJSON](t, f.control("decider", 0, "rollout", "advance", "--command", f.file(winner.Command)))
	require.True(t, replay.AlreadyApplied)
	require.Equal(t, winner.DecisionID, replay.Decision.DecisionID)
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	candidatePin := persisted(t, f.dir, selectReceipt(t, a, "EU", f.second.Digest))
	invokeRule(t, a, candidatePin, false, true)
	require.NoError(t, a.ReportCorrectness(t.Context(), candidatePin, dataplane.Incorrect))
	invokeRule(t, a, selectReceipt(t, a, "US", f.first.Digest), false, false)
	invalid, err := a.Select([]byte("user-2"), nil)
	require.NoError(t, err)
	require.Equal(t, f.first.Digest, invalid.Digest, "missing targeting input cannot select the candidate")
	invokeRule(t, a, firstPin, true, false)

	full := f.execute("decider", "rollout", "advance", rollout.Command{ID: "full-scope", Expected: winner.DecisionID, ApprovalID: approval,
		Rung: 10000, Reason: "full scoped exposure", Evidence: upgrade.Evidence})
	finished := f.execute("decider", "rollout", "finish", rollout.Command{ID: "finish", Expected: full.DecisionID, ApprovalID: approval, Reason: "scoped finish"})
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	invokeRule(t, a, selectReceipt(t, a, "EU", f.second.Digest), false, true)
	invokeRule(t, a, selectReceipt(t, a, "US", f.first.Digest), false, false)
	setDefault := rollout.Command{ID: "make-default", Expected: finished.DecisionID, PlanID: planID, ApprovalID: approval, Reason: "global default"}
	f.control("decider", 2, "rollout", "set-default", "--command", f.file(setDefault))
	global := upgrade
	global.AllowDefault = true
	setDefault.PlanID, setDefault.ApprovalID = f.approve(global)
	defaulted := f.execute("decider", "rollout", "set-default", setDefault)
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	invokeRule(t, a, selectReceipt(t, a, "US", f.second.Digest), false, true)
	rolled := f.execute("responder", "rollout", "rollback", rollout.Command{ID: "rollback", Expected: defaulted.DecisionID, Reason: "return to known release", Incident: "incident-2"})
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	invokeRule(t, a, selectReceipt(t, a, "EU", f.first.Digest), false, false)
	// A newly started host on the post-rollback generation does not have the
	// historical candidate warm: it proves ancestry and admits it cold.
	cold := f.host(4*64<<20, &nowA, o11y.config("cold-host"))
	require.NoError(t, cold.Sync(t.Context()))
	require.Len(t, cold.Status().Residents, 1)
	invokeRule(t, cold, candidatePin, true, true)
	old := candidatePin
	old.SelectedAt = time.Now().Add(-2 * time.Hour)
	require.ErrorIs(t, cold.InvokeRetry(t.Context(), old, noCall(t)), dataplane.ErrReceiptExpired)

	// Warm again to force the small host to lag. It must enforce a native deny
	// even if the plan is not serving locally and the new head has no lease.
	warm = f.execute("decider", "rollout", "activate", rollout.Command{ID: "warm-again", Expected: rolled.DecisionID, PlanID: planID, ApprovalID: approval, Reason: "repeat safely"})
	f.renew()
	require.ErrorIs(t, b.Sync(t.Context()), dataplane.ErrCapacity)
	const backup = "registry-recovery"
	newBucket(t, f.client, backup)
	snapshot(t, f.client, environmentBucket, backup)
	finish, inFlight := admitInFlight(t, a, candidatePin)
	defer finish()
	denied := f.execute("responder", "release", "quarantine", rollout.Command{ID: "deny", Expected: warm.DecisionID, Digest: f.second.Digest, Incident: "incident-3", Reason: "unsafe release"})
	_ = b.Sync(t.Context())
	require.Equal(t, denied.DecisionID, b.Status().Observed.Decision)
	require.ErrorIs(t, b.InvokeRetry(t.Context(), candidatePin, noCall(t)), dataplane.ErrQuarantined)
	_ = a.Sync(t.Context())
	require.ErrorIs(t, a.InvokeRetry(t.Context(), candidatePin, noCall(t)), dataplane.ErrQuarantined)
	finish()
	require.NoError(t, <-inFlight, "an already admitted invocation may finish")
	// A disconnected host still has its last valid authority; its clock is
	// advanced independently of issuer time without waiting or sleeping.
	invokeRule(t, cold, candidatePin, true, true)
	nowA.Add(int64(11 * time.Minute))
	require.ErrorIs(t, cold.InvokeRetry(t.Context(), candidatePin, noCall(t)), dataplane.ErrStale)
	_, err = cold.Select([]byte("user-2"), nil)
	require.ErrorIs(t, err, dataplane.ErrStale)
	nowA.Store(0)
	f.control("responder", 3, "release", "restore", "--command", f.file(rollout.Command{ID: "restore-denied", Expected: denied.DecisionID,
		Digest: f.second.Digest, ApprovalID: approval, Reason: "responder must not restore"}))
	restoreApproval := decodeJSON[struct {
		ID string `json:"approval_id"`
	}](t, f.control("approver", 0, "rollout", "approve-restore",
		"--digest", f.second.Digest, "--expected", denied.DecisionID))
	restored := f.execute("decider", "release", "restore", rollout.Command{ID: "restore", Expected: denied.DecisionID, Digest: f.second.Digest,
		ApprovalID: restoreApproval.ID, Reason: "remove the deny without reactivation"})
	f.renew()
	require.NoError(t, a.Sync(t.Context()))
	invokeRule(t, a, selectReceipt(t, a, "EU", f.first.Digest), false, false)
	invokeRule(t, a, candidatePin, true, true)
	checkpoint := f.execute("responder", "release", "quarantine", rollout.Command{ID: "deny-again", Expected: restored.DecisionID,
		Digest: f.second.Digest, Incident: "incident-4", Reason: "new incident before recovery"})
	f.assertHistory(winner, checkpoint)
	f.publisherLifecycle()
	f.recoveryLifecycle(backup, checkpoint, candidatePin, o11y)
	o11y.verify(t)
}

func admitInFlight(t *testing.T, h *dataplane.Host[testcontract.Rule], pin dataplane.Receipt) (func(), <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	gate := make(chan struct{})
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.InvokeRetry(ctx, pin, func(plugin testcontract.Rule) error {
			close(entered)
			select {
			case <-gate:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
			ok, err := plugin.Accept(ctx, "silver")
			if err == nil && !ok {
				return errors.New("in-flight call was switched to the wrong digest")
			}
			return err
		})
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("could not admit the invocation before quarantine: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for admission before quarantine")
	}
	return func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}, result
}

func noCall(t *testing.T) func(testcontract.Rule) error {
	t.Helper()
	return func(testcontract.Rule) error { t.Error("unauthorized guest call was admitted"); return nil }
}

func (f *lifecycle) raceRung(input rollout.Command) decisionJSON {
	f.t.Helper()
	other := input
	other.ID = "competing-rung"
	args := [2][]string{
		f.args("decider", "rollout", "advance", "--command", f.file(input)),
		f.args("decider", "rollout", "advance", "--command", f.file(other)),
	}
	type result struct {
		data []byte
		err  error
	}
	responses := make(chan result, 2)
	start := make(chan struct{})
	for _, argv := range args {
		cmd := command(f.t, f.dir, nil, f.cli, argv...)
		go func() { <-start; data, err := cmd.CombinedOutput(); responses <- result{data, err} }()
	}
	close(start)
	var winner decisionJSON
	for range 2 {
		response := <-responses
		if response.err == nil {
			require.Empty(f.t, winner.DecisionID, "only one competing decision may apply")
			winner = decodeJSON[appliedJSON](f.t, response.data).Decision
			continue
		}
		var exit *exec.ExitError
		require.ErrorAs(f.t, response.err, &exit)
		require.Equal(f.t, 4, exit.ExitCode(), "%s", response.data)
	}
	require.Equal(f.t, input.Rung, winner.State.Rung)
	return winner
}

func (f *lifecycle) assertHistory(winner, checkpoint decisionJSON) {
	f.t.Helper()
	history := decodeJSON[struct {
		Decisions []decisionJSON `json:"decisions"`
	}](f.t, f.control("", 0, "history")).Decisions
	require.Len(f.t, history, int(checkpoint.Generation))
	require.Equal(f.t, checkpoint.DecisionID, history[0].DecisionID)
	var rampCount int
	for i, d := range history {
		if i+1 < len(history) {
			require.Equal(f.t, history[i+1].DecisionID, d.Previous)
		}
		if d.Command.Rung == 2500 {
			rampCount++
			require.Equal(f.t, winner.DecisionID, d.DecisionID)
			require.Equal(f.t, "local:decider", d.Actor)
		}
	}
	require.Equal(f.t, 1, rampCount, "losing signed decisions are not applied history")
}

func (f *lifecycle) publisherLifecycle() {
	f.t.Helper()
	type status struct {
		Revision string   `json:"revision"`
		Affected []string `json:"affected_digests"`
	}
	old := decodeJSON[status](f.t, f.control("", 0, "publisher", "status"))
	private, public := signingKey(f.t, f.dir, "replacement")
	f.keys["replacement"] = private
	data, err := os.ReadFile(public)
	require.NoError(f.t, err)
	der, _ := pem.Decode(data)
	require.NotNil(f.t, der)
	newPublisher := f.file(registry.Publisher{Repository: "example/author", Workflow: workflow(), KeyID: "local:replacement", PublicKey: der.Bytes})
	rotated := decodeJSON[status](f.t, f.control("publisher-admin", 0, "publisher", "rotate", "--expected", old.Revision, "--publisher", newPublisher))
	f.publish("v3.0.0", f.secondArtifact, f.secondCommit, "author", 3)
	release := f.publish("v3.0.0", f.secondArtifact, f.secondCommit, "replacement", 0)
	require.Equal(f.t, f.second.Digest, release.Digest)
	suspended := decodeJSON[status](f.t, f.control("publisher-admin", 0, "publisher", "suspend", "--expected", rotated.Revision))
	require.Equal(f.t, []string{f.second.Digest}, suspended.Affected)
	f.publish("v4.0.0", f.secondArtifact, f.secondCommit, "replacement", 3)
	f.publication(0, "release", "inspect", "--plugin", "eligibility", "--version", f.first.Version)
}

func (f *lifecycle) recoveryLifecycle(backup string, checkpoint decisionJSON, denied dataplane.Receipt, signals *telemetryFixture) {
	f.t.Helper()
	fromCLI := decodeJSON[struct {
		Checkpoint rollout.RecoveryEvidence `json:"checkpoint"`
	}](f.t, f.control("", 0, "recovery", "evidence")).Checkpoint
	require.Equal(f.t, checkpoint.DecisionID, fromCLI.Decision)
	f.deployment.Recovery = &fromCLI
	f.deployment.Scope.Epoch = "recovered"
	f.deployment.Destination.Bucket = backup
	f.config = f.file(f.deployment)
	f.control("renewer", 5, "freshness", "renew", "--duration", "10m")
	f.control("recoverer", 4, "recovery", "reconcile")
	snapshot(f.t, f.client, environmentBucket, backup)
	recovered := decodeJSON[appliedJSON](f.t, f.control("recoverer", 0, "recovery", "reconcile"))
	require.Equal(f.t, checkpoint.DecisionID, recovered.Decision.Previous)
	require.Equal(f.t, checkpoint.Generation+1, recovered.Decision.Generation)
	f.renew()
	var clock atomic.Int64
	h := f.host(4*64<<20, &clock, signals.config("recovered-host"))
	require.NoError(f.t, h.Sync(f.t.Context()))
	invokeRule(f.t, h, selectReceipt(f.t, h, "EU", f.first.Digest), false, false)
	require.ErrorIs(f.t, h.InvokeRetry(f.t.Context(), denied, noCall(f.t)), dataplane.ErrQuarantined)
}
