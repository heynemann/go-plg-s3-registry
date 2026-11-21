package rollout

import (
	"strings"
	"testing"
	"time"
)

func TestResponderSnapshotAuthorization(t *testing.T) {
	baseline := Ref{Version: "1", Digest: "sha256:" + strings.Repeat("a", 64)}
	candidate := Ref{Version: "2", Digest: "sha256:" + strings.Repeat("b", 64)}
	quarantined := "sha256:" + strings.Repeat("c", 64)
	at := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	prev := Decision{Scope: Scope{Registry: "registry", Environment: "production", Plugin: "sample", Epoch: "epoch"}, ID: baseline.Digest, Generation: 7, At: at, State: State{
		Plan:   Plan{Baseline: baseline, Candidate: candidate, Rungs: []uint16{100, 500}},
		PlanID: "approved-plan", ApprovalID: "approval", Default: baseline,
		Phase: "ramping", Rung: 100, Denied: []string{quarantined},
	}}

	paused := prev.State
	paused.Phase = "paused"
	rolledBack := prev.State
	rolledBack.Phase, rolledBack.Rung = "rolled-back", 0
	rolledBack.Retired = []Retired{{Release: candidate, At: at.Add(time.Second)}}
	denied := prev.State
	denied.Denied = []string{candidate.Digest, quarantined}

	for _, tc := range []struct {
		name, action, digest string
		state                State
		edit                 func(*Decision)
		inapplicable         bool
	}{
		{name: "pause", action: "pause", state: paused},
		{name: "rollback", action: "rollback", state: rolledBack},
		{name: "quarantine", action: "quarantine", digest: candidate.Digest, state: denied},
		{name: "default change", action: "pause", state: paused, edit: func(d *Decision) { d.State.Default = candidate }},
		{name: "rung change", action: "pause", state: paused, edit: func(d *Decision) { d.State.Rung = 500 }},
		{name: "plan change", action: "pause", state: paused, edit: func(d *Decision) { d.State.Plan.AllowDefault = true }},
		{name: "approval change", action: "pause", state: paused, edit: func(d *Decision) { d.State.ApprovalID = "another" }},
		{name: "deny removal", action: "quarantine", digest: candidate.Digest, state: denied, edit: func(d *Decision) { d.State.Denied = []string{candidate.Digest} }},
		{name: "retirement removal", action: "rollback", state: rolledBack, edit: func(d *Decision) { d.State.Retired = nil }},
		{name: "backdated pause", action: "pause", state: paused, edit: func(d *Decision) { d.At = prev.At.Add(-time.Second) }},
		{name: "repeated quarantine", action: "quarantine", digest: quarantined, state: prev.State, inapplicable: true},
		{name: "missing incident", action: "pause", state: paused, edit: func(d *Decision) { d.Command.Incident = "" }},
		{name: "wrong expected digest", action: "pause", state: paused, edit: func(d *Decision) { d.Command.Expected = candidate.Digest }},
		{name: "wrong predecessor", action: "pause", state: paused, edit: func(d *Decision) {
			d.Previous, d.Command.Expected = candidate.Digest, candidate.Digest
		}},
		{name: "cross-epoch incident", action: "pause", state: paused, edit: func(d *Decision) { d.Scope.Epoch = "new-epoch" }},
		{name: "skipped generation", action: "pause", state: paused, edit: func(d *Decision) { d.Generation++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Decision{
				Scope: prev.Scope, Previous: prev.ID, Generation: prev.Generation + 1,
				Command: Command{ID: "command", Action: tc.action, Expected: prev.ID, Reason: "test", Incident: "incident", Digest: tc.digest},
				At:      at.Add(time.Second), State: tc.state,
			}
			if tc.edit != nil {
				tc.edit(&d)
			}
			if got, want := (Service{}).validResponderSnapshot(t.Context(), d, prev), tc.edit == nil && !tc.inapplicable; got != want {
				t.Fatalf("responder snapshot accepted = %t, want %t", got, want)
			}
		})
	}
}
