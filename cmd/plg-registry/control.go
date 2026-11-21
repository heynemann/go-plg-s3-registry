package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
)

type controlOptions struct {
	global *options
	config string
}

func (o *controlOptions) addCommands(root, release *cobra.Command) {
	root.PersistentFlags().StringVar(&o.config, "config", "", "trusted v1 deployment JSON for control commands")
	rollouts := &cobra.Command{Use: "rollout", Short: "Preview, approve and change rollout state"}
	rollouts.AddCommand(o.preview(), o.propose(), o.approve(), o.approveRestore())
	for _, action := range []struct{ name, summary, role string }{
		{"activate", "Promote an exact release and activate its approved plan", deciderRole},
		{"advance", "Apply the next approved traffic rung", deciderRole},
		{"resume", "Resume a paused rollout", deciderRole},
		{"finish", "Finish a rollout without widening its audience", deciderRole},
		{"set-default", "Set the default with approval covering global exposure", deciderRole},
		{"pause", "Pause an in-progress rollout", responderRole},
		{"rollback", "Stop new candidate assignments", responderRole},
	} {
		rollouts.AddCommand(o.execute(action.name, action.summary, action.role))
	}
	release.AddCommand(
		o.execute("quarantine", "Deny new invocations of one digest", responderRole),
		o.execute("restore", "Remove a deny with fresh independent approval", deciderRole),
	)
	freshness := &cobra.Command{Use: "freshness", Short: "Issue a proof for the current committed head"}
	freshness.AddCommand(o.renew())
	publisher := &cobra.Command{Use: "publisher", Short: "Inspect and administer publication authority"}
	publisher.AddCommand(o.publisherStatus(), o.publisherChange("rotate"), o.publisherChange("suspend"))
	recovery := &cobra.Command{Use: "recovery", Short: "Record and reconcile a fenced recovery checkpoint"}
	recovery.AddCommand(o.recoveryEvidence(), o.reconcile())
	root.AddCommand(rollouts, freshness, publisher, recovery, o.status(), o.history())
}

func (o *controlOptions) command(use, short string, run func(context.Context, *cobra.Command) error) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: noArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if o.global.output != "text" && o.global.output != "json" {
			return invalidInput("output format must be text or json")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
		defer cancel()
		err := run(ctx, cmd)
		var control *controlError
		if err == nil || errors.As(err, &control) {
			return err
		}
		return &controlError{err: err}
	}}
}

func (o *controlOptions) output(cmd *cobra.Command, result any, format string, args ...any) error {
	if o.global.output == "json" {
		return writeJSON(cmd.OutOrStdout(), result)
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), format, args...)
	return err
}

type controlError struct {
	err     error
	current string
}

func (e *controlError) Error() string { return e.err.Error() }
func (e *controlError) Unwrap() error { return e.err }

func (e *controlError) failure() (string, int) {
	switch {
	case errors.Is(e.err, registry.ErrInvalid):
		return e.err.Error(), 2
	case errors.Is(e.err, registry.ErrDenied):
		return "control authority, approval or release verification denied", 3
	case errors.Is(e.err, registry.ErrConflict):
		msg := "revision conflict or command ID already bound to another request; inspect status or history before retrying"
		if e.current != "" {
			msg += "; current revision: " + e.current
		}
		return msg, 4
	case errors.Is(e.err, registry.ErrNotFound):
		return "required registry record not found for this scope or release", 5
	case errors.Is(e.err, registry.ErrCorrupt):
		return "registry record failed verification; no authority may be derived from it", 6
	case errors.Is(e.err, context.Canceled), errors.Is(e.err, context.DeadlineExceeded):
		return "operation interrupted or timed out; inspect the applied history before retrying", 1
	default:
		return "control operation unavailable; check deployment, storage or signing credentials", 1
	}
}

func (s controlSession) onConflict(ctx context.Context, err error) error {
	if !errors.Is(err, registry.ErrConflict) {
		return err
	}
	current, readErr := s.service.Current(ctx)
	if readErr != nil {
		return err
	}
	return &controlError{err: err, current: current.ID}
}

type scopedResult struct {
	Schema int           `json:"schema_version"`
	Scope  rollout.Scope `json:"scope"`
}

func (s controlSession) resultScope() scopedResult { return scopedResult{1, s.service.Scope} }

func (o *controlOptions) propose() *cobra.Command {
	var path string
	cmd := o.command("propose", "Store an immutable rollout plan without activating it", func(ctx context.Context, cmd *cobra.Command) error {
		var p rollout.Plan
		if err := readInput(path, &p); err != nil {
			return err
		}
		s, err := o.connect(ctx, cmd, proposerRole)
		if err != nil {
			return err
		}
		if p.Scope == (rollout.Scope{}) {
			p.Scope = s.service.Scope
		}
		if p.Scope != s.service.Scope {
			return invalidInput("plan scope does not match the deployment")
		}
		if err := p.Validate(); err != nil {
			return err
		}
		source, err := s.sourceRegistry()
		if err != nil {
			return err
		}
		candidate, err := inspectRef(ctx, source, p.Scope.Plugin, p.Candidate)
		if err != nil {
			return err
		}
		var baseline *registry.Release
		if p.Baseline != (rollout.Ref{}) {
			target, err := s.targetRegistry()
			if err != nil {
				return err
			}
			release, err := inspectRef(ctx, target, p.Scope.Plugin, p.Baseline)
			if err != nil {
				return err
			}
			baseline = &release
		}
		id, err := s.service.Propose(ctx, p, s.actor)
		if err != nil {
			return err
		}
		result := struct {
			scopedResult
			Status    string            `json:"status"`
			PlanID    string            `json:"plan_id"`
			Candidate registry.Release  `json:"candidate"`
			Baseline  *registry.Release `json:"baseline,omitempty"`
		}{s.resultScope(), "proposed", id, candidate, baseline}
		return o.output(cmd, result, "proposed %s for %s %s; see --output json for candidate and baseline evidence\n",
			id, candidate.Version, candidate.ArtifactDigest)
	})
	cmd.Flags().StringVar(&path, "plan", "", "JSON rollout plan")
	return cmd
}

func inspectRef(ctx context.Context, store registry.Registry, plugin string, ref rollout.Ref) (registry.Release, error) {
	releases, err := store.Inspect(ctx, plugin, ref.Version, "")
	if err != nil {
		return registry.Release{}, err
	}
	if len(releases) != 1 || releases[0].ArtifactDigest != ref.Digest {
		return registry.Release{}, registry.ErrDenied
	}
	return releases[0], nil
}

func (o *controlOptions) approve() *cobra.Command {
	var path string
	var request struct {
		PlanID string `json:"plan_id"`
	}
	cmd := o.command("approve", "Approve exactly one immutable rollout plan", func(ctx context.Context, cmd *cobra.Command) error {
		if err := readOperationInput(cmd, path, &request, "plan-id"); err != nil {
			return err
		}
		if request.PlanID == "" {
			return invalidInput("a plan ID is required")
		}
		s, err := o.connect(ctx, cmd, approverRole)
		if err != nil {
			return err
		}
		id, err := s.service.Approve(ctx, request.PlanID, s.actor)
		if err != nil {
			return err
		}
		return o.approvalResult(cmd, s, id)
	})
	cmd.Flags().StringVar(&request.PlanID, "plan-id", "", "exact proposed plan ID")
	cmd.Flags().StringVar(&path, "request", "", "JSON request with plan_id")
	return cmd
}

func (o *controlOptions) approveRestore() *cobra.Command {
	var path string
	var request struct {
		Digest   string `json:"digest"`
		Expected string `json:"expected"`
	}
	cmd := o.command("approve-restore", "Approve removal of one exact deny at a specific revision", func(ctx context.Context, cmd *cobra.Command) error {
		if err := readOperationInput(cmd, path, &request, "digest", "expected"); err != nil {
			return err
		}
		if request.Digest == "" || request.Expected == "" {
			return invalidInput("a digest and expected revision are required")
		}
		s, err := o.connect(ctx, cmd, approverRole)
		if err != nil {
			return err
		}
		id, err := s.service.ApproveRestore(ctx, request.Digest, request.Expected, s.actor)
		if err != nil {
			return s.onConflict(ctx, err)
		}
		return o.approvalResult(cmd, s, id)
	})
	cmd.Flags().StringVar(&request.Digest, "digest", "", "exact quarantined artifact digest")
	cmd.Flags().StringVar(&request.Expected, "expected", "", "exact current decision ID")
	cmd.Flags().StringVar(&path, "request", "", "JSON request with digest and expected")
	return cmd
}

func (o *controlOptions) approvalResult(cmd *cobra.Command, s controlSession, id string) error {
	result := struct {
		scopedResult
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
	}{s.resultScope(), "approved", id}
	return o.output(cmd, result, "approved %s\n", id)
}

func (o *controlOptions) execute(action, summary, role string) *cobra.Command {
	var path string
	cmd := o.command(action, summary, func(ctx context.Context, cmd *cobra.Command) error {
		var request rollout.Command
		if err := readInput(path, &request); err != nil {
			return err
		}
		if request.Action != "" && request.Action != action {
			return invalidInput("JSON command action does not match the CLI verb")
		}
		request.Action = action
		s, err := o.connect(ctx, cmd, role)
		if err != nil {
			return err
		}
		var promote func(context.Context, rollout.Ref) error
		if action == "activate" {
			promote = func(ctx context.Context, ref rollout.Ref) error {
				source, err := s.sourceRegistry()
				if err != nil {
					return err
				}
				target, err := s.targetRegistry()
				if err != nil {
					return err
				}
				_, err = source.Promote(ctx, target, s.service.Scope.Plugin, ref.Version, ref.Digest)
				return err
			}
		}
		decision, err := s.service.Execute(ctx, request, s.actor, promote)
		if err != nil {
			return s.onConflict(ctx, err)
		}
		return o.applied(cmd, decision)
	})
	cmd.Flags().StringVar(&path, "command", "", "JSON command with ID, expected revision and action-specific evidence")
	return cmd
}

const unknown = "unknown"

// The wire decision omits its own digest. CLI readers need that exact value
// as the optimistic precondition for a subsequent operation.
type decisionView struct {
	*rollout.Decision
	DecisionID string `json:"decision_id"`
}

func viewDecision(d *rollout.Decision) decisionView { return decisionView{d, d.ID} }

func (o *controlOptions) applied(cmd *cobra.Command, d rollout.Decision) error {
	result := struct {
		Schema         int          `json:"schema_version"`
		Status         string       `json:"status"`
		Decision       decisionView `json:"decision"`
		AlreadyApplied bool         `json:"already_applied"`
		HostAdoption   string       `json:"host_adoption"`
		Exposure       string       `json:"exposure"`
	}{1, "applied", viewDecision(&d), d.AlreadyApplied, unknown, unknown}
	previous := d.Previous
	if previous == "" {
		previous = "none"
	}
	return o.output(cmd, result, "applied %s: %s/%s generation %d, decision %s, previous %s, already applied: %t; adoption and exposure unknown\n",
		d.Command.ID, d.Scope.Environment, d.Scope.Plugin, d.Generation, d.ID, previous, d.AlreadyApplied)
}

func (o *controlOptions) status() *cobra.Command {
	return o.command("status", "Show verified desired state and freshness, not host adoption", func(ctx context.Context, cmd *cobra.Command) error {
		s, err := o.connect(ctx, cmd, "")
		if err != nil {
			return err
		}
		obs, err := s.service.Observe(ctx)
		if err != nil {
			return err
		}
		return o.observation(cmd, s, "committed", obs)
	})
}

func (o *controlOptions) history() *cobra.Command {
	return o.command("history", "Show the verified applied decision chain, newest first", func(ctx context.Context, cmd *cobra.Command) error {
		s, err := o.connect(ctx, cmd, "")
		if err != nil {
			return err
		}
		decisions, err := s.service.History(ctx)
		if err != nil {
			return err
		}
		if o.global.output == "json" {
			out := make([]decisionView, len(decisions))
			for i := range decisions {
				out[i] = viewDecision(&decisions[i])
			}
			return writeJSON(cmd.OutOrStdout(), struct {
				scopedResult
				Decisions []decisionView `json:"decisions"`
			}{s.resultScope(), out})
		}
		for _, d := range decisions {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%d %s %s %s %s\n", d.Generation, d.ID, d.Command.ID, d.Command.Action, d.Actor); err != nil {
				return err
			}
		}
		return nil
	})
}

func (o *controlOptions) renew() *cobra.Command {
	var path string
	var request struct {
		Duration string `json:"duration"`
	}
	cmd := o.command("renew", "Renew freshness for the exact current committed head", func(ctx context.Context, cmd *cobra.Command) error {
		if err := readOperationInput(cmd, path, &request, "duration"); err != nil {
			return err
		}
		lease, err := time.ParseDuration(request.Duration)
		if err != nil || lease <= 0 {
			return invalidInput("freshness duration must be positive")
		}
		s, err := o.connect(ctx, cmd, renewerRole)
		if err != nil {
			return err
		}
		obs, err := s.service.Renew(ctx, s.actor, lease)
		if err != nil {
			return s.onConflict(ctx, err)
		}
		return o.observation(cmd, s, "renewed", obs)
	})
	cmd.Flags().StringVar(&request.Duration, "duration", "", "bounded freshness duration (for example 30s)")
	cmd.Flags().StringVar(&path, "request", "", "JSON request with duration")
	return cmd
}

func (o *controlOptions) observation(cmd *cobra.Command, s controlSession, state string, obs rollout.Observation) error {
	freshness := "unavailable"
	var expiry *time.Time
	if !obs.ExpiresAt.IsZero() {
		freshness = "current"
		expiry = &obs.ExpiresAt
	}
	result := struct {
		scopedResult
		Status       string       `json:"status"`
		Decision     decisionView `json:"decision"`
		Freshness    string       `json:"freshness"`
		ExpiresAt    *time.Time   `json:"expires_at"`
		HostAdoption string       `json:"host_adoption"`
		Exposure     string       `json:"exposure"`
	}{s.resultScope(), state, viewDecision(&obs.Decision), freshness, expiry, unknown, unknown}
	if expiry != nil {
		freshness = "current until " + expiry.Format(time.RFC3339Nano)
	}
	return o.output(cmd, result, "%s %s/%s generation %d (%s), phase %s, rung %d; freshness %s; adoption and exposure unknown\n",
		state, s.service.Scope.Environment, s.service.Scope.Plugin, obs.Decision.Generation, obs.Decision.ID,
		obs.Decision.State.Phase, obs.Decision.State.Rung, freshness)
}

func (o *controlOptions) preview() *cobra.Command {
	var planPath, attrPath, subject string
	var rung uint16
	cmd := o.command("preview", "Evaluate rollout targeting on synthetic input without storage access", func(_ context.Context, cmd *cobra.Command) error {
		var plan rollout.Plan
		if err := readInput(planPath, &plan); err != nil {
			return err
		}
		if rung > 10000 {
			return invalidInput("--rung must be at most 10000 basis points")
		}
		var attrs map[string]any
		if attrPath != "" {
			if err := readInput(attrPath, &attrs); err != nil {
				return err
			}
		}
		var reason string
		var result target.Result
		if plan.Baseline == (rollout.Ref{}) {
			// First activation has no audience or rung: every ready host serves it.
			if rung != 0 {
				return invalidInput("first activation has no preview rung")
			}
			if err := plan.Validate(); err != nil {
				return err
			}
			result, reason = target.Result{Match: true, Candidate: true}, "first_activation"
		} else {
			program, err := target.Compile(plan.Target)
			if err != nil {
				return invalidInput("invalid targeting declaration")
			}
			result, err = program.Evaluate(plan.Scope.Environment, plan.Scope.Plugin, []byte(subject), attrs, rung)
			if err != nil {
				return invalidInput("invalid targeting input")
			}
			switch {
			case !result.Match:
				reason = "predicate_nonmatch"
			case !result.Candidate:
				reason = "outside_rung"
			default:
				reason = "within_rung"
			}
		}
		return o.output(cmd, struct {
			Schema int    `json:"schema_version"`
			Reason string `json:"reason"`
			target.Result
		}{1, reason, result}, "match=%t bucket=%d candidate=%t reason=%s\n", result.Match, result.Bucket, result.Candidate, reason)
	})
	cmd.Flags().StringVar(&planPath, "plan", "", "JSON rollout plan with scope")
	cmd.Flags().StringVar(&subject, "subject", "", "synthetic subject key, never a real identity")
	cmd.Flags().StringVar(&attrPath, "attrs", "", "JSON object containing synthetic targeting attributes")
	cmd.Flags().Uint16Var(&rung, "rung", 0, "candidate exposure to preview in basis points")
	return cmd
}
