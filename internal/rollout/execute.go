package rollout

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

// Execute validates and commits exactly one authorized state change. A signed
// decision object on its own is not applied; only the conditional head write
// can make it part of the applied chain.
func (s Service) Execute(ctx context.Context, cmd Command, identity Identity, promote func(context.Context, Ref) error) (Decision, error) {
	if err := s.check(); err != nil {
		return Decision{}, err
	}
	if err := cmd.validate(); err != nil {
		return Decision{}, err
	}
	key, ok := keyByID(s.decisionKeys(cmd.Action), identity.ID)
	if !ok || identity.Sign == nil {
		return Decision{}, registry.ErrDenied
	}
	current, etag, err := s.readHead(ctx, s.Scope)
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		return Decision{}, err
	}
	if current.ID != "" {
		replay, err := s.commandReplay(ctx, current, cmd, key.Principal)
		if err != nil {
			return Decision{}, err
		}
		if replay.ID != "" {
			// The CLI authenticates its signing identity before reaching this
			// path. Also prove possession here for other callers of the service.
			if _, err = seal(ctx, identity, key, "retry", cmd); err != nil {
				return Decision{}, err
			}
			return replay, nil
		}
	}
	if current.ID != cmd.Expected {
		return Decision{}, registry.ErrConflict
	}
	if current.Generation == ^uint64(0) {
		return Decision{}, registry.ErrCorrupt
	}
	if current.ID == "" && (cmd.Action != "activate" || s.Recovery != nil) {
		return Decision{}, fmt.Errorf("%w: environment has no authorized head", registry.ErrInvalid)
	}
	now := s.now()
	if now.Before(current.At) {
		return Decision{}, fmt.Errorf("%w: clock is behind current decision", registry.ErrInvalid)
	}
	next, err := s.transition(ctx, current.State, cmd, key, identity.Provenance)
	if err != nil {
		return Decision{}, err
	}
	trackRetirement(&next, current.State, now)
	d := Decision{Scope: s.Scope, Generation: current.Generation + 1, Previous: current.ID, Command: cmd, Actor: key.Principal, At: now, State: next}
	// Prove possession before side effects in the target bucket. The committed
	// record is signed again in commit, after immutable release promotion.
	if _, err = seal(ctx, identity, key, "command", cmd); err != nil {
		return Decision{}, err
	}
	if cmd.Action == "activate" {
		if promote == nil {
			return Decision{}, fmt.Errorf("%w: activation requires release verification and promotion", registry.ErrInvalid)
		}
		if err = promote(ctx, next.Plan.Candidate); err != nil {
			return Decision{}, err
		}
	}
	return s.commit(ctx, d, etag, identity, key)
}

func (c Command) validate() error {
	if !text(c.ID, 128) || !text(c.Reason, 1024) || !texts(c.Evidence, 16) ||
		(c.Expected != "" && !digestPattern.MatchString(c.Expected)) {
		return registry.ErrInvalid
	}
	var plan, approve, incident, digestArg, rung bool
	switch c.Action {
	case "activate", "set-default":
		plan, approve = true, true
	case "advance":
		approve, rung = true, true
	case "resume", "finish":
		approve = true
	case "pause", "rollback":
		incident = true
	case "quarantine":
		incident, digestArg = true, true
	case "restore":
		approve, digestArg = true, true
	default:
		return fmt.Errorf("%w: unknown rollout action", registry.ErrInvalid)
	}
	if (plan && !digestPattern.MatchString(c.PlanID)) || (!plan && c.PlanID != "") ||
		(approve && !digestPattern.MatchString(c.ApprovalID)) || (!approve && c.ApprovalID != "") ||
		(incident && !text(c.Incident, 256)) || (!incident && c.Incident != "") ||
		(digestArg && !digestPattern.MatchString(c.Digest)) || (!digestArg && c.Digest != "") ||
		(rung && (c.Rung == 0 || c.Rung > 10000 || len(c.Evidence) == 0)) || (!rung && c.Rung != 0) {
		return fmt.Errorf("%w: missing or inapplicable rollout command arguments", registry.ErrInvalid)
	}
	return nil
}

func (s Service) commandReplay(ctx context.Context, current Decision, cmd Command, actor string) (Decision, error) {
	var found Decision
	err := s.walk(ctx, current, func(d Decision) bool {
		if d.Command.ID == cmd.ID {
			found = d
			return false
		}
		return true
	})
	if err != nil || found.ID == "" {
		return Decision{}, err
	}
	a, err := encode(cmd)
	if err != nil {
		return Decision{}, err
	}
	b, err := encode(found.Command)
	if err != nil {
		return Decision{}, err
	}
	if string(a) != string(b) || found.Actor != actor {
		return Decision{}, registry.ErrConflict
	}
	found.AlreadyApplied = true
	return found, nil
}

func (s Service) requirePlanApproval(ctx context.Context, id, planID string, executor Key, execution *Provenance) (Plan, error) {
	a, approver, err := s.readApproval(ctx, id)
	if err != nil {
		return Plan{}, err
	}
	if a.Action != "plan" || a.Plan != planID || !independent(approver, executor) || !independentReview(a.Provenance, execution) {
		return Plan{}, registry.ErrDenied
	}
	p, provenance, proposer, err := s.readPlan(ctx, planID)
	if err != nil {
		return Plan{}, err
	}
	if !independent(approver, proposer) || !independentReview(a.Provenance, provenance) {
		return Plan{}, registry.ErrDenied
	}
	return p, nil
}

func (s Service) transition(ctx context.Context, current State, cmd Command, executor Key, execution *Provenance) (State, error) {
	next := current
	inapplicable := fmt.Errorf("%w: transition is not allowed from the current rollout", registry.ErrInvalid)
	switch cmd.Action {
	case "activate":
		p, err := s.requirePlanApproval(ctx, cmd.ApprovalID, cmd.PlanID, executor, execution)
		if err != nil {
			return State{}, err
		}
		if current.Phase == "paused" || current.Phase == "warming" || current.Phase == "ramping" || current.Phase == "finished" ||
			p.Baseline != current.Default || current.Quarantined(p.Candidate.Digest) ||
			(current.PlanID != "" && p.Unavailable != current.Plan.Unavailable) {
			return State{}, inapplicable
		}
		next.Plan, next.PlanID, next.ApprovalID = p, cmd.PlanID, cmd.ApprovalID
		next.Default, next.Phase, next.Rung = p.Baseline, "warming", 0
		if p.Baseline == (Ref{}) {
			next.Default, next.Phase = p.Candidate, "serving"
		}
	case "advance", "resume", "finish", "set-default":
		planID := current.PlanID
		if cmd.Action == "set-default" {
			planID = cmd.PlanID
		}
		if planID == "" {
			return State{}, inapplicable
		}
		p, err := s.requirePlanApproval(ctx, cmd.ApprovalID, planID, executor, execution)
		if err != nil {
			return State{}, err
		}
		if current.Quarantined(current.Plan.Candidate.Digest) {
			return State{}, inapplicable
		}
		switch cmd.Action {
		case "advance":
			if current.Phase != "warming" && current.Phase != "ramping" {
				return State{}, inapplicable
			}
			index := 0
			if current.Rung > 0 {
				index = slices.Index(p.Rungs, current.Rung) + 1
				if index == 0 {
					return State{}, registry.ErrCorrupt
				}
			}
			if index >= len(p.Rungs) || p.Rungs[index] != cmd.Rung {
				return State{}, inapplicable
			}
			next.Rung, next.Phase = cmd.Rung, "ramping"
		case "resume":
			if current.Phase != "paused" {
				return State{}, inapplicable
			}
			next.Phase = "warming"
			if current.Rung > 0 {
				next.Phase = "ramping"
			}
		case "finish":
			if current.Phase != "ramping" || len(p.Rungs) == 0 || current.Rung != p.Rungs[len(p.Rungs)-1] {
				return State{}, inapplicable
			}
			next.Phase = "finished"
		case "set-default":
			if !p.AllowDefault || current.Phase != "finished" {
				return State{}, inapplicable
			}
			same := p
			same.AllowDefault = current.Plan.AllowDefault
			sum, err := same.Digest()
			if err != nil {
				return State{}, err
			}
			if sum != current.PlanID {
				return State{}, inapplicable
			}
			next.Plan, next.PlanID = p, planID
			next.Default, next.Phase, next.Rung = p.Candidate, "serving", 0
		}
		next.ApprovalID = cmd.ApprovalID
	case "pause":
		if current.Phase != "ramping" && current.Phase != "warming" {
			return State{}, inapplicable
		}
		next.Phase = "paused"
	case "rollback":
		if current.PlanID == "" || current.Phase == "rolled-back" {
			return State{}, inapplicable
		}
		next.Default, next.Phase, next.Rung = current.Plan.Baseline, "rolled-back", 0
	case "quarantine":
		if current.Quarantined(cmd.Digest) {
			return State{}, inapplicable
		}
		next.Denied = append(slices.Clone(current.Denied), cmd.Digest)
		slices.Sort(next.Denied)
	case "restore":
		if !current.Quarantined(cmd.Digest) {
			return State{}, inapplicable
		}
		a, approver, err := s.readApproval(ctx, cmd.ApprovalID)
		if err != nil {
			return State{}, err
		}
		if a.Action != "restore" || a.Digest != cmd.Digest || a.Expected != cmd.Expected ||
			!independent(approver, executor) || !independentReview(a.Provenance, execution) {
			return State{}, registry.ErrDenied
		}
		// Clearing the deny must not revive a selectable route. A separate
		// approved activation may intentionally bring the digest back.
		if next.Default.Digest == cmd.Digest {
			next.Default = Ref{}
			next.Phase, next.Rung = "rolled-back", 0
		}
		if next.Plan.Candidate.Digest == cmd.Digest &&
			(next.Phase == "warming" || next.Phase == "ramping" || next.Phase == "paused" || next.Phase == "finished") {
			next.Phase, next.Rung = "rolled-back", 0
		}
		next.Denied = slices.DeleteFunc(slices.Clone(current.Denied), func(sum string) bool { return sum == cmd.Digest })
	}
	return next, nil
}

func trackRetirement(next *State, current State, now time.Time) {
	// Quarantine does not retire a route; expiry of a receipt and safety
	// revocation are independent. Track when routing stopped assigning it.
	before, after := current, *next
	before.Denied, after.Denied = nil, nil
	retired := slices.Clone(current.Retired)
	for _, ref := range [2]Ref{before.Default, before.Plan.Candidate} {
		if !before.Selectable(ref) || after.Selectable(ref) {
			continue
		}
		if i := slices.IndexFunc(retired, func(r Retired) bool { return r.Release == ref }); i >= 0 {
			retired[i].At = now
		} else {
			retired = append(retired, Retired{Release: ref, At: now})
		}
	}
	next.Retired = retired
}
