package rollout

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/heynemann/go-plg-s3-registry/internal/dsse"
	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

// Store adds optimistic conditional publication to the registry object seam.
type Store interface {
	registry.Store
	Read(context.Context, string) (io.ReadCloser, string, error)
	CompareAndSwap(context.Context, string, string, []byte) error
}

// Service operates on an explicitly configured scope. Store and trust are
// deployment inputs, never discovered from a plan. VerifyRelease is used by
// recovery to verify already-promoted bytes in its destination.
type Service struct {
	Store         Store
	Scope         Scope
	Trust         Trust
	Now           func() time.Time
	MaxClockSkew  time.Duration
	Recovery      *RecoveryEvidence
	VerifyRelease func(context.Context, Ref) error
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Service) check() error {
	if err := s.Scope.validate(); err != nil {
		return err
	}
	if s.Store == nil {
		return fmt.Errorf("%w: registry store is required", registry.ErrInvalid)
	}
	return nil
}

func (s Service) base() string {
	return "v1/" + s.Scope.Registry + "/environments/" + s.Scope.Environment + "/plugins/" + s.Scope.Plugin + "/"
}

func (s Service) headKey(epoch string) string  { return s.base() + "heads/" + epoch + ".json" }
func (s Service) blob(kind, sum string) string { return s.base() + kind + "/" + sum + ".json" }

func seal(ctx context.Context, ident Identity, key Key, kind string, value any) ([]byte, error) {
	if ident.Sign == nil {
		return nil, registry.ErrDenied
	}
	payload, err := encode(value)
	if err != nil {
		return nil, err
	}
	kind = payloadType(kind)
	sum := dsse.Digest(kind, payload)
	sig, err := ident.Sign(ctx, sum)
	if err != nil {
		return nil, fmt.Errorf("sign protocol record: %w", err)
	}
	if !ecdsa.VerifyASN1(key.PublicKey, sum[:], sig) {
		return nil, registry.ErrDenied
	}
	return encode(envelope{Type: kind, Payload: payload, Signatures: []wireSignature{{Key: ident.ID, Signature: sig}}})
}

func openSigned(data []byte, keys []Key, kind string, out any) (Key, error) {
	var e envelope
	if decode(data, &e) != nil || e.Type != payloadType(kind) || len(e.Signatures) != 1 {
		return Key{}, registry.ErrCorrupt
	}
	sig := e.Signatures[0]
	key, ok := keyByID(keys, sig.Key)
	if !ok {
		return Key{}, registry.ErrCorrupt
	}
	sum := dsse.Digest(e.Type, e.Payload)
	if !ecdsa.VerifyASN1(key.PublicKey, sum[:], sig.Signature) || decode(e.Payload, out) != nil {
		return Key{}, registry.ErrCorrupt
	}
	return key, nil
}

func readBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, registry.MaxRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read protocol record: %w", err)
	}
	if len(data) > registry.MaxRecordBytes {
		return nil, registry.ErrCorrupt
	}
	return data, nil
}

func (s Service) read(ctx context.Context, key string) ([]byte, error) {
	body, err := s.Store.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	return readBody(body)
}

func (s Service) readBlob(ctx context.Context, kind, sum string) ([]byte, error) {
	if !digestPattern.MatchString(sum) {
		return nil, registry.ErrInvalid
	}
	data, err := s.read(ctx, s.blob(kind, sum))
	if err != nil {
		return nil, err
	}
	if digest(data) != sum {
		return nil, registry.ErrCorrupt
	}
	return data, nil
}

func (s Service) create(ctx context.Context, key string, data []byte) error {
	err := s.Store.Create(ctx, key, data)
	if !errors.Is(err, registry.ErrConflict) {
		return err
	}
	old, err := s.read(ctx, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(old, data) {
		return registry.ErrConflict
	}
	return nil
}

// Propose stores an immutable plan and a verified owner's endorsement. A plan
// endorsement is not an approval and cannot change a serving head.
func (s Service) Propose(ctx context.Context, p Plan, actor Identity) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	if p.Scope != s.Scope {
		return "", registry.ErrInvalid
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	key, ok := keyByID(s.Trust.Proposers, actor.ID)
	if !ok {
		return "", registry.ErrDenied
	}
	data, err := encode(p)
	if err != nil {
		return "", err
	}
	id := digest(data)
	signed, err := seal(ctx, actor, key, "proposal", proposal{Scope: s.Scope, Plan: id, Actor: key.Principal, Provenance: actor.Provenance})
	if err != nil {
		return "", err
	}
	if err = s.create(ctx, s.blob("plans", id), data); err != nil {
		return "", err
	}
	err = s.Store.Create(ctx, s.blob("proposals", id), signed)
	if errors.Is(err, registry.ErrConflict) {
		_, _, existing, readErr := s.readPlan(ctx, id)
		if readErr != nil {
			return "", readErr
		}
		if existing.Principal != key.Principal {
			return "", registry.ErrConflict
		}
		err = nil
	}
	return id, err
}

func (s Service) readPlan(ctx context.Context, id string) (Plan, *Provenance, Key, error) {
	data, err := s.readBlob(ctx, "plans", id)
	if err != nil {
		return Plan{}, nil, Key{}, err
	}
	var p Plan
	if decode(data, &p) != nil || p.Scope != s.Scope || p.Validate() != nil {
		return Plan{}, nil, Key{}, registry.ErrCorrupt
	}
	data, err = s.read(ctx, s.blob("proposals", id))
	if err != nil {
		return Plan{}, nil, Key{}, err
	}
	var attestation proposal
	key, err := openSigned(data, s.Trust.Proposers, "proposal", &attestation)
	if err != nil || attestation.Scope != s.Scope || attestation.Plan != id || attestation.Actor != key.Principal {
		return Plan{}, nil, Key{}, registry.ErrCorrupt
	}
	return p, attestation.Provenance, key, nil
}

func (s Service) Approve(ctx context.Context, planID string, actor Identity) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	key, ok := keyByID(s.Trust.Approvers, actor.ID)
	if !ok {
		return "", registry.ErrDenied
	}
	_, provenance, proposer, err := s.readPlan(ctx, planID)
	if err != nil {
		return "", err
	}
	if !independent(key, proposer) || !independentReview(actor.Provenance, provenance) {
		return "", registry.ErrDenied
	}
	return s.writeApproval(ctx, actor, key, approval{Scope: s.Scope, Action: "plan", Plan: planID, Actor: key.Principal, Provenance: actor.Provenance})
}

func (s Service) ApproveRestore(ctx context.Context, sum, expected string, actor Identity) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	key, ok := keyByID(s.Trust.Approvers, actor.ID)
	if !ok {
		return "", registry.ErrDenied
	}
	if !digestPattern.MatchString(sum) || !digestPattern.MatchString(expected) {
		return "", registry.ErrInvalid
	}
	current, err := s.Current(ctx)
	if err != nil {
		return "", err
	}
	if current.ID != expected {
		return "", registry.ErrConflict
	}
	if !current.State.Quarantined(sum) {
		return "", fmt.Errorf("%w: digest is not quarantined", registry.ErrInvalid)
	}
	return s.writeApproval(ctx, actor, key, approval{Scope: s.Scope, Action: "restore", Expected: expected, Digest: sum, Actor: key.Principal, Provenance: actor.Provenance})
}

func (s Service) writeApproval(ctx context.Context, actor Identity, key Key, a approval) (string, error) {
	data, err := seal(ctx, actor, key, "approval", a)
	if err != nil {
		return "", err
	}
	id := digest(data)
	return id, s.create(ctx, s.blob("approvals", id), data)
}

func (s Service) readApproval(ctx context.Context, id string) (approval, Key, error) {
	data, err := s.readBlob(ctx, "approvals", id)
	if err != nil {
		return approval{}, Key{}, err
	}
	var a approval
	key, err := openSigned(data, s.Trust.Approvers, "approval", &a)
	if err != nil || a.Scope != s.Scope || a.Actor != key.Principal {
		return approval{}, Key{}, registry.ErrCorrupt
	}
	return a, key, nil
}

func independent(a, b Key) bool {
	return a.PublicKey != nil && b.PublicKey != nil && a.ID != b.ID && a.Principal != b.Principal && !a.PublicKey.Equal(b.PublicKey)
}

func responderAction(action string) bool {
	return action == "rollback" || action == "pause" || action == "quarantine"
}

func (s Service) decisionKeys(action string) []Key {
	if responderAction(action) {
		return s.Trust.Responders
	}
	switch action {
	case "recover":
		return s.Trust.Recoverers
	default:
		return s.Trust.Deciders
	}
}

func (s Service) loadDecision(ctx context.Context, id string) (Decision, error) {
	data, err := s.readBlob(ctx, "decisions", id)
	if err != nil {
		return Decision{}, err
	}
	var e envelope
	var d Decision
	if decode(data, &e) != nil || decode(e.Payload, &d) != nil {
		return Decision{}, registry.ErrCorrupt
	}
	key, err := openSigned(data, s.decisionKeys(d.Command.Action), "decision", &d)
	if err != nil || !d.Scope.samePlugin(s.Scope) || d.Scope.validate() != nil || d.Actor != key.Principal ||
		d.Generation == 0 || d.At.IsZero() || (d.Generation == 1 && d.Previous != "") ||
		(d.Generation > 1 && !digestPattern.MatchString(d.Previous)) {
		return Decision{}, registry.ErrCorrupt
	}
	d.ID = id
	return d, nil
}

func (s Service) readHead(ctx context.Context, scope Scope) (Decision, string, error) {
	body, etag, err := s.Store.Read(ctx, s.headKey(scope.Epoch))
	if err != nil {
		return Decision{}, "", err
	}
	data, err := readBody(body)
	if err != nil {
		return Decision{}, "", err
	}
	var h head
	if etag == "" || decode(data, &h) != nil || h.Version != wireVersion || h.Scope != scope || !digestPattern.MatchString(h.Decision) {
		return Decision{}, "", registry.ErrCorrupt
	}
	d, err := s.loadDecision(ctx, h.Decision)
	// Once the head exists, missing data is corruption, never a bootstrap opportunity.
	if errors.Is(err, registry.ErrNotFound) {
		err = registry.ErrCorrupt
	}
	if err != nil {
		return Decision{}, "", err
	}
	if d.Scope != scope || d.Generation != h.Generation {
		return Decision{}, "", registry.ErrCorrupt
	}
	if err := s.walk(ctx, d, nil); err != nil {
		return Decision{}, "", err
	}
	return d, etag, nil
}

func (s Service) Current(ctx context.Context) (Decision, error) {
	if err := s.check(); err != nil {
		return Decision{}, err
	}
	d, _, err := s.readHead(ctx, s.Scope)
	return d, err
}

func (s Service) History(ctx context.Context) ([]Decision, error) {
	start, err := s.Current(ctx)
	if err != nil {
		return nil, err
	}
	var history []Decision
	err = s.walk(ctx, start, func(d Decision) bool { history = append(history, d); return true })
	if err != nil {
		return nil, err
	}
	return history, nil
}

func (s Service) Decision(ctx context.Context, id string) (Decision, error) {
	start, err := s.Current(ctx)
	if err != nil {
		return Decision{}, err
	}
	return s.findDecision(ctx, id, start)
}

// DecisionAt proves ancestry of id relative to a head already verified by the
// caller. It never substitutes a freshly read, potentially older head.
func (s Service) DecisionAt(ctx context.Context, id, headID string) (Decision, error) {
	if err := s.check(); err != nil {
		return Decision{}, err
	}
	start, err := s.loadDecision(ctx, headID)
	if err != nil {
		return Decision{}, err
	}
	if start.Scope != s.Scope {
		return Decision{}, registry.ErrCorrupt
	}
	return s.findDecision(ctx, id, start)
}

func (s Service) findDecision(ctx context.Context, id string, start Decision) (Decision, error) {
	if !digestPattern.MatchString(id) {
		return Decision{}, registry.ErrInvalid
	}
	var found Decision
	err := s.walk(ctx, start, func(d Decision) bool {
		if d.ID == id {
			found = d
			return false
		}
		return true
	})
	if err != nil {
		return Decision{}, err
	}
	if found.ID == "" {
		return Decision{}, registry.ErrNotFound
	}
	return found, nil
}

// A nil or stopped visitor only verifies a contiguous responder suffix. A
// responder snapshot derives authority from its predecessor all the way back
// to a non-responder decision; a normal poll need not read beyond that anchor.
func (s Service) walk(ctx context.Context, start Decision, visit func(Decision) bool) error {
	for d := start; ; {
		if visit != nil && !visit(d) {
			visit = nil
		}
		responder := responderAction(d.Command.Action)
		if !responder && (visit == nil || d.Previous == "") {
			return nil
		}
		if responder && d.Previous == "" {
			return registry.ErrCorrupt
		}
		prev, err := s.loadDecision(ctx, d.Previous)
		if errors.Is(err, registry.ErrNotFound) {
			return registry.ErrCorrupt
		}
		if err != nil {
			return err
		}
		if responder {
			if !s.validResponderSnapshot(ctx, d, prev) {
				return registry.ErrCorrupt
			}
		} else if prev.Generation != d.Generation-1 || (prev.Scope != d.Scope && d.Command.Action != "recover") {
			return registry.ErrCorrupt
		}
		d = prev
	}
}

func (s Service) validResponderSnapshot(ctx context.Context, d, prev Decision) bool {
	if !responderAction(d.Command.Action) || d.Command.validate() != nil ||
		d.Command.Expected != d.Previous || d.Previous != prev.ID ||
		d.Scope != prev.Scope || prev.Generation != d.Generation-1 || d.At.Before(prev.At) {
		return false
	}
	// The signature has already been verified with the responder key in
	// loadDecision. These incident transitions need no key or external I/O.
	next, err := s.transition(ctx, prev.State, d.Command, Key{}, d.Provenance)
	if err != nil {
		return false
	}
	trackRetirement(&next, prev.State, d.At)
	// Compare the entire canonical snapshot, including the plan, deny set,
	// and retirement history, not just the fields this action may change.
	want, err := encode(next)
	if err != nil {
		return false
	}
	got, err := encode(d.State)
	return err == nil && bytes.Equal(got, want)
}

func (s Service) commit(ctx context.Context, d Decision, etag string, ident Identity, key Key) (Decision, error) {
	d.Provenance = ident.Provenance
	data, err := seal(ctx, ident, key, "decision", d)
	if err != nil {
		return Decision{}, err
	}
	d.ID = digest(data)
	if err = s.create(ctx, s.blob("decisions", d.ID), data); err != nil {
		return Decision{}, err
	}
	pointer, err := encode(head{Version: wireVersion, Scope: d.Scope, Generation: d.Generation, Decision: d.ID})
	if err != nil {
		return Decision{}, err
	}
	err = s.Store.CompareAndSwap(ctx, s.headKey(d.Scope.Epoch), etag, pointer)
	if err == nil {
		return d, nil
	}
	// A competing request may have committed the same command, or a timeout
	// may have lost the successful response. An object write alone proves neither.
	current, readErr := s.Current(ctx)
	if readErr == nil {
		applied, replayErr := s.commandReplay(ctx, current, d.Command, d.Actor)
		if replayErr != nil {
			return Decision{}, replayErr
		}
		if applied.ID != "" {
			return applied, nil
		}
	}
	return Decision{}, err
}
