package rollout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

func (s Service) leaseKey(id string) string { return s.blob("freshness", id) }

// ValidLeaseLimits reports whether a lease can remain usable after clock skew.
func ValidLeaseLimits(maxLease, skew time.Duration) bool {
	return maxLease > 0 && skew >= 0 && skew < maxLease
}

func (s Service) leaseLimits() error {
	if !ValidLeaseLimits(s.Trust.MaxLease, s.MaxClockSkew) {
		return fmt.Errorf("%w: configure a positive maximum lease and a smaller nonnegative clock skew", registry.ErrInvalid)
	}
	return nil
}

func (s Service) proof(ctx context.Context, d Decision) (proof, string, error) {
	body, etag, err := s.Store.Read(ctx, s.leaseKey(d.ID))
	if err != nil {
		return proof{}, "", err
	}
	data, err := readBody(body)
	if err != nil {
		return proof{}, "", err
	}
	var p proof
	_, err = openSigned(data, s.Trust.Renewers, "freshness", &p)
	if err != nil || etag == "" || p.Scope != d.Scope || p.Generation != d.Generation || p.Decision != d.ID ||
		p.Observed.Before(d.At.Add(-s.MaxClockSkew)) || !p.Expires.After(p.Observed) || p.Expires.Sub(p.Observed) > s.Trust.MaxLease {
		return proof{}, "", registry.ErrCorrupt
	}
	return p, etag, nil
}

// Observe verifies the committed head independently of its freshness record.
// A valid newer deny can therefore take effect even while renewal is offline.
func (s Service) Observe(ctx context.Context) (Observation, error) {
	if err := s.leaseLimits(); err != nil {
		return Observation{}, err
	}
	d, err := s.Current(ctx)
	if err != nil {
		return Observation{}, err
	}
	obs := Observation{Decision: d}
	p, _, err := s.proof(ctx, d)
	if errors.Is(err, registry.ErrNotFound) {
		return obs, nil
	}
	if err != nil {
		return obs, err
	}
	current, err := s.Current(ctx)
	if err != nil {
		return obs, err
	}
	if current.ID != d.ID {
		return Observation{Decision: current}, nil
	}
	now := s.now()
	if p.Observed.After(now.Add(s.MaxClockSkew)) {
		return obs, registry.ErrCorrupt
	}
	if !p.Expires.After(now) {
		return obs, nil
	}
	obs.ProofAt, obs.ExpiresAt = p.Observed, p.Expires
	return obs, nil
}

// Renew extends only the authenticated decision that was current when the
// renewal started. It is never a serving-state write.
func (s Service) Renew(ctx context.Context, signer Identity, duration time.Duration) (Observation, error) {
	if err := s.leaseLimits(); err != nil {
		return Observation{}, err
	}
	if duration <= 0 || duration > s.Trust.MaxLease {
		return Observation{}, registry.ErrInvalid
	}
	key, ok := keyByID(s.Trust.Renewers, signer.ID)
	if !ok {
		return Observation{}, registry.ErrDenied
	}
	observed := s.now()
	d, err := s.Current(ctx)
	if err != nil {
		return Observation{}, err
	}
	if observed.Before(d.At.Add(-s.MaxClockSkew)) {
		return Observation{}, registry.ErrConflict
	}
	prior, etag, err := s.proof(ctx, d)
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		return Observation{}, err
	}
	p := proof{Scope: d.Scope, Generation: d.Generation, Decision: d.ID, Observed: observed, Expires: observed.Add(duration)}
	if etag != "" && (!p.Observed.After(prior.Observed) || !p.Expires.After(prior.Expires)) {
		return Observation{}, registry.ErrConflict
	}
	data, err := seal(ctx, signer, key, "freshness", p)
	if err != nil {
		return Observation{}, err
	}
	current, err := s.Current(ctx)
	if err != nil {
		return Observation{}, err
	}
	if current.ID != d.ID || !p.Expires.After(s.now()) {
		return Observation{}, registry.ErrConflict
	}
	if err = s.Store.CompareAndSwap(ctx, s.leaseKey(d.ID), etag, data); err != nil {
		return Observation{}, err
	}
	return Observation{Decision: d, ProofAt: p.Observed, ExpiresAt: p.Expires}, nil
}

// RecoveryEvidence identifies the last applied head corroborated outside of
// the restored bucket, after fencing its old writers and freshness issuers.
// It must come from trusted deployment configuration, not from the backup.
type RecoveryEvidence struct {
	Scope      Scope  `json:"scope"`
	Generation uint64 `json:"generation"`
	Decision   string `json:"decision"`
}

// Recover makes a restored copy authoritative only after its history matches
// an independent checkpoint and an authorized new epoch is committed.
func (s Service) Recover(ctx context.Context, evidence RecoveryEvidence, signer Identity) (Decision, error) {
	if err := s.check(); err != nil {
		return Decision{}, err
	}
	if s.Recovery == nil || *s.Recovery != evidence || !evidence.Scope.samePlugin(s.Scope) || evidence.Scope.Epoch == s.Scope.Epoch ||
		evidence.Scope.validate() != nil || !digestPattern.MatchString(evidence.Decision) || evidence.Generation == 0 ||
		evidence.Generation == ^uint64(0) || s.VerifyRelease == nil {
		return Decision{}, registry.ErrDenied
	}
	key, ok := keyByID(s.Trust.Recoverers, signer.ID)
	if !ok {
		return Decision{}, registry.ErrDenied
	}
	previous, _, err := s.readHead(ctx, evidence.Scope)
	if err != nil {
		return Decision{}, err
	}
	if previous.ID != evidence.Decision || previous.Generation != evidence.Generation {
		return Decision{}, registry.ErrConflict
	}
	if err = s.walk(ctx, previous, func(Decision) bool { return true }); err != nil {
		return Decision{}, err
	}
	now := s.now()
	if now.Before(previous.At) {
		return Decision{}, registry.ErrInvalid
	}
	cmd := Command{ID: "recover-" + s.Scope.Epoch, Action: "recover", Expected: previous.ID, Reason: "reconcile externally verified checkpoint"}
	if _, err = seal(ctx, signer, key, "recovery", evidence); err != nil {
		return Decision{}, err
	}
	state := previous.State
	for _, ref := range recoveryRefs(state) {
		if err = s.VerifyRelease(ctx, ref); err != nil {
			return Decision{}, err
		}
	}
	// The previous approval was scoped to the prior epoch. Preserve exactly
	// the approved effective routing and denies, but disallow advancing that
	// plan without a proposal and approval in the new epoch.
	return s.commit(ctx, Decision{Scope: s.Scope, Generation: previous.Generation + 1, Previous: previous.ID,
		Command: cmd, Actor: key.Principal, At: now, State: state}, "", signer, key)
}

func recoveryRefs(s State) []Ref {
	// Recovery has no trusted upper bound on callers' retry horizons. Keep
	// and verify all retained bindings in the preview, including retired
	// releases that may still be needed by an exact historical receipt.
	refs := make([]Ref, 0, 2+len(s.Retired))
	seen := make(map[Ref]struct{}, cap(refs))
	add := func(ref Ref) {
		if ref == (Ref{}) || s.Quarantined(ref.Digest) {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	add(s.Default)
	if s.KeepsCandidate() {
		add(s.Plan.Candidate)
	}
	for _, r := range s.Retired {
		add(r.Release)
	}
	return refs
}
