package dataplane

import (
	"context"
	"errors"
	"time"

	"github.com/heynemann/go-plg"
	"go.opentelemetry.io/otel/trace"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

// Select assigns an exact release using only local state. It does not reserve
// permission to call it; persist the receipt and use Invoke to dispatch.
func (h *Host[T]) Select(subject []byte, attrs map[string]any) (Receipt, error) {
	for {
		if h.closed.Load() {
			return Receipt{}, h.block(ErrClosed)
		}
		v := h.view.Load()
		r := v.effective
		now := h.cfg.Now()
		if r == nil {
			if v.quarantined(v.observed.State.Default.Digest) {
				return Receipt{}, h.selectionError(ErrQuarantined)
			}
			if v.observed.ID != "" && !v.proof.fresh(now) {
				return Receipt{}, h.selectionError(ErrStale)
			}
			return Receipt{}, h.selectionError(ErrUnavailable)
		}
		if !r.lease.fresh(now) {
			return Receipt{}, h.selectionError(ErrStale)
		}
		s := r.decision.State
		ref, lane := s.Default, defaultLane(s)
		var targeting string
		switch s.Phase {
		case "warming", "ramping", "paused", "finished":
			if r.program != nil {
				result, err := r.program.Evaluate(h.cfg.Environment, h.cfg.Plugin, subject, attrs, s.Rung)
				switch {
				case err != nil:
					targeting = "targeting_error"
				case !result.Match:
					targeting = "non_match"
				case result.Candidate && r.proof.candidate != (rollout.Ref{}):
					ref, lane = r.proof.candidate, CandidateLane
				}
			}
		}
		residents := h.storage.current.Load()
		ready := readyAssignment(v, r, residents, ref, lane)
		if !ready && lane == CandidateLane {
			ref, lane = s.Default, defaultLane(s)
			ready = readyAssignment(v, r, residents, ref, lane)
		}
		if h.view.Load() != v {
			continue
		}
		// Evaluation is bounded but may take us to the old lease's deadline.
		now = h.cfg.Now()
		if !r.lease.fresh(now) {
			return Receipt{}, h.selectionError(ErrStale)
		}
		if now.Before(r.proof.at.Add(-h.cfg.MaxClockSkew)) {
			return Receipt{}, h.selectionError(ErrStale)
		}
		if targeting != "" {
			h.signals.count(context.Background(), "select", lane, targeting)
		}
		if !ready {
			if v.quarantined(ref.Digest) {
				return Receipt{}, h.selectionError(ErrQuarantined)
			}
			return Receipt{}, h.selectionError(ErrUnavailable)
		}
		h.signals.count(context.Background(), "select", lane, "assigned")
		return Receipt{Version: 1, Registry: h.scope.Registry, Environment: h.scope.Environment, Plugin: h.scope.Plugin,
			Epoch: r.decision.Scope.Epoch, Digest: ref.Digest, Generation: r.decision.Generation,
			Decision: r.decision.ID, SelectedAt: now.UTC(), Lane: lane}, nil
	}
}

func readyAssignment(v *authorityView, r *route, storage *storageSnapshot, ref rollout.Ref, lane Lane) bool {
	if !v.permitsAssignment(r, ref, lane) {
		return false
	}
	resident := storage.byDigest[ref.Digest]
	return resident != nil && resident.bound(ref) && resident.ready.Load() && resident.users.Load() < retiredBit
}

func defaultLane(s rollout.State) Lane {
	if s.Default != (rollout.Ref{}) && s.Default == s.Plan.Baseline {
		return BaselineLane
	}
	return DefaultLane
}

func (h *Host[T]) block(cause error) error {
	return &AdmissionError{Action: h.cfg.Unavailable, Cause: cause}
}

func (h *Host[T]) selectionError(err error) error {
	h.signals.count(context.Background(), "select", "", reason(err))
	return h.block(err)
}

// Invoke checks a persisted receipt and dispatches the selected release. call
// must make exactly one synchronous guest method call with the invocation's
// bounded context. It must not retain, publish or use T after returning.
// The trusted application owns the callback, deadline and idempotency. Once
// admitted a call may finish even if a newer view subsequently revokes it.
func (h *Host[T]) Invoke(ctx context.Context, receipt Receipt, call func(T) error) error {
	return h.invoke(ctx, receipt, call, "invoke")
}

// InvokeRetry is Invoke with separate pinned-retry telemetry. It checks the
// same receipt and does not run selection again.
func (h *Host[T]) InvokeRetry(ctx context.Context, receipt Receipt, call func(T) error) error {
	return h.invoke(ctx, receipt, call, "invoke_retry")
}

func (h *Host[T]) invoke(ctx context.Context, receipt Receipt, call func(T) error, op string) (err error) {
	name := "registry.invoke"
	if op == "invoke_retry" {
		name = "registry.invoke_retry"
	}
	ctx, span := h.signals.start(ctx, name)
	defer span.End()
	start := h.signals.now()
	var admitted, completed bool
	defer func() { h.signals.invocation(ctx, span, receipt, op, start, admitted, completed, err) }()
	if call == nil || !h.validReceipt(receipt) {
		return h.block(ErrUnauthorized)
	}
	v := h.view.Load()
	if err := h.check(ctx, v, receipt); err != nil {
		return h.block(err)
	}
	proof, known := h.proofOf(v, receipt.Decision)
	if known {
		ref, err := h.pinRef(v, receipt, proof)
		if err != nil {
			return h.block(err)
		}
		if r := h.storage.current.Load().byDigest[ref.Digest]; r != nil && r.bound(ref) && r.ready.Load() && r.enter() {
			defer r.leave()
			return h.dispatch(ctx, span, receipt, ref, r, &admitted, &completed, call)
		}
	}
	result, err := h.cold(ctx, receipt)
	if err != nil {
		return h.block(err)
	}
	defer result.resident.leave()
	return h.dispatch(ctx, span, receipt, result.ref, result.resident, &admitted, &completed, call)
}

func (h *Host[T]) dispatch(ctx context.Context, span trace.Span, receipt Receipt, ref rollout.Ref, r *resident, admitted, completed *bool, call func(T) error) error {
	plugin, err := plg.Get[T](ctx, h.ctr, r.key)
	if err != nil {
		return h.block(ErrUnavailable)
	}
	h.signals.owner(span, r.owner, r.onCall, r.runbook)

	// Admission linearizes at this final snapshot load, after acquiring the
	// runtime reference and after any cold work. Either the new deny/freshness
	// snapshot is visible here, or the call was already admitted before it.
	v := h.view.Load()
	if err := h.check(ctx, v, receipt); err != nil {
		return h.block(err)
	}
	if !v.callable(ref) {
		return h.block(ErrUnauthorized)
	}
	*admitted = true
	err = call(plugin)
	*completed = true
	return err
}

func (h *Host[T]) validReceipt(r Receipt) bool {
	return r.Version == 1 && r.Registry == h.scope.Registry && r.Environment == h.scope.Environment &&
		r.Plugin == h.scope.Plugin && slug(r.Epoch) && digestOK(r.Digest) && digestOK(r.Decision) &&
		r.Generation != 0 && !r.SelectedAt.IsZero() && validLane(r.Lane)
}

func (h *Host[T]) check(ctx context.Context, v *authorityView, r Receipt) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if h.closed.Load() {
		return ErrClosed
	}
	now := h.cfg.Now()
	if r.SelectedAt.After(now.Add(h.cfg.MaxClockSkew)) {
		return ErrUnauthorized
	}
	if !now.Before(r.SelectedAt.Add(h.cfg.RetryHorizon)) {
		return ErrReceiptExpired
	}
	if v.quarantined(r.Digest) {
		return ErrQuarantined
	}
	if !v.proof.fresh(now) {
		return ErrStale
	}
	if r.Generation > v.observed.Generation {
		return ErrUnauthorized
	}
	if r.Generation > v.proof.generation {
		return ErrStale
	}
	return nil
}

func validLane(l Lane) bool { return l == DefaultLane || l == BaselineLane || l == CandidateLane }

// A compact, bounded cache of verified decision-to-pin evidence. Only the
// serialized lane writes it; values depend neither on request attributes nor
// on the receipt's claim that the named decision once won the head CAS.
type decisionProof struct {
	revision       Revision
	at             time.Time
	def, candidate rollout.Ref
	defLane        Lane
}

func makeProof(d rollout.Decision) decisionProof {
	s := d.State
	p := decisionProof{revision: revisionOf(d), at: d.At, defLane: defaultLane(s)}
	if s.Selectable(s.Default) {
		p.def = s.Default
	}
	if s.Plan.Candidate != s.Default && s.Selectable(s.Plan.Candidate) {
		p.candidate = s.Plan.Candidate
	}
	return p
}

const maxRememberedDecisions = 128

type decisionCache struct {
	proofs map[string]decisionProof
	order  []string
}

func (h *Host[T]) remember(proof decisionProof) {
	id := proof.revision.Decision
	prior := h.proofs.Load()
	if prior != nil {
		if _, exists := prior.proofs[id]; exists {
			return
		}
	}
	size := 1
	if prior != nil {
		size = min(maxRememberedDecisions, 1+len(prior.order))
	}
	next := &decisionCache{proofs: make(map[string]decisionProof, size), order: make([]string, 0, size)}
	if prior != nil {
		start := max(0, len(prior.order)+1-maxRememberedDecisions)
		for _, old := range prior.order[start:] {
			next.proofs[old] = prior.proofs[old]
			next.order = append(next.order, old)
		}
	}
	next.proofs[id] = proof
	next.order = append(next.order, id)
	h.proofs.Store(next)
}

func (h *Host[T]) proofOf(v *authorityView, id string) (decisionProof, bool) {
	if v.observed.ID == id {
		return v.observedProof, true
	}
	if v.effective != nil && v.effective.decision.ID == id {
		return v.effective.proof, true
	}
	if cache := h.proofs.Load(); cache != nil {
		proof, ok := cache.proofs[id]
		return proof, ok
	}
	return decisionProof{}, false
}

func (h *Host[T]) pinRef(v *authorityView, r Receipt, p decisionProof) (rollout.Ref, error) {
	if p.revision.Decision != r.Decision || p.revision.Generation != r.Generation || p.revision.Epoch != r.Epoch ||
		r.SelectedAt.Before(p.at.Add(-h.cfg.MaxClockSkew)) {
		return rollout.Ref{}, ErrUnauthorized
	}
	var ref rollout.Ref
	if r.Lane == CandidateLane {
		ref = p.candidate
	} else if r.Lane == p.defLane {
		ref = p.def
	}
	if ref.Digest != r.Digest || !v.callable(ref) {
		return rollout.Ref{}, ErrUnauthorized
	}
	return ref, nil
}

type coldResult struct {
	resident *resident
	ref      rollout.Ref
	err      error
}

func (h *Host[T]) cold(ctx context.Context, r Receipt) (coldResult, error) {
	if h.coldWaiting.Add(1) > int64(h.cfg.MaxPendingCold) {
		h.coldWaiting.Add(-1)
		return coldResult{}, ErrCapacity
	}
	defer h.coldWaiting.Add(-1)
	ctx, cancel := context.WithTimeout(ctx, h.cfg.SyncTimeout)
	defer cancel()
	done := make(chan coldResult)
	work := laneWork{ctx, func(runCtx context.Context) {
		result := h.prepareCold(runCtx, r)
		select {
		case done <- result:
		case <-runCtx.Done():
			if result.resident != nil {
				result.resident.leave()
			}
		}
	}}
	select {
	case h.ops <- work:
	case <-ctx.Done():
		return coldResult{}, context.Cause(ctx)
	case <-h.stopped:
		return coldResult{}, ErrClosed
	}
	select {
	case result := <-done:
		return result, result.err
	case <-ctx.Done():
		return coldResult{}, context.Cause(ctx)
	case <-h.stopped:
		return coldResult{}, ErrClosed
	}
}

func (h *Host[T]) prepareCold(ctx context.Context, r Receipt) coldResult {
	v := h.view.Load()
	if err := h.check(ctx, v, r); err != nil {
		return coldResult{err: err}
	}
	p, known := h.proofOf(v, r.Decision)
	if !known {
		d, err := h.authority.DecisionAt(ctx, r.Decision, v.observed.ID)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrInvalid) {
				return coldResult{err: ErrUnauthorized}
			}
			return coldResult{err: coldFailure(ctx, err)}
		}
		p = makeProof(d)
	}
	v = h.view.Load()
	if err := h.check(ctx, v, r); err != nil {
		return coldResult{err: err}
	}
	ref, err := h.pinRef(v, r, p)
	if err != nil {
		return coldResult{err: err}
	}
	if err := h.flushRemoval(ctx); err != nil {
		return coldResult{err: coldFailure(ctx, err)}
	}
	resident, err := h.stage(ctx, ref, keepRefs(v), r.Lane)
	if err != nil {
		return coldResult{err: coldFailure(ctx, err)}
	}
	if !resident.ready.Load() {
		if err := h.warm(ctx, [2]rollout.Ref{ref}); err != nil {
			return coldResult{err: coldFailure(ctx, err)}
		}
	}
	v = h.view.Load()
	if err := h.check(ctx, v, r); err != nil {
		return coldResult{err: err}
	}
	if !v.callable(ref) {
		return coldResult{err: ErrUnauthorized}
	}
	h.remember(p)
	if !resident.enter() {
		return coldResult{err: ErrUnavailable}
	}
	return coldResult{resident: resident, ref: ref}
}

func coldFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if errors.Is(err, plg.ErrClosed) || errors.Is(err, ErrClosed) {
		return ErrClosed
	}
	if errors.Is(err, ErrCapacity) || errors.Is(err, plg.ErrMemoryBudget) {
		return ErrCapacity
	}
	if errors.Is(err, ErrPolicy) {
		return ErrPolicy
	}
	return ErrUnavailable
}
