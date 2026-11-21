package dataplane

import (
	"context"
	"time"

	"github.com/heynemann/go-plg"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

// Status reads the locally observed state and actual runtime inspection,
// without fetching authority, artifacts or exporter state.
func (h *Host[T]) Status() Status {
	v, snapshot := h.view.Load(), h.storage.current.Load()
	status := Status{
		Desired: revisionOf(v.observed), Observed: revisionOf(v.observed),
		ExpiresAt: v.proof.deadline.UTC(), Phase: v.observed.State.Phase, Rung: v.observed.State.Rung,
		Failure: v.failure, Unavailable: h.cfg.Unavailable, CacheBytes: snapshot.bytes,
		Retention: h.cfg.RetryHorizon + h.cfg.RetentionMargin, ColdWaiting: h.coldWaiting.Load(),
		Residents: make([]ResidentStatus, 0, len(snapshot.ordered)),
	}
	now := h.cfg.Now()
	status.Fresh = !h.closed.Load() && v.proof.fresh(now)
	status.Ready = h.ready(v, snapshot, now)
	if v.effective != nil {
		status.Effective = revisionOf(v.effective.decision)
		status.EffectiveExpiresAt = v.effective.lease.deadline.UTC()
	}
	if status.Failure == "" && !status.Fresh && status.Observed.Generation != 0 {
		status.Failure = "stale"
	}
	if h.closed.Load() {
		status.Failure = "closed"
	}
	for _, r := range snapshot.ordered {
		info, err := plg.Info(h.ctr, r.key)
		status.Residents = append(status.Residents, ResidentStatus{Digest: r.ref.Digest, Version: r.ref.Version,
			Owner: r.owner, OnCall: r.onCall, Runbook: r.runbook, CacheBytes: r.bytes, Pool: info.Pool,
			RequestedMemory: r.desc.MemoryLimit, RequestedSecrets: len(r.desc.Secrets),
			Ready: r.ready.Load() && err == nil && info.Status == plg.StatusServing && info.Version == r.ref.Digest})
	}
	return status
}

func (h *Host[T]) ready(v *authorityView, snapshot *storageSnapshot, now time.Time) bool {
	r := v.effective
	if h.closed.Load() || r == nil || !r.lease.fresh(now) {
		return false
	}
	state := r.decision.State
	ref := state.Default
	if !readyAssignment(v, r, snapshot, ref, defaultLane(state)) {
		return false
	}
	for _, ref := range required(r.decision, v.denied) {
		if ref == (rollout.Ref{}) {
			continue
		}
		resident := snapshot.byDigest[ref.Digest]
		if resident == nil || !resident.ready.Load() {
			return false
		}
		info, err := plg.Info(h.ctr, resident.key)
		if err != nil || info.Status != plg.StatusServing || info.Version != ref.Digest {
			return false
		}
	}
	return true
}

type seriesKey struct {
	operation string
	lane      Lane
	outcome   string
}

type signals struct {
	tracer       trace.Tracer
	tracing      []attribute.KeyValue
	counter      metric.Int64Counter
	duration     metric.Float64Histogram
	series       map[seriesKey]metric.MeasurementOption
	registration metric.Registration
}

const instrumentation = "github.com/heynemann/go-plg-s3-registry/dataplane"

func (h *Host[T]) startTelemetry() error {
	cfg := h.cfg.Telemetry
	s := &h.signals
	base := []attribute.KeyValue{
		attribute.String("registry", h.scope.Registry), attribute.String("environment", h.scope.Environment),
		attribute.String("plugin", h.scope.Plugin),
	}
	if cfg.TracerProvider != nil {
		s.tracer = cfg.TracerProvider.Tracer(instrumentation)
		s.tracing = append(base, attribute.String("registry.host.id", cfg.HostID),
			attribute.String("registry.host.owner", cfg.HostOwner), attribute.String("registry.operations.owner", cfg.RegistryOwner))
	}
	if cfg.MeterProvider == nil {
		return nil
	}
	m := cfg.MeterProvider.Meter(instrumentation)
	var err error
	s.counter, err = m.Int64Counter("registry.host.operations", metric.WithDescription("SDK operation outcomes by assignment lane and operation class"))
	if err != nil {
		return err
	}
	s.duration, err = m.Float64Histogram("registry.host.duration", metric.WithUnit("s"), metric.WithDescription("SDK operation latency in seconds"))
	if err != nil {
		return err
	}
	revision, err := m.Int64ObservableGauge("registry.host.revision", metric.WithDescription("Desired, verified observed, and locally effective generation"))
	if err != nil {
		return err
	}
	state, err := m.Int64ObservableUpDownCounter("registry.host.state", metric.WithDescription("Hosts reporting fresh authority or a ready route"))
	if err != nil {
		return err
	}
	pressure, err := m.Int64ObservableUpDownCounter("registry.host.pressure", metric.WithDescription("Aggregate go-plg pools, local artifact cache and cold admission pressure"))
	if err != nil {
		return err
	}

	with := func(key, value string) metric.MeasurementOption {
		return metric.WithAttributeSet(attribute.NewSet(base[0], base[1], base[2], attribute.String(key, value)))
	}
	desired, observed, effective := with("stage", "desired"), with("stage", "observed"), with("stage", "effective")
	fresh, ready := with("state", "fresh"), with("state", "ready")
	instances, inUse, waiting := with("kind", "instances"), with("kind", "in_use"), with("kind", "waiting")
	memoryBytes, cacheBytes, coldWaiting := with("kind", "linear_memory_bytes"), with("kind", "cache_bytes"), with("kind", "cold_waiting")
	s.registration, err = m.RegisterCallback(func(_ context.Context, ob metric.Observer) error {
		v, loaded := h.view.Load(), h.storage.current.Load()
		if v.observed.Generation != 0 {
			ob.ObserveInt64(revision, int64(v.observed.Generation), desired)
			ob.ObserveInt64(revision, int64(v.observed.Generation), observed)
		}
		if v.effective != nil {
			ob.ObserveInt64(revision, int64(v.effective.decision.Generation), effective)
		}
		now := h.cfg.Now()
		ob.ObserveInt64(state, indicator(!h.closed.Load() && v.proof.fresh(now)), fresh)
		ob.ObserveInt64(state, indicator(h.ready(v, loaded, now)), ready)
		var live, busy, waits, mem int64
		for _, r := range loaded.ordered {
			info, err := plg.Info(h.ctr, r.key)
			if err != nil || info.Version != r.ref.Digest {
				continue
			}
			live += int64(info.Pool.Instances)
			busy += int64(info.Pool.InUse)
			waits += int64(info.Pool.Waiting)
			mem += int64(info.Pool.Memory)
		}
		ob.ObserveInt64(pressure, live, instances)
		ob.ObserveInt64(pressure, busy, inUse)
		ob.ObserveInt64(pressure, waits, waiting)
		ob.ObserveInt64(pressure, mem, memoryBytes)
		ob.ObserveInt64(pressure, loaded.bytes, cacheBytes)
		ob.ObserveInt64(pressure, h.coldWaiting.Load(), coldWaiting)
		return nil
	}, revision, state, pressure)
	if err != nil {
		return err
	}

	// Materialize only the supported label values; the warm path never builds
	// a new attribute set. Digest, decision and host identity are trace-only.
	s.series = make(map[seriesKey]metric.MeasurementOption)
	failures := []string{"ok", "timeout", "canceled", "stale", "closed", "quarantined", "expired_receipt", "unauthorized",
		"capacity", "policy", "authority_conflict", "verification", "not_found", "unavailable", "warm_failed", "error"}
	for _, op := range []string{"sync", "select", "load", "warm", "invoke", "invoke_retry", "correctness"} {
		lanes := []Lane{"", DefaultLane, BaselineLane, CandidateLane}
		outcomes := failures
		switch op {
		case "sync", "warm":
			lanes = lanes[:1]
		case "invoke", "invoke_retry":
			outcomes = append(append([]string(nil), failures...), "admitted", "call_error", "callback_panic")
		case "correctness":
			lanes = lanes[1:]
			outcomes = []string{string(Correct), string(Incorrect), string(Unknown)}
		}
		for _, lane := range lanes {
			for _, outcome := range outcomes {
				s.defineSeries(base, op, lane, outcome)
			}
			if op == "select" && lane != "" {
				for _, outcome := range []string{"assigned", "targeting_error", "non_match"} {
					s.defineSeries(base, op, lane, outcome)
				}
			}
		}
	}
	return nil
}

func (s *signals) defineSeries(base []attribute.KeyValue, op string, lane Lane, outcome string) {
	label := string(lane)
	if label == "" {
		label = "none"
	}
	s.series[seriesKey{op, lane, outcome}] = metric.WithAttributeSet(attribute.NewSet(base[0], base[1], base[2],
		attribute.String("operation", op), attribute.String("lane", label), attribute.String("outcome", outcome)))
}

func indicator(yes bool) int64 {
	if yes {
		return 1
	}
	return 0
}

func (s *signals) start(ctx context.Context, name string) (context.Context, trace.Span) {
	if s.tracer == nil {
		return ctx, tracenoop.Span{}
	}
	return s.tracer.Start(ctx, name, trace.WithAttributes(s.tracing...))
}

func (s *signals) stop() error {
	if s.registration != nil {
		return s.registration.Unregister()
	}
	return nil
}

func (s *signals) now() time.Time {
	if s.duration == nil {
		return time.Time{}
	}
	return time.Now()
}

func (s *signals) count(ctx context.Context, op string, lane Lane, outcome string) {
	if opt := s.series[seriesKey{op, lane, outcome}]; opt != nil {
		s.counter.Add(ctx, 1, opt)
	}
}

func (s *signals) record(ctx context.Context, op string, lane Lane, outcome string, elapsed time.Duration) {
	if opt := s.series[seriesKey{op, lane, outcome}]; opt != nil {
		s.counter.Add(ctx, 1, opt)
		s.duration.Record(ctx, elapsed.Seconds(), opt)
	}
}

func (s *signals) sync(ctx context.Context, span trace.Span, v *authorityView, elapsed time.Duration, err error) {
	outcome := reason(err)
	s.record(ctx, "sync", "", outcome, elapsed)
	if span.IsRecording() {
		span.SetAttributes(attribute.String("registry.decision", v.observed.ID),
			attribute.Int64("registry.generation", int64(v.observed.Generation)), attribute.String("registry.epoch", v.observed.Scope.Epoch))
		if v.effective != nil {
			span.SetAttributes(attribute.String("registry.effective_decision", v.effective.decision.ID))
		}
		spanResult(span, outcome)
	}
}

func (s *signals) load(ctx context.Context, span trace.Span, digest string, lane Lane, start time.Time, err error) {
	outcome := reason(err)
	if !start.IsZero() {
		s.record(ctx, "load", lane, outcome, time.Since(start))
	}
	if span.IsRecording() {
		span.SetAttributes(attribute.String("registry.digest", digest))
		spanResult(span, outcome)
	}
}

func (s *signals) invocation(ctx context.Context, span trace.Span, r Receipt, op string, start time.Time, admitted, completed bool, err error) {
	recording := span.IsRecording()
	if start.IsZero() && !recording {
		return
	}
	lane := r.Lane
	if !validLane(lane) {
		lane = ""
	}
	outcome := reason(err)
	if admitted {
		s.count(ctx, op, lane, "admitted")
		if !completed {
			outcome = "callback_panic"
		} else if err != nil && outcome != "timeout" && outcome != "canceled" {
			outcome = "call_error"
		}
	}
	if !start.IsZero() {
		s.record(ctx, op, lane, outcome, time.Since(start))
	}
	if recording {
		traceReceipt(span, r, lane)
		span.SetAttributes(attribute.Bool("registry.admitted", admitted))
		spanResult(span, outcome)
	}
}

func traceReceipt(span trace.Span, r Receipt, lane Lane) {
	if digestOK(r.Digest) {
		span.SetAttributes(attribute.String("registry.digest", r.Digest))
	}
	if digestOK(r.Decision) {
		span.SetAttributes(attribute.String("registry.decision", r.Decision))
	}
	if validLane(lane) {
		span.SetAttributes(attribute.String("registry.lane", string(lane)))
	}
	if slug(r.Epoch) {
		span.SetAttributes(attribute.String("registry.epoch", r.Epoch))
	}
	span.SetAttributes(attribute.Int64("registry.generation", int64(r.Generation)))
}

func spanResult(span trace.Span, outcome string) {
	span.SetAttributes(attribute.String("registry.outcome", outcome))
	if outcome != "ok" {
		span.SetStatus(codes.Error, outcome)
	}
}

func (s *signals) owner(span trace.Span, owner, onCall, runbook string) {
	if span.IsRecording() {
		span.SetAttributes(attribute.String("registry.plugin.owner", owner), attribute.String("registry.plugin.on_call", onCall),
			attribute.String("registry.plugin.runbook", runbook))
	}
}

// ReportCorrectness reports a host-owned outcome without exporting business
// values, error strings or the receipt. It never changes serving authority.
func (h *Host[T]) ReportCorrectness(ctx context.Context, r Receipt, result Correctness) error {
	if h.closed.Load() {
		return ErrClosed
	}
	if !h.validReceipt(r) || (result != Correct && result != Incorrect && result != Unknown) {
		return ErrUnauthorized
	}
	ctx, span := h.signals.start(ctx, "registry.correctness")
	defer span.End()
	h.signals.count(ctx, "correctness", r.Lane, string(result))
	if span.IsRecording() {
		traceReceipt(span, r, r.Lane)
		span.SetAttributes(attribute.String("registry.correctness", string(result)))
	}
	return nil
}
