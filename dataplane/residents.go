package dataplane

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/heynemann/go-plg"
	"go.opentelemetry.io/otel/attribute"

	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
)

const storageName = "registry-local"
const retiredBit uint64 = 1 << 63

var errWarm = errors.New("registry release did not warm")

type resident struct {
	ref                    rollout.Ref
	key                    string
	desc                   plg.Descriptor
	artifact               *plg.Artifact
	bytes                  int64
	reservation            uint64
	owner, onCall, runbook string
	aliases                atomic.Pointer[[]string] // additional verified version bindings for these exact bytes
	ready                  atomic.Bool
	users                  atomic.Uint64
}

// Retiring a key and acquiring a dispatch reference compete on the same
// word. A successful acquire pins the immutable key through the callback,
// including while go-plg waits for a pool slot. No lane is held by a call.
func (r *resident) enter() bool {
	for {
		n := r.users.Load()
		if n >= retiredBit-1 {
			return false
		}
		if r.users.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (r *resident) leave() { r.users.Add(^uint64(0)) }

func (r *resident) bound(ref rollout.Ref) bool {
	if ref.Digest != r.ref.Digest {
		return false
	}
	if ref.Version == r.ref.Version {
		return true
	}
	aliases := r.aliases.Load()
	return aliases != nil && slices.Contains(*aliases, ref.Version)
}

type storageSnapshot struct {
	byKey    map[string]*resident
	byDigest map[string]*resident
	ordered  []*resident
	bytes    int64
}

type localStorage struct {
	current atomic.Pointer[storageSnapshot]
}

func (*localStorage) Name() string { return storageName }

func (s *localStorage) List(ctx context.Context) ([]plg.Descriptor, error) {
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	current := s.current.Load()
	out := make([]plg.Descriptor, len(current.ordered))
	for i, r := range current.ordered {
		out[i] = r.desc
	}
	return out, nil
}

func (s *localStorage) Open(ctx context.Context, d *plg.Descriptor) (fs.FS, error) {
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	if d != nil {
		r := s.current.Load().byKey[d.Key]
		if r != nil && r.desc.Version == d.Version {
			return r.artifact, nil
		}
	}
	return nil, fs.ErrNotExist
}

func (h *Host[T]) publishStorage() {
	s := &storageSnapshot{byKey: make(map[string]*resident, len(h.entries)),
		byDigest: make(map[string]*resident, len(h.entries)), ordered: make([]*resident, 0, len(h.entries)), bytes: h.cacheBytes}
	for _, r := range h.entries {
		s.byKey[r.desc.Key] = r
		s.byDigest[r.ref.Digest] = r
		s.ordered = append(s.ordered, r)
	}
	slices.SortFunc(s.ordered, func(a, b *resident) int { return strings.Compare(a.key, b.key) })
	h.storage.current.Store(s)
}

// required includes the zero-rung candidate during the warm phase, but not a
// rollback's retired candidate, a superseded baseline, or a denied digest.
func required(d rollout.Decision, denied map[string]struct{}) [2]rollout.Ref {
	s := d.State
	refs := [2]rollout.Ref{s.Default}
	switch s.Phase {
	case "warming", "ramping", "paused", "finished":
		if s.Plan.Candidate != s.Default {
			refs[1] = s.Plan.Candidate
		}
	}
	for i, ref := range refs {
		if _, blocked := denied[ref.Digest]; blocked {
			refs[i] = rollout.Ref{}
		}
	}
	return refs
}

func keepRefs(v *authorityView) map[string]bool {
	// During staging preserve both plans' non-quarantined route keys.
	keep := make(map[string]bool, 5)
	for _, ref := range required(v.observed, v.denied) {
		if ref.Digest != "" {
			keep[ref.Digest] = true
		}
	}
	if v.effective != nil {
		for _, ref := range required(v.effective.decision, v.denied) {
			if ref.Digest != "" {
				keep[ref.Digest] = true
			}
		}
	}
	return keep
}

func (h *Host[T]) reconcile(ctx context.Context) (err error) {
	view := h.view.Load()
	d := view.observed
	defer func() {
		if err != nil {
			h.failure(d.ID, reason(err))
		}
	}()
	if d.State.Plan.Unavailable != string(h.cfg.Unavailable) {
		return ErrPolicy
	}
	if err := h.flushRemoval(ctx); err != nil {
		return err
	}
	keep := keepRefs(view)
	if err := h.trim(ctx, keep, h.cfg.MaxHistoricalResidents, 0, 0); err != nil && !errors.Is(err, ErrCapacity) {
		return err
	}
	refs := required(d, view.denied)
	// Compile on route change only. S3 and this lane are never part of warm
	// dispatch. go-plg reload may fail unrelated keys: inspect each required key.
	var program *target.Program
	if view.effective != nil && view.effective.decision.State.PlanID == d.State.PlanID {
		program = view.effective.program
	} else if d.State.Plan.Baseline != (rollout.Ref{}) {
		program, err = target.Compile(d.State.Plan.Target)
		if err != nil {
			return ErrPolicy
		}
	}
	var warmed bool
	for i, ref := range refs {
		if ref == (rollout.Ref{}) {
			continue
		}
		lane := defaultLane(d.State)
		if i == 1 {
			lane = CandidateLane
		}
		r, err := h.stage(ctx, ref, keep, lane)
		if err != nil {
			return err
		}
		warmed = !h.inspectReady(ctx, r) || warmed
	}
	if warmed {
		if err := h.warm(ctx, refs); err != nil {
			return err
		}
	}
	if warmed || view.effective == nil || view.effective.decision.ID != d.ID {
		// Do not promote after a long warm-up without checking authority again.
		if err := h.observe(ctx); err != nil {
			return err
		}
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if h.closed.Load() {
			return ErrClosed
		}
		prior := h.view.Load()
		if prior.observed.ID != d.ID || required(d, prior.denied) != refs {
			return ErrStale
		}
		if prior.proof.generation != d.Generation || !prior.proof.fresh(h.cfg.Now()) {
			return ErrStale
		}
		if prior.effective != nil && prior.effective.decision.ID == d.ID && prior.failure == "" {
			break
		}
		// Keep the old receipt proof locally when replacing the effective route.
		if prior.effective != nil {
			h.remember(prior.effective.proof)
		}
		next := *prior
		next.effective = &route{decision: d, proof: prior.observedProof, program: program, lease: prior.proof}
		next.failure = ""
		if h.view.CompareAndSwap(prior, &next) {
			break
		}
	}
	// A busy historical key can transiently exceed the desired historical
	// count; it stays charged and is eligible for pruning on the next pass.
	err = h.trim(ctx, keepRefs(h.view.Load()), h.cfg.MaxHistoricalResidents, 0, 0)
	if errors.Is(err, ErrCapacity) {
		err = nil
	}
	if err == nil && refs == [2]rollout.Ref{} {
		if d.State.Default.Digest != "" && view.quarantined(d.State.Default.Digest) {
			return ErrQuarantined
		}
		return ErrUnavailable
	}
	return err
}

// stage verifies a binding before exposing any descriptor. The lane limits
// archive verification/decompression to one fetch, independent of resident
// capacity and bounded by registry.Fetch's per-download limits.
func (h *Host[T]) stage(ctx context.Context, ref rollout.Ref, keep map[string]bool, lane Lane) (*resident, error) {
	if existing := h.entries[ref.Digest]; existing != nil {
		if existing.bound(ref) {
			return existing, nil
		}
		verified, err := h.fetch(ctx, ref, lane)
		if err != nil {
			return nil, err
		}
		// Exact bytes can be independently admitted under another version.
		// Never let an alias change the owner of a running immutable key.
		if verified.owner != existing.owner || verified.onCall != existing.onCall || verified.runbook != existing.runbook {
			return nil, ErrPolicy
		}
		h.bindAlias(existing, ref.Version)
		return existing, nil
	}
	r, err := h.fetch(ctx, ref, lane)
	if err != nil {
		return nil, err
	}
	limit := max(1, h.cfg.MaxHistoricalResidents)
	if !keep[ref.Digest] {
		limit--
	}
	if err := h.trim(ctx, keep, limit, r.bytes, r.reservation); err != nil {
		return nil, err
	}
	h.entries[ref.Digest] = r
	h.cacheBytes += r.bytes
	h.publishStorage()
	return r, nil
}

func (h *Host[T]) bindAlias(r *resident, version string) {
	var aliases []string
	if old := r.aliases.Load(); old != nil {
		aliases = *old
	}
	const maxAliases = 8
	next := make([]string, 0, min(maxAliases, len(aliases)+1))
	if len(aliases) >= maxAliases {
		v := h.view.Load()
		var effective [2]rollout.Ref
		if v.effective != nil {
			effective = required(v.effective.decision, nil)
		}
		desired := required(v.observed, nil)
		skipped := false
		for _, alias := range aliases {
			ref := rollout.Ref{Digest: r.ref.Digest, Version: alias}
			if !skipped && !slices.Contains(effective[:], ref) && !slices.Contains(desired[:], ref) {
				skipped = true
				continue
			}
			next = append(next, alias)
		}
	} else {
		next = append(next, aliases...)
	}
	next = append(next, version)
	r.aliases.Store(&next)
}

func (h *Host[T]) warm(ctx context.Context, refs [2]rollout.Ref) (err error) {
	ctx, span := h.signals.start(ctx, "registry.warm")
	defer span.End()
	start := h.signals.now()
	defer func() {
		if !start.IsZero() {
			h.signals.record(ctx, "warm", "", reason(err), time.Since(start))
		}
		if span.IsRecording() {
			spanResult(span, reason(err))
		}
	}()
	reloadErr := plg.ReloadInterface(ctx, h.ctr, h.cfg.Registration)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if errors.Is(reloadErr, plg.ErrClosed) {
		return ErrClosed
	}
	var failed bool
	for _, ref := range refs {
		if ref == (rollout.Ref{}) {
			continue
		}
		failed = !h.inspectReady(ctx, h.entries[ref.Digest]) || failed
	}
	if failed {
		if errors.Is(reloadErr, plg.ErrMemoryBudget) {
			return ErrCapacity
		}
		return errors.Join(errWarm, reloadErr)
	}
	return nil
}

func (h *Host[T]) fetch(ctx context.Context, ref rollout.Ref, lane Lane) (_ *resident, err error) {
	ctx, span := h.signals.start(ctx, "registry.load")
	defer span.End()
	start := h.signals.now()
	defer func() { h.signals.load(ctx, span, ref.Digest, lane, start, err) }()
	release, art, err := h.releases.Fetch(ctx, h.cfg.Plugin, ref.Version, ref.Digest)
	if err != nil {
		return nil, err
	}
	// Drop query and fragment in diagnostics; even trusted runbook metadata
	// must not become a transport for credentials.
	runbook := release.Runbook
	if i := strings.IndexAny(runbook, "?#"); i >= 0 {
		runbook = runbook[:i]
	}
	h.signals.owner(span, release.Owner, release.OnCall, runbook)
	if span.IsRecording() {
		span.SetAttributes(attribute.Int64("registry.memory.request_bytes", int64(release.Capabilities.MemoryBytes)),
			attribute.Int64("registry.memory.ceiling_bytes", int64(h.cfg.MemoryLimit)),
			attribute.Int("registry.secrets.request_count", len(release.Capabilities.Secrets)))
	}
	manifest, err := art.ReadFile("plugin.yaml")
	if err != nil {
		return nil, ErrPolicy
	}
	desc, err := plg.ParseManifest(manifest)
	if err != nil {
		return nil, ErrPolicy
	}
	if !strings.HasPrefix(desc.Implements, h.interfaceName+"@") ||
		(h.cfg.ContractModule != "" && release.Contract.Module != h.cfg.ContractModule) ||
		(h.cfg.ContractVersion != "" && release.Contract.ModuleVersion != h.cfg.ContractVersion) ||
		release.Capabilities.MemoryBytes > h.cfg.MemoryLimit {
		return nil, ErrPolicy
	}
	if h.cfg.Policy == nil {
		if len(release.Capabilities.Secrets) != 0 {
			return nil, ErrPolicy
		}
	} else if h.cfg.Policy(CapabilityRequest{
		Digest: ref.Digest, Version: ref.Version, Owner: release.Owner, Language: desc.Language,
		Interface: release.Contract.Interface, ContractModule: release.Contract.Module, ContractVersion: release.Contract.ModuleVersion,
		Secrets: slices.Clone(release.Capabilities.Secrets), MemoryBytes: release.Capabilities.MemoryBytes, MemoryCeiling: h.cfg.MemoryLimit,
	}) != nil {
		return nil, ErrPolicy
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	bytes, err := artifactFootprint(ctx, art, h.cfg.MaxCacheBytes)
	if err != nil {
		return nil, err
	}
	mem := desc.MemoryLimit
	if mem == 0 {
		mem = h.cfg.MemoryLimit
	}
	// Round identically to go-plg's linear-memory reservation.
	mem -= mem % (1 << 16)
	desc.Key = h.cfg.Plugin + "-" + ref.Digest[len("sha256:"):]
	desc.Version = ref.Digest
	owner := &plg.Owner{Team: plg.Team{Name: release.Owner}, Contact: plg.Contact{Oncall: release.OnCall}}
	if len(runbook) <= plg.MaxOwnerStringBytes {
		owner.Links.Runbook = runbook
	}
	desc.Owner = owner
	r := &resident{ref: ref, key: h.cfg.Registration + "/" + desc.Key, desc: desc, artifact: art, bytes: bytes,
		reservation: mem * uint64(h.cfg.PoolMax), owner: release.Owner, onCall: release.OnCall, runbook: runbook}
	return r, nil
}

func artifactFootprint(ctx context.Context, art *plg.Artifact, budget int64) (int64, error) {
	p := art.Provenance()
	bytes := int64(len(p.Report) + len(p.Commit) + len(p.Digest) + len(p.PlgVersion) + len(p.Contract.Path) + len(p.Contract.Version))
	if bytes > budget {
		return 0, ErrCapacity
	}
	err := fs.WalkDir(art, ".", func(path string, ent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		bytes += int64(len(path))
		if !ent.IsDir() {
			info, err := ent.Info()
			if err != nil {
				return err
			}
			bytes += info.Size()
		}
		if bytes > budget {
			return ErrCapacity
		}
		return nil
	})
	return bytes, err
}

func (h *Host[T]) inspectReady(ctx context.Context, r *resident) bool {
	info, err := plg.Info(h.ctr, r.key)
	ready := err == nil && info.Status == plg.StatusServing && info.Storage == storageName &&
		info.Version == r.ref.Digest && info.Provenance != nil && info.Provenance.Digest == r.artifact.Provenance().Digest &&
		info.Pool.Instances >= h.cfg.PoolMin
	if ready {
		_, err = plg.Get[T](ctx, h.ctr, r.key)
		ready = err == nil
	}
	r.ready.Store(ready)
	return ready
}

func (h *Host[T]) flushRemoval(ctx context.Context) error {
	if !h.removalPending {
		return nil
	}
	err := plg.ReloadInterface(ctx, h.ctr, h.cfg.Registration)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if errors.Is(err, plg.ErrClosed) {
		return ErrClosed
	}
	// Its result can include unrelated load errors, but the completed round
	// has applied removals (local Storage.List cannot fail in a live round).
	h.removalPending = false
	return nil
}

func (h *Host[T]) trim(ctx context.Context, keep map[string]bool, maxHistorical int, extraBytes int64, extraMemory uint64) error {
	var reserved uint64
	historical := 0
	for digest, r := range h.entries {
		reserved += r.reservation
		if !keep[digest] {
			historical++
		}
	}
	if extraBytes > h.cfg.MaxCacheBytes || extraMemory > h.cfg.MemoryBudget {
		return ErrCapacity
	}
	over := func() bool {
		return historical > maxHistorical || h.cacheBytes > h.cfg.MaxCacheBytes-extraBytes ||
			reserved > h.cfg.MemoryBudget-extraMemory
	}
	if !over() {
		return nil
	}
	for digest, r := range h.entries {
		if !over() {
			break
		}
		if keep[digest] || !r.users.CompareAndSwap(0, retiredBit) {
			continue
		}
		delete(h.entries, digest)
		h.cacheBytes -= r.bytes
		reserved -= r.reservation
		historical--
		h.removalPending = true
	}
	if h.removalPending {
		h.publishStorage()
		if err := h.flushRemoval(ctx); err != nil {
			return err
		}
	}
	if over() {
		return ErrCapacity
	}
	return nil
}
