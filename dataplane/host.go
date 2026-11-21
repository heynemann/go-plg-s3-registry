package dataplane

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/heynemann/go-plg"
	"go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
	"github.com/heynemann/go-plg-s3-registry/internal/s3store"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
)

// Host owns one logical plugin and its dedicated go-plg registration. Multiple
// typed hosts may intentionally share a container with distinct registrations.
// Use the checked dispatch methods, not the container catalogue, for this plugin.
type Host[T any] struct {
	cfg           Config
	ctr           *plg.Container
	owned         bool
	scope         rollout.Scope
	releases      registry.Registry
	authority     rollout.Service
	interfaceName string
	storage       localStorage
	view          atomic.Pointer[authorityView]
	coldWaiting   atomic.Int64
	closed        atomic.Bool
	ops           chan laneWork
	lifetime      context.Context
	stop          context.CancelFunc
	stopped       chan struct{}
	signals       signals
	// The worker alone owns these fields. Readers see immutable snapshots.
	entries        map[string]*resident
	removalPending bool
	cacheBytes     int64
	proofs         atomic.Pointer[decisionCache]
}

type laneWork struct {
	ctx context.Context
	run func(context.Context)
}

type lease struct {
	generation                   uint64
	proofAt, deadline, monotonic time.Time
	expired                      *atomic.Bool
}

func (l lease) fresh(now time.Time) bool {
	if l.expired == nil || l.expired.Load() {
		return false
	}
	if !now.Before(l.deadline) || !time.Now().Before(l.monotonic) {
		l.expired.Store(true)
		return false
	}
	return !l.expired.Load()
}

type route struct {
	proof    decisionProof
	decision rollout.Decision
	program  *target.Program
	lease    lease
}

type authorityView struct {
	observed      rollout.Decision
	observedProof decisionProof
	retired       map[rollout.Ref]time.Time
	effective     *route
	proof         lease               // last independently verified proof, even if warming failed
	denied        map[string]struct{} // includes unproven restorations until a current proof arrives
	failure       string
}

// Attach registers an initially empty, local storage. With a nil container it
// creates and owns a container whose memory ceiling includes draining pools,
// and whose digest-labelled go-plg metrics and traces are disabled. A supplied
// container must be created with plg.WithMemoryBudget to bound draining memory
// (SDK budgets also limit staged pools), and its telemetry must drop or adapt
// digest-key metric labels. Close the returned host when no longer needed.
//
// opts are trusted, fixed host grants (e.g. WithHost or WithHTTP), not release
// configuration. Do not add other storages or mutate this registration outside
// Host. The host overrides poll, memory and pool options with its own limits.
// Attach does not contact S3; call Sync or Run to bootstrap readiness.
func Attach[T any](ctx context.Context, container *plg.Container, cfg Config, opts ...plg.RegisterOption) (*Host[T], error) {
	if err := cfg.settle(); err != nil {
		return nil, err
	}
	cfg.Trust = pinnedTrust(cfg.Trust)
	typ := reflect.TypeFor[T]()
	if typ.Kind() != reflect.Interface || typ.Name() == "" {
		return nil, errors.New("dataplane: expected a named plugin interface")
	}
	scope := rollout.Scope{Registry: cfg.Registry, Environment: cfg.Environment, Plugin: cfg.Plugin, Epoch: cfg.Epoch}
	store := readonlyStore{s3store.New(cfg.Client, cfg.Bucket, cfg.BucketOwner)}
	releases, err := registry.New(store, cfg.Registry)
	if err != nil {
		return nil, err
	}
	h := &Host[T]{
		cfg: cfg, ctr: container, owned: container == nil, scope: scope, releases: releases,
		authority:     rollout.Service{Store: store, Scope: scope, Trust: cfg.Trust, Now: cfg.Now, MaxClockSkew: cfg.MaxClockSkew},
		interfaceName: typ.PkgPath() + "." + typ.Name(), ops: make(chan laneWork), stopped: make(chan struct{}),
		entries: make(map[string]*resident),
	}
	h.view.Store(&authorityView{})
	h.storage.current.Store(&storageSnapshot{})
	if h.owned {
		h.ctr = plg.New(plg.WithMemoryBudget(cfg.MemoryBudget), plg.WithMeterProvider(noop.NewMeterProvider()),
			plg.WithTracerProvider(tracenoop.NewTracerProvider()))
	}
	if err := h.startTelemetry(); err != nil {
		if h.owned {
			_ = h.ctr.Close(ctx)
		}
		return nil, err
	}
	opts = append([]plg.RegisterOption(nil), opts...)
	opts = append(opts, plg.WithStorage(&h.storage), plg.WithPollInterval(0),
		plg.WithMemoryLimit(cfg.MemoryLimit), plg.WithPool(cfg.PoolMin, cfg.PoolMax), plg.WithRequiredOwnership())
	if err := plg.Register[T](ctx, h.ctr, cfg.Registration, opts...); err != nil {
		_ = h.signals.stop()
		if h.owned {
			_ = h.ctr.Close(ctx)
		}
		return nil, fmt.Errorf("dataplane: register host contract: %w", err)
	}
	h.lifetime, h.stop = context.WithCancel(context.Background())
	go h.work(h.lifetime)
	return h, nil
}

func pinnedTrust(trust Trust) Trust {
	cloneKeys := func(keys []Key) []Key {
		keys = slices.Clone(keys)
		for i := range keys {
			k := keys[i].PublicKey
			if k == nil || k.X == nil || k.Y == nil {
				continue
			}
			keys[i].PublicKey = &ecdsa.PublicKey{Curve: k.Curve, X: new(big.Int).Set(k.X), Y: new(big.Int).Set(k.Y)}
		}
		return keys
	}
	trust.Deciders = cloneKeys(trust.Deciders)
	trust.Approvers = cloneKeys(trust.Approvers)
	trust.Responders = cloneKeys(trust.Responders)
	trust.Renewers = cloneKeys(trust.Renewers)
	trust.Recoverers = cloneKeys(trust.Recoverers)
	trust.Proposers = cloneKeys(trust.Proposers)
	return trust
}

// readonlyStore intentionally has no working write or list method, even if a
// misconfigured deployment supplies a client with broader S3 credentials.
type readonlyStore struct{ store s3store.Store }

func (s readonlyStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.store.Open(ctx, key)
}
func (s readonlyStore) Read(ctx context.Context, key string) (io.ReadCloser, string, error) {
	return s.store.Read(ctx, key)
}
func (readonlyStore) Create(context.Context, string, []byte) error { return registry.ErrDenied }
func (readonlyStore) CompareAndSwap(context.Context, string, string, []byte) error {
	return registry.ErrDenied
}
func (readonlyStore) List(context.Context, string, func(string) error) error {
	return registry.ErrDenied
}

func (c *Config) settle() error {
	if c.Bucket == "" || c.Client == nil || !slug(c.Registry) || !slug(c.Environment) || !slug(c.Plugin) || !slug(c.Epoch) {
		return errors.New("dataplane: expected S3 client, bucket, registry, environment, plugin and epoch")
	}
	if c.BucketOwner == "" {
		base := c.Client.Options().BaseEndpoint
		if base == nil {
			return errors.New("dataplane: expected AWS bucket owner")
		}
		u, err := url.Parse(*base)
		if err != nil || u == nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			return errors.New("dataplane: expected AWS bucket owner")
		}
	} else if len(c.BucketOwner) != 12 || strings.IndexFunc(c.BucketOwner, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return errors.New("dataplane: expected a 12-digit AWS bucket owner")
	}
	if c.Registration == "" {
		c.Registration = c.Plugin
	}
	if !slug(c.Registration) || (c.Unavailable != Hold && c.Unavailable != Reject && c.Unavailable != Disable) {
		return errors.New("dataplane: expected registration slug and explicit hold, reject or disable behavior")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.SyncTimeout == 0 {
		c.SyncTimeout = 30 * time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.RetryHorizon <= 0 || c.RetentionMargin < 0 || c.RetryHorizon+c.RetentionMargin < c.RetryHorizon ||
		c.Trust.MaxLease <= 0 || c.MaxClockSkew < 0 || c.MaxClockSkew >= c.Trust.MaxLease ||
		c.SyncTimeout < 0 || c.PollInterval < 0 {
		return errors.New("dataplane: invalid clock, freshness, retry or sync bounds")
	}
	if c.PoolMin == 0 {
		c.PoolMin = 1
	}
	if c.PoolMax == 0 {
		c.PoolMax = c.PoolMin
	}
	if c.MemoryLimit == 0 {
		c.MemoryLimit = 128 << 20
	}
	const wasmPage = 1 << 16
	if c.PoolMin < 1 || c.PoolMin > c.PoolMax || c.PoolMax > 4096 || c.MemoryLimit < wasmPage ||
		c.MemoryLimit > 4<<30 || c.MemoryLimit%wasmPage != 0 || c.MaxHistoricalResidents < 0 || c.MaxHistoricalResidents > 64 {
		return errors.New("dataplane: invalid resident, pool or memory limit")
	}
	one := uint64(c.PoolMax) * c.MemoryLimit
	if c.MemoryBudget == 0 {
		c.MemoryBudget = one * uint64(4+max(1, c.MaxHistoricalResidents))
	}
	if c.MaxCacheBytes == 0 {
		c.MaxCacheBytes = int64(4+max(1, c.MaxHistoricalResidents)) * (plg.MaxPluginSize + plg.MaxPluginPathBytes)
	}
	if c.MaxPendingCold == 0 {
		c.MaxPendingCold = 8
	}
	if c.MaxCacheBytes < 1 || c.MaxPendingCold < 1 || c.MaxPendingCold > 1024 {
		return errors.New("dataplane: invalid cache, download or memory budget")
	}
	return nil
}

func slug(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (h *Host[T]) work(ctx context.Context) {
	defer close(h.stopped)
	for {
		select {
		case <-ctx.Done():
			return
		case op := <-h.ops:
			if op.ctx.Err() != nil || ctx.Err() != nil {
				continue
			}
			runCtx, cancel := context.WithCancel(op.ctx)
			stop := context.AfterFunc(ctx, cancel)
			op.run(runCtx)
			stop()
			cancel()
		}
	}
}

// Close stops this SDK's operations and its telemetry. The caller remains
// responsible for closing a borrowed container and not using its abandoned
// registration. Close the host outside any of its own invocation callbacks.
func (h *Host[T]) Close(ctx context.Context) error {
	first := h.closed.CompareAndSwap(false, true)
	var err error
	if first {
		h.stop()
		err = h.signals.stop()
	}
	select {
	case <-h.stopped:
	case <-ctx.Done():
		err = errors.Join(err, context.Cause(ctx))
	}
	if h.owned && first {
		err = errors.Join(err, h.ctr.Close(ctx))
	}
	return err
}

// Run reconciles immediately and periodically. Operational failures are
// retained in Status and telemetry; Run returns only on cancellation or Close.
func (h *Host[T]) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(h.lifetime, cancel)
	defer stop()
	t := time.NewTicker(h.cfg.PollInterval)
	defer t.Stop()
	var running chan struct{}
	startSync := func() {
		done := make(chan struct{})
		running = done
		go func() { defer close(done); _ = h.Sync(ctx) }()
	}
	startSync()
	for {
		select {
		case <-ctx.Done():
			if h.closed.Load() {
				return ErrClosed
			}
			return context.Cause(ctx)
		case <-h.stopped:
			return ErrClosed
		case <-running:
			running = nil
		case <-t.C:
			if running == nil {
				startSync()
				continue
			}
			// Continue observing containment while warm-up or a cold
			// admission occupies the ownership lane.
			poll, stop := context.WithTimeout(ctx, h.cfg.SyncTimeout)
			floor := h.view.Load().observed.ID
			if err := h.observe(poll); err != nil {
				h.failure(floor, reason(err))
			}
			stop()
		}
	}
}

// Sync verifies authority before entering the warm-up lane, so a newly
// verified deny can supersede an earlier round still warming its candidate.
func (h *Host[T]) Sync(ctx context.Context) (err error) {
	if h.closed.Load() {
		return ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, h.cfg.SyncTimeout)
	defer cancel()
	stop := context.AfterFunc(h.lifetime, cancel)
	defer stop()
	ctx, span := h.signals.start(ctx, "registry.sync")
	defer span.End()
	start := time.Now()
	defer func() {
		s := h.view.Load()
		h.signals.sync(ctx, span, s, time.Since(start), err)
	}()
	floor := h.view.Load().observed.ID
	defer func() {
		if err != nil {
			h.failure(floor, reason(err))
		}
	}()
	if err = h.observe(ctx); err != nil {
		return err
	}
	floor = h.view.Load().observed.ID
	done := make(chan error, 1)
	select {
	case h.ops <- laneWork{ctx, func(ctx context.Context) { done <- h.reconcile(ctx) }}:
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-h.stopped:
		return ErrClosed
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-h.stopped:
		return ErrClosed
	}
}
