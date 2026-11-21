// Package dataplane selects and dispatches exact, locally admitted releases.
// The application owns durable receipt storage and supplies a read-only S3 client.
package dataplane

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/heynemann/go-plg"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

// Key and Trust describe deployment-pinned, purpose-scoped authority.
type Key = rollout.Key
type Trust = rollout.Trust

// Unavailable is the action the application must take when no assignment or
// invocation can be admitted. Disable is only for applications with an optional plugin.
type Unavailable string

const (
	Hold    Unavailable = "hold"
	Reject  Unavailable = "reject"
	Disable Unavailable = "disable"
)

var (
	ErrUnavailable    = errors.New("no authorized ready release")
	ErrStale          = errors.New("registry authority is not fresh")
	ErrQuarantined    = errors.New("release is quarantined")
	ErrReceiptExpired = errors.New("selection receipt expired")
	ErrUnauthorized   = errors.New("selection receipt is not authorized")
	ErrCapacity       = errors.New("registry host capacity exhausted")
	ErrPolicy         = errors.New("release exceeds host permissions or is incompatible")
	ErrClosed         = errors.New("registry host is closed")
)

// AdmissionError distinguishes the authorization failure from the host's
// response to it. In particular none of the actions authorize repinning.
type AdmissionError struct {
	Action Unavailable
	Cause  error
}

func (e *AdmissionError) Error() string { return string(e.Action) + ": " + e.Cause.Error() }
func (e *AdmissionError) Unwrap() error { return e.Cause }

// Lane identifies the assignment path. It remains fixed on retries.
type Lane string

const (
	DefaultLane   Lane = "default"
	BaselineLane  Lane = "baseline"
	CandidateLane Lane = "candidate"
)

// Receipt is trusted workflow data, not an authorization token from a caller.
// Persist it before the first side effect; reuse it verbatim on retry. It says
// nothing about whether a guest completed a call or a side effect happened.
type Receipt struct {
	Version     uint8     `json:"version"`
	Registry    string    `json:"registry"`
	Environment string    `json:"environment"`
	Plugin      string    `json:"plugin"`
	Epoch       string    `json:"epoch"`
	Digest      string    `json:"digest"`
	Generation  uint64    `json:"generation"`
	Decision    string    `json:"decision"`
	SelectedAt  time.Time `json:"selected_at"`
	Lane        Lane      `json:"lane"`
}

// CapabilityRequest is verified release metadata, not a grant. The policy
// receives its own copy of the declared secret names; no secret values are read
// or injected by the SDK. Network and host functions are fixed by the trusted
// registration options, not by an archive, plan, release or receipt.
type CapabilityRequest struct {
	Digest, Version, Owner    string
	Language                  plg.Language
	Interface, ContractModule string
	ContractVersion           string
	Secrets                   []string
	MemoryBytes               uint64
	MemoryCeiling             uint64
}

// Config is trusted deployment configuration. Client must be read-only. An
// expected AWS bucket owner is required except for a loopback fixture endpoint.
// RetryHorizon is the accepted age of a stored receipt; provision callable
// artifact and decision retention through last assignment plus RetryHorizon
// and RetentionMargin, independently of any archive deletion policy.
type Config struct {
	Bucket, BucketOwner, Registry, Environment, Plugin, Epoch, Registration string
	Client                                                                  *s3.Client
	Trust                                                                   Trust
	Unavailable                                                             Unavailable
	// ContractModule and ContractVersion, when set, pin exact release compatibility
	// in addition to the typed contract and go-plg's own manifest checks.
	ContractModule, ContractVersion string
	// Policy, when non-nil, must approve every request. Without it requests for
	// secrets are rejected; with it a nil return explicitly approves the requested
	// names, not any other host grant. MemoryLimit always applies.
	Policy                                                                 func(CapabilityRequest) error
	Now                                                                    func() time.Time
	MaxClockSkew, RetryHorizon, RetentionMargin, PollInterval, SyncTimeout time.Duration
	PoolMin, PoolMax                                                       int
	MemoryLimit, MemoryBudget                                              uint64
	// MaxHistoricalResidents is the idle historical pool limit. With zero,
	// one cold key may be staged for dispatch and pruned at the next sync.
	// Keys with active dispatch references still count against MemoryBudget.
	MaxHistoricalResidents int
	MaxCacheBytes          int64
	MaxPendingCold         int
	Telemetry              Telemetry
}

// Telemetry uses only explicit providers. HostID and owner routing identifiers
// are trace attributes, not metric dimensions. The host owns export and alerting.
type Telemetry struct {
	MeterProvider                    metric.MeterProvider
	TracerProvider                   trace.TracerProvider
	HostID, HostOwner, RegistryOwner string
}

// Revision identifies a verified rollout decision, not an artifact.
type Revision struct {
	Generation uint64 `json:"generation"`
	Decision   string `json:"decision"`
	Epoch      string `json:"epoch"`
}

// ResidentStatus reports the actual runtime pool for a locally staged digest.
type ResidentStatus struct {
	Digest, Version, Owner, OnCall, Runbook string
	Ready                                   bool
	Pool                                    plg.PoolStats
	CacheBytes                              int64
	RequestedMemory                         uint64
	RequestedSecrets                        int
}

// Status is local and requires no network. Desired is the latest committed
// revision advertised by observation, Observed the verified replay floor, and
// Effective the revision that last passed the local warm gate. Ready takes
// account of current expiry, containment and the routes' runtime availability.
type Status struct {
	Desired, Observed, Effective  Revision
	Phase                         string
	Rung                          uint16
	Ready, Fresh                  bool
	ExpiresAt, EffectiveExpiresAt time.Time
	Failure                       string
	Unavailable                   Unavailable
	Residents                     []ResidentStatus
	CacheBytes                    int64
	Retention                     time.Duration
	ColdWaiting                   int64
}

// Correctness is the application's own bounded assessment of a call's result.
type Correctness string

const (
	Correct   Correctness = "correct"
	Incorrect Correctness = "incorrect"
	Unknown   Correctness = "unknown"
)
