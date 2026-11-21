// Package rollout implements the registry's signed, conditionally committed control state.
package rollout

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bytedance/sonic"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
)

const wireVersion = 1

var (
	slug           = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	releaseVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Scope binds a decision to an environment and to a deployment-approved authority epoch.
type Scope struct {
	Registry    string `json:"registry"`
	Environment string `json:"environment"`
	Plugin      string `json:"plugin"`
	Epoch       string `json:"epoch"`
}

func (s Scope) validate() error {
	if !slug.MatchString(s.Registry) || !slug.MatchString(s.Environment) || !slug.MatchString(s.Plugin) || !slug.MatchString(s.Epoch) {
		return fmt.Errorf("%w: registry, environment, plugin and epoch must be lowercase slugs", registry.ErrInvalid)
	}
	return nil
}

func (s Scope) samePlugin(t Scope) bool {
	return s.Registry == t.Registry && s.Environment == t.Environment && s.Plugin == t.Plugin
}

// Ref identifies both an admitted release binding and its exact bytes.
type Ref struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

func (r Ref) valid() bool {
	return releaseVersion.MatchString(r.Version) && digestPattern.MatchString(r.Digest)
}

// Plan is immutable after proposal. The human approval binds its exact payload.
type Plan struct {
	Scope          Scope       `json:"scope"`
	Candidate      Ref         `json:"candidate"`
	Baseline       Ref         `json:"baseline"`
	Target         target.Spec `json:"target"`
	Rungs          []uint16    `json:"rungs"`
	Evidence       []string    `json:"evidence"`
	StopConditions []string    `json:"stop_conditions"`
	AllowDefault   bool        `json:"allow_default"`
	Unavailable    string      `json:"unavailable"`
}

func (p Plan) Validate() error {
	if err := p.Scope.validate(); err != nil {
		return err
	}
	if !p.Candidate.valid() || !texts(p.Evidence, 16) || !texts(p.StopConditions, 16) {
		return fmt.Errorf("%w: invalid candidate or plan evidence", registry.ErrInvalid)
	}
	switch p.Unavailable {
	case "hold", "reject", "disable":
	default:
		return fmt.Errorf("%w: unavailable behavior must be hold, reject or disable", registry.ErrInvalid)
	}
	if p.Baseline == (Ref{}) {
		if len(p.Rungs) != 0 || p.Target.Version != 0 || p.Target.Expression != "" || len(p.Target.Attributes) != 0 || p.Target.Seed != "" || p.AllowDefault {
			return fmt.Errorf("%w: first activation cannot include targeting, rungs or a default switch", registry.ErrInvalid)
		}
		return nil
	}
	if !p.Baseline.valid() || p.Baseline.Digest == p.Candidate.Digest || len(p.Rungs) == 0 || len(p.Rungs) > 32 ||
		len(p.Evidence) == 0 || len(p.StopConditions) == 0 {
		return fmt.Errorf("%w: an upgrade needs a different baseline, rungs, evidence and stop conditions", registry.ErrInvalid)
	}
	var prev uint16
	for _, rung := range p.Rungs {
		if rung <= prev || rung > 10000 {
			return fmt.Errorf("%w: rungs must increase from zero through at most 10000 basis points", registry.ErrInvalid)
		}
		prev = rung
	}
	if _, err := target.Compile(p.Target); err != nil {
		return fmt.Errorf("%w: invalid plan targeting: %v", registry.ErrInvalid, err)
	}
	return nil
}

func (p Plan) Digest() (string, error) {
	data, err := encode(p)
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

// Key is a purpose-scoped verification key from trusted deployment configuration.
type Key struct {
	ID        string
	PublicKey *ecdsa.PublicKey
	Principal string
}

// Trust deliberately separates ordinary execution, approval, incident response,
// freshness and recovery authority. Principal is authenticated by the integration
// that grants access to the signing key, not supplied as a command field.
type Trust struct {
	Deciders, Approvers, Responders, Renewers, Recoverers, Proposers []Key
	MaxLease                                                         time.Duration
}

// Provenance is verified by the protected executor, not accepted from a request.
type Provenance struct {
	Repository   string `json:"repository"`
	RepositoryID int64  `json:"repository_id"`
	Run          int64  `json:"run_id"`
	Commit       string `json:"commit"`
	Initiator    int64  `json:"initiator_id"`
	Reviewer     int64  `json:"reviewer_id"`
}

func independentReview(approval, other *Provenance) bool {
	if approval == nil || other == nil {
		return approval == nil && other == nil // Loopback fixtures have no provider.
	}
	return approval.Reviewer != other.Initiator && approval.Reviewer != other.Reviewer
}

// Identity holds the credential used to sign one operation.
type Identity struct {
	ID         string
	Sign       registry.Signer
	Provenance *Provenance
}

// Command is a state transition with an optimistic constraint. Expected is the
// full exact predecessor digest, or empty only when the head is absent.
type Command struct {
	ID         string   `json:"id"`
	Action     string   `json:"action"`
	Expected   string   `json:"expected,omitempty"`
	PlanID     string   `json:"plan_id,omitempty"`
	ApprovalID string   `json:"approval_id,omitempty"`
	Reason     string   `json:"reason"`
	Incident   string   `json:"incident,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Rung       uint16   `json:"rung,omitempty"`
	Digest     string   `json:"digest,omitempty"`
}

// Retired records when a previously selectable release left a route.
type Retired struct {
	Release Ref       `json:"release"`
	At      time.Time `json:"at"`
}

// State is a whole routing and deny snapshot. Default is the route for an
// ordinary non-match. Scoped candidates are selected only in ramp/paused/finished.
type State struct {
	Plan       Plan      `json:"plan"`
	PlanID     string    `json:"plan_id"`
	ApprovalID string    `json:"approval_id"`
	Phase      string    `json:"phase"`
	Rung       uint16    `json:"rung"`
	Default    Ref       `json:"default"`
	Denied     []string  `json:"denied"`
	Retired    []Retired `json:"retired,omitempty"`
}

func (s State) Quarantined(sum string) bool {
	for _, deny := range s.Denied {
		if deny == sum {
			return true
		}
	}
	return false
}

// KeepsCandidate reports whether this phase retains the scoped candidate,
// including at zero exposure. Quarantine and selectability are separate.
func (s State) KeepsCandidate() bool {
	switch s.Phase {
	case "warming", "ramping", "paused", "finished":
		return true
	default:
		return false
	}
}

// Selectable reports whether a route can issue a receipt for the reference.
func (s State) Selectable(ref Ref) bool {
	if ref == (Ref{}) || s.Quarantined(ref.Digest) {
		return false
	}
	if ref == s.Default {
		return true
	}
	return ref == s.Plan.Candidate && s.Rung > 0 && (s.Phase == "ramping" || s.Phase == "paused" || s.Phase == "finished")
}

// Decision is immutable and signed. ID is the digest of its stored envelope and
// is deliberately excluded from the payload.
type Decision struct {
	Scope          Scope       `json:"scope"`
	Generation     uint64      `json:"generation"`
	Previous       string      `json:"previous,omitempty"`
	ID             string      `json:"-"`
	AlreadyApplied bool        `json:"-"`
	Command        Command     `json:"command"`
	Actor          string      `json:"actor"`
	Provenance     *Provenance `json:"provenance,omitempty"`
	At             time.Time   `json:"at"`
	State          State       `json:"state"`
}

// Observation carries verified restrictions even if no live lease was present.
type Observation struct {
	Decision  Decision
	ProofAt   time.Time
	ExpiresAt time.Time
}

type head struct {
	Version    int    `json:"schema_version"`
	Scope      Scope  `json:"scope"`
	Generation uint64 `json:"generation"`
	Decision   string `json:"decision"`
}

type proposal struct {
	Scope      Scope       `json:"scope"`
	Plan       string      `json:"plan_id"`
	Actor      string      `json:"actor"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

type approval struct {
	Scope      Scope       `json:"scope"`
	Action     string      `json:"action"`
	Plan       string      `json:"plan_id,omitempty"`
	Expected   string      `json:"expected,omitempty"`
	Digest     string      `json:"digest,omitempty"`
	Actor      string      `json:"actor"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

type proof struct {
	Scope      Scope     `json:"scope"`
	Generation uint64    `json:"generation"`
	Decision   string    `json:"decision"`
	Observed   time.Time `json:"observed"`
	Expires    time.Time `json:"expires"`
}

type wireSignature struct {
	Key       string `json:"keyid"`
	Signature []byte `json:"sig"`
}

type envelope struct {
	Type       string          `json:"payloadType"`
	Payload    []byte          `json:"payload"`
	Signatures []wireSignature `json:"signatures"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func encode(value any) ([]byte, error) {
	data, err := sonic.ConfigStd.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode registry protocol: %w", err)
	}
	if len(data) > registry.MaxRecordBytes {
		return nil, fmt.Errorf("%w: registry protocol record too large", registry.ErrInvalid)
	}
	return data, nil
}

func decode(data []byte, out any) error {
	if len(data) > registry.MaxRecordBytes || sonic.ConfigStd.Unmarshal(data, out) != nil {
		return registry.ErrCorrupt
	}
	canonical, err := encode(out)
	if err != nil || !bytes.Equal(data, canonical) {
		return registry.ErrCorrupt
	}
	return nil
}

func keyByID(keys []Key, id string) (Key, bool) {
	var found Key
	for _, key := range keys {
		if key.ID != id {
			continue
		}
		if found.PublicKey != nil || key.PublicKey == nil || key.PublicKey.Curve != elliptic.P256() ||
			!text(id, 256) || !text(key.Principal, 256) {
			return Key{}, false
		}
		found = key
	}
	return found, found.PublicKey != nil
}

func payloadType(kind string) string {
	return "application/vnd.go-plg-s3-registry." + kind + ".v1+json"
}

func texts(list []string, max int) bool {
	if len(list) > max {
		return false
	}
	for _, value := range list {
		if !text(value, 2048) {
			return false
		}
	}
	return true
}

func text(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && strings.TrimSpace(value) != "" && strings.IndexFunc(value, unicode.IsControl) < 0
}
