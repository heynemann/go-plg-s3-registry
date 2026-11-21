package registry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/heynemann/go-plg"
)

const (
	MaxArtifactBytes = 64 << 20
	MaxRecordBytes   = 1 << 20
	recordVersion    = 1
)

var (
	ErrInvalid  = errors.New("invalid registry input")
	ErrDenied   = errors.New("publisher not authorized")
	ErrConflict = errors.New("immutable binding or expected publisher revision conflict")
	ErrNotFound = errors.New("registry record not found")
	ErrCorrupt  = errors.New("registry record failed verification")

	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)
	commitPattern  = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	keyPattern     = regexp.MustCompile(`^(?:local:[a-z0-9][a-z0-9-]{0,62}|arn:aws[a-z0-9-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+)$`)
)

// Publisher binds a workflow to a purpose-scoped P-256 signing key. The key ID
// is an exact KMS key ARN in AWS, never an alias or a caller-declared identity.
type Publisher struct {
	Repository string `json:"repository"`
	Workflow   string `json:"workflow"`
	KeyID      string `json:"key_id"`
	PublicKey  []byte `json:"public_key_pkix"`
}

// Registration records authority established by a registry administrator.
type Registration struct {
	Schema    int       `json:"schema_version"`
	Registry  string    `json:"registry"`
	Plugin    string    `json:"plugin"`
	Revision  uint64    `json:"revision"`
	Suspended bool      `json:"suspended"`
	Owner     string    `json:"owner"`
	OnCall    string    `json:"on_call"`
	Runbook   string    `json:"runbook"`
	Publisher Publisher `json:"publisher"`
}

// Release is the typed, signed payload. Ownership comes from the registration,
// not the artifact's manifest. The report digest binds pack's embedded report.
type Release struct {
	Schema             int      `json:"schema_version"`
	Registry           string   `json:"registry"`
	Plugin             string   `json:"plugin"`
	Version            string   `json:"version"`
	ArtifactDigest     string   `json:"artifact_digest"`
	ArtifactBytes      int64    `json:"artifact_bytes"`
	RegistrationDigest string   `json:"registration_digest"`
	Owner              string   `json:"owner"`
	Repository         string   `json:"repository"`
	Workflow           string   `json:"workflow"`
	SourceCommit       string   `json:"source_commit"`
	Contract           Contract `json:"contract"`
	Capabilities       Requests `json:"requested_capabilities"`
	Evidence           Evidence `json:"evidence"`
	OnCall             string   `json:"-"`
	Runbook            string   `json:"-"`
}

type Contract struct {
	Interface     string `json:"interface"`
	Module        string `json:"module"`
	ModuleVersion string `json:"module_version"`
}

// Requests captures declared go-plg capabilities; it grants none. HTTP/host
// function grants come exclusively from the host and are not in plugin.yaml.
type Requests struct {
	Secrets     []string `json:"secrets"`
	MemoryBytes uint64   `json:"memory_bytes,omitempty"`
}

type Evidence struct {
	Packer           string `json:"packer"`
	ValidationDigest string `json:"validation_report_digest"`
	PassedTests      int    `json:"passed_author_tests"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	end, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(end) != 64 {
		return false
	}
	for _, c := range end {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (p Publisher) key() (*ecdsa.PublicKey, error) {
	if !keyPattern.MatchString(p.KeyID) || !repoPattern.MatchString(p.Repository) || !validWorkflow(p) {
		return nil, fmt.Errorf("%w: expected repository, workflow path and exact signing key ID", ErrInvalid)
	}
	key, err := x509.ParsePKIXPublicKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: expected a PKIX public key", ErrInvalid)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: expected a P-256 signing key", ErrInvalid)
	}
	return pub, nil
}

func validWorkflow(p Publisher) bool {
	path, rev, ok := strings.Cut(p.Workflow, "@")
	repo, file, relative := strings.Cut(path, "/.github/workflows/")
	return ok && relative && repoPattern.MatchString(repo) && len(file) <= 120 && versionPattern.MatchString(file) &&
		(strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml")) && commitPattern.MatchString(rev)
}

func (r Registration) check() (*ecdsa.PublicKey, error) {
	u, err := url.Parse(r.Runbook)
	if r.Revision == 0 || !idPattern.MatchString(r.Plugin) || !idPattern.MatchString(r.Owner) || !idPattern.MatchString(r.OnCall) ||
		err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(r.Runbook) > 2048 {
		return nil, fmt.Errorf("%w: expected plugin, owner, on-call IDs and an HTTPS runbook", ErrInvalid)
	}
	return r.Publisher.key()
}

// decodeRecord requires exactly the wire form emitted by v1. This refuses
// duplicate or unknown fields, trailing data, and alternate representations.
func decodeRecord[T any](data []byte, dest *T) error {
	if len(data) > MaxRecordBytes || sonic.ConfigStd.Unmarshal(data, dest) != nil {
		return ErrCorrupt
	}
	canonical, err := sonic.ConfigStd.Marshal(dest)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrCorrupt
	}
	return nil
}

func parseArtifact(data []byte, sourceCommit, version string) (Release, *plg.Artifact, error) {
	if len(data) == 0 || len(data) > MaxArtifactBytes || !commitPattern.MatchString(sourceCommit) {
		return Release{}, nil, fmt.Errorf("%w: expected a bounded .plg archive and a full source commit", ErrInvalid)
	}
	archive, err := plg.OpenArtifact(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Release{}, nil, fmt.Errorf("%w: invalid .plg archive; rebuild with plg pack", ErrInvalid)
	}
	manifest, err := archive.ReadFile("plugin.yaml")
	if err != nil {
		return Release{}, nil, fmt.Errorf("%w: missing plugin.yaml", ErrInvalid)
	}
	desc, err := plg.ParseManifest(manifest)
	if err != nil || (desc.Version != "" && desc.Version != version) {
		return Release{}, nil, fmt.Errorf("%w: plugin.yaml is invalid or its version disagrees with the release", ErrInvalid)
	}
	provenance := archive.Provenance()
	if provenance.Commit != sourceCommit || provenance.Dirty || provenance.Contract.Path == "" ||
		provenance.Contract.Version == "" || provenance.PlgVersion == "" {
		return Release{}, nil, fmt.Errorf("%w: pack a clean checkout of the stated source commit against a pinned contract", ErrInvalid)
	}
	tests, err := passedTests(provenance.Report)
	if err != nil {
		return Release{}, nil, err
	}
	return Release{
		Contract:     Contract{desc.Implements, provenance.Contract.Path, provenance.Contract.Version},
		Capabilities: Requests{Secrets: desc.Secrets, MemoryBytes: desc.MemoryLimit},
		Evidence:     Evidence{provenance.PlgVersion, digest(provenance.Report), tests},
	}, archive, nil
}

func passedTests(data []byte) (int, error) {
	var report struct {
		Version int  `json:"version"`
		Valid   bool `json:"valid"`
		Plugins []struct {
			Valid bool `json:"valid"`
			Steps []struct {
				Step   string `json:"step"`
				Result string `json:"result"`
			} `json:"steps"`
		} `json:"plugins"`
	}
	invalid := fmt.Errorf("%w: plg pack must record a passing validation and at least one passing author test", ErrInvalid)
	if err := sonic.ConfigStd.Unmarshal(data, &report); err != nil || report.Version != 1 || !report.Valid ||
		len(report.Plugins) != 1 || !report.Plugins[0].Valid {
		return 0, invalid
	}
	count := 0
	for _, step := range report.Plugins[0].Steps {
		if step.Result == "failed" {
			return 0, invalid
		}
		if step.Step == "test" && step.Result == "ok" {
			count++
		}
	}
	if count == 0 {
		return 0, invalid
	}
	return count, nil
}
