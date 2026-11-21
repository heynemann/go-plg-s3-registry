package registry

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/bytedance/sonic"
)

const releaseType = "application/vnd.go-plg-s3-registry.release.v1+json"

// Store is the object boundary. Create may never overwrite a present key.
type Store interface {
	Create(ctx context.Context, key string, data []byte) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string, yield func(string) error) error
}

type indexStore interface {
	Store
	Read(context.Context, string) (io.ReadCloser, string, error)
	CompareAndSwap(context.Context, string, string, []byte) error
}

// Signer signs a SHA-256 digest with P-256 and returns an ASN.1 signature.
type Signer func(context.Context, [sha256.Size]byte) ([]byte, error)

// Registry manages publication records only; none of its operations has access
// to a serving head or has any effect on activation.
type Registry struct {
	store indexStore
	id    string
}

func New(store Store, id string) (Registry, error) {
	if !idPattern.MatchString(id) {
		return Registry{}, fmt.Errorf("%w: registry ID must be a lowercase slug", ErrInvalid)
	}
	objects, ok := store.(indexStore)
	if !ok {
		return Registry{}, fmt.Errorf("%w: registry storage must support exact-key conditional writes", ErrInvalid)
	}
	return Registry{store: objects, id: id}, nil
}

func (r Registry) pluginKey(plugin string) string { return "v1/" + r.id + "/plugins/" + plugin }

func (r Registry) artifactKey(sum string) string { return "v1/" + r.id + "/artifacts/" + sum + ".plg" }

type signature struct {
	KeyID string `json:"keyid"`
	Bytes []byte `json:"sig"`
}

type envelope struct {
	Type       string      `json:"payloadType"`
	Payload    []byte      `json:"payload"`
	Signatures []signature `json:"signatures"`
}

func paeDigest(payload []byte) [sha256.Size]byte {
	h := sha256.New()
	io.WriteString(h, "DSSEv1 "+strconv.Itoa(len(releaseType))+" "+releaseType+" "+strconv.Itoa(len(payload))+" ")
	h.Write(payload)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

func (r Registry) Publish(
	ctx context.Context, plugin, version, commit, keyID string, data []byte, sign Signer,
) (Release, error) {
	if !versionPattern.MatchString(version) || sign == nil {
		return Release{}, fmt.Errorf("%w: expected a release version and signing key", ErrInvalid)
	}
	index, etag, err := r.readIndex(ctx, plugin)
	if err != nil {
		return Release{}, err
	}
	registration, err := r.publisher(ctx, index)
	if err != nil {
		return Release{}, err
	}
	if registration.Suspended || registration.Publisher.KeyID != keyID {
		return Release{}, ErrDenied
	}
	release, _, err := parseArtifact(data, commit, version)
	if err != nil {
		return Release{}, err
	}
	release.Schema, release.Registry = recordVersion, r.id
	release.Plugin, release.Version = plugin, version
	release.ArtifactDigest, release.ArtifactBytes = digest(data), int64(len(data))
	release.SourceCommit, release.RegistrationDigest = commit, index.RegistrationDigest
	release.Owner, release.Repository, release.Workflow = registration.Owner, registration.Publisher.Repository, registration.Publisher.Workflow
	release.OnCall, release.Runbook = registration.OnCall, registration.Runbook
	payload, err := sonic.ConfigStd.Marshal(release)
	if err != nil {
		return Release{}, err
	}
	sum := paeDigest(payload)
	sig, err := sign(ctx, sum)
	if err != nil {
		return Release{}, fmt.Errorf("sign release: %w", err)
	}
	if !ecdsa.VerifyASN1(registration.key, sum[:], sig) {
		return Release{}, ErrDenied
	}

	if existing, ok := index.Releases[version]; ok {
		return r.identicalPublication(ctx, release, existing)
	}
	signed, err := sonic.ConfigStd.Marshal(envelope{releaseType, payload, []signature{{keyID, sig}}})
	if err != nil {
		return Release{}, err
	}
	entry := admission{
		EnvelopeDigest:     digest(signed),
		ArtifactDigest:     release.ArtifactDigest,
		RegistrationDigest: release.RegistrationDigest,
		PublisherKeyDigest: digest(registration.Publisher.PublicKey),
	}
	index.Releases[version] = entry
	next, err := encodeIndex(index)
	if err != nil {
		return Release{}, err
	}
	if err := r.stageRelease(ctx, plugin, entry, signed, data); err != nil {
		return Release{}, err
	}
	if err := r.saveIndex(ctx, plugin, etag, next); err != nil {
		// An ambiguous response or a concurrent identical publish may have committed.
		latest, _, readErr := r.readIndex(ctx, plugin)
		if readErr == nil {
			if existing, ok := latest.Releases[version]; ok {
				return r.identicalPublication(ctx, release, existing)
			}
			if latest.RegistrationDigest != release.RegistrationDigest {
				return Release{}, ErrDenied
			}
		}
		return Release{}, err
	}
	return release, nil
}

func (r Registry) identicalPublication(ctx context.Context, candidate Release, existing admission) (Release, error) {
	if existing.ArtifactDigest != candidate.ArtifactDigest {
		return Release{}, ErrConflict
	}
	verified, err := r.readAdmission(ctx, candidate.Plugin, candidate.Version, existing)
	if err != nil {
		return Release{}, err
	}
	if verified.release.SourceCommit != candidate.SourceCommit {
		return Release{}, ErrConflict
	}
	if err := r.verifyArtifact(ctx, existing.ArtifactDigest, verified.release.ArtifactBytes); err != nil {
		return Release{}, err
	}
	return verified.release, nil
}

func verifyRelease(data []byte, registration verifiedRegistration, policyDigest, version string) (Release, error) {
	var signed envelope
	if decodeRecord(data, &signed) != nil || signed.Type != releaseType || len(signed.Signatures) != 1 ||
		signed.Signatures[0].KeyID != registration.Publisher.KeyID {
		return Release{}, ErrCorrupt
	}
	sum := paeDigest(signed.Payload)
	if !ecdsa.VerifyASN1(registration.key, sum[:], signed.Signatures[0].Bytes) {
		return Release{}, ErrCorrupt
	}
	var release Release
	if decodeRecord(signed.Payload, &release) != nil || release.Schema != recordVersion ||
		release.Registry != registration.Registry || release.Plugin != registration.Plugin || release.Version != version ||
		release.Owner != registration.Owner || release.Repository != registration.Publisher.Repository ||
		release.Workflow != registration.Publisher.Workflow || release.RegistrationDigest != policyDigest ||
		!validDigest(release.ArtifactDigest) || release.ArtifactBytes <= 0 || release.ArtifactBytes > MaxArtifactBytes ||
		!commitPattern.MatchString(release.SourceCommit) || release.Contract.Interface == "" ||
		release.Contract.Module == "" || release.Contract.ModuleVersion == "" || release.Evidence.Packer == "" ||
		!validDigest(release.Evidence.ValidationDigest) || release.Evidence.PassedTests <= 0 {
		return Release{}, ErrCorrupt
	}
	release.OnCall, release.Runbook = registration.OnCall, registration.Runbook
	return release, nil
}

// Inspect verifies admitted publication metadata without changing state.
func (r Registry) Inspect(ctx context.Context, plugin, version, sum string) ([]Release, error) {
	if (version == "" && !validDigest(sum)) || (version != "" && (sum != "" || !versionPattern.MatchString(version))) {
		return nil, fmt.Errorf("%w: give exactly one release version or sha256 digest", ErrInvalid)
	}
	index, _, err := r.readIndex(ctx, plugin)
	if err != nil {
		return nil, err
	}
	if version != "" {
		entry, ok := index.Releases[version]
		if !ok {
			return nil, ErrNotFound
		}
		verified, err := r.readAdmission(ctx, plugin, version, entry)
		if err != nil {
			return nil, err
		}
		return []Release{verified.release}, nil
	}
	var releases []Release
	for name, entry := range index.Releases {
		if entry.ArtifactDigest != sum {
			continue
		}
		verified, err := r.readAdmission(ctx, plugin, name, entry)
		if err != nil {
			return nil, err
		}
		releases = append(releases, verified.release)
	}
	if len(releases) == 0 {
		return nil, ErrNotFound
	}
	slices.SortFunc(releases, func(a, b Release) int { return cmp.Compare(a.Version, b.Version) })
	return releases, nil
}

func (r Registry) record(ctx context.Context, key string) ([]byte, error) {
	body, err := r.store.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	return readRecord(body)
}

func readRecord(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, MaxRecordBytes+1))
	if err == nil && len(data) > MaxRecordBytes {
		return nil, ErrCorrupt
	}
	return data, err
}

func (r Registry) createRecord(ctx context.Context, key string, data []byte) error {
	if len(data) > MaxRecordBytes {
		return fmt.Errorf("%w: record exceeds size limit", ErrInvalid)
	}
	err := r.store.Create(ctx, key, data)
	if !errors.Is(err, ErrConflict) {
		return err
	}
	existing, err := r.record(ctx, key)
	if err != nil {
		return requiredObject(err)
	}
	if !bytes.Equal(existing, data) {
		return ErrCorrupt
	}
	return nil
}

func requiredObject(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrCorrupt
	}
	return err
}

func (r Registry) createArtifact(ctx context.Context, sum string, data []byte) error {
	key := r.artifactKey(sum)
	err := r.store.Create(ctx, key, data)
	if !errors.Is(err, ErrConflict) {
		return err
	}
	return r.verifyArtifact(ctx, sum, int64(len(data)))
}

func (r Registry) verifyArtifact(ctx context.Context, sum string, size int64) error {
	body, err := r.store.Open(ctx, r.artifactKey(sum))
	if err != nil {
		return requiredObject(err)
	}
	defer body.Close()
	h := sha256.New()
	length, err := io.Copy(h, io.LimitReader(body, size+1))
	if err != nil {
		return err
	}
	var sumBytes [sha256.Size]byte
	if length != size || "sha256:"+hex.EncodeToString(h.Sum(sumBytes[:0])) != sum {
		return ErrCorrupt
	}
	return nil
}
