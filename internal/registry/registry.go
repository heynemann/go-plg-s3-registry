package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
)

const releaseType = "application/vnd.go-plg-s3-registry.release.v1+json"

// Store is the object boundary. Create may never overwrite a present key.
type Store interface {
	Create(ctx context.Context, key string, data []byte) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string, yield func(string) error) error
}

// Signer signs a SHA-256 digest with P-256 and returns an ASN.1 signature.
type Signer func(context.Context, [sha256.Size]byte) ([]byte, error)

// Registry manages publication records only; none of its operations has access
// to a serving head or has any effect on activation.
type Registry struct {
	store Store
	id    string
}

func New(store Store, id string) (Registry, error) {
	if !idPattern.MatchString(id) {
		return Registry{}, fmt.Errorf("%w: registry ID must be a lowercase slug", ErrInvalid)
	}
	return Registry{store: store, id: id}, nil
}

func (r Registry) pluginKey(plugin string) string { return "v1/" + r.id + "/plugins/" + plugin }

func (r Registry) artifactKey(sum string) string { return "v1/" + r.id + "/artifacts/" + sum + ".plg" }

func (r Registry) Onboard(ctx context.Context, registration Registration) (Registration, error) {
	registration.Schema, registration.Registry = recordVersion, r.id
	if err := registration.check(); err != nil {
		return Registration{}, err
	}
	data, err := sonic.ConfigStd.Marshal(registration)
	if err != nil {
		return Registration{}, err
	}
	key := r.pluginKey(registration.Plugin) + "/registration.json"
	if err = r.store.Create(ctx, key, data); errors.Is(err, ErrConflict) {
		existing, readErr := r.record(ctx, key)
		if readErr != nil {
			return Registration{}, readErr
		}
		if bytes.Equal(data, existing) {
			return registration, nil
		}
	}
	return registration, err
}

func (r Registry) registration(ctx context.Context, plugin string) (Registration, string, error) {
	if !idPattern.MatchString(plugin) {
		return Registration{}, "", fmt.Errorf("%w: plugin ID must be a lowercase slug", ErrInvalid)
	}
	data, err := r.record(ctx, r.pluginKey(plugin)+"/registration.json")
	if err != nil {
		return Registration{}, "", err
	}
	var record Registration
	if decodeRecord(data, &record) != nil || record.Schema != recordVersion || record.Registry != r.id ||
		record.Plugin != plugin || record.check() != nil {
		return Registration{}, "", ErrCorrupt
	}
	return record, digest(data), nil
}

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
	registration, policyDigest, err := r.registration(ctx, plugin)
	if err != nil {
		return Release{}, err
	}
	if registration.Publisher.KeyID != keyID {
		return Release{}, ErrDenied
	}
	release, err := fromArtifact(data, commit, version)
	if err != nil {
		return Release{}, err
	}
	release.Schema, release.Registry = recordVersion, r.id
	release.Plugin, release.Version = plugin, version
	release.RegistrationDigest = policyDigest
	release.Owner, release.Repository, release.Workflow = registration.Owner, registration.Publisher.Repository, registration.Publisher.Workflow
	payload, err := sonic.ConfigStd.Marshal(release)
	if err != nil {
		return Release{}, err
	}
	sum := paeDigest(payload)
	sig, err := sign(ctx, sum)
	if err != nil {
		return Release{}, fmt.Errorf("sign release: %w", err)
	}
	key, err := registration.Publisher.key()
	if err != nil || !ecdsa.VerifyASN1(key, sum[:], sig) {
		return Release{}, ErrDenied
	}

	releaseKey := r.pluginKey(plugin) + "/releases/" + version + ".json"
	// Check existing immutable bindings before uploading an artifact for an
	// already-taken version. The conditional write below handles races.
	existing, err := r.record(ctx, releaseKey)
	if err == nil {
		existingRelease, err := sameRelease(existing, payload, registration, policyDigest, version)
		if err != nil {
			return Release{}, err
		}
		return existingRelease, r.verifyArtifact(ctx, release.ArtifactDigest, release.ArtifactBytes)
	}
	if !errors.Is(err, ErrNotFound) {
		return Release{}, err
	}
	if err = r.createArtifact(ctx, release.ArtifactDigest, data); err != nil {
		return Release{}, err
	}
	signed, err := sonic.ConfigStd.Marshal(envelope{releaseType, payload, []signature{{keyID, sig}}})
	if err != nil {
		return Release{}, err
	}
	if err = r.store.Create(ctx, releaseKey, signed); errors.Is(err, ErrConflict) {
		existing, err = r.record(ctx, releaseKey)
		if err != nil {
			return Release{}, err
		}
		return sameRelease(existing, payload, registration, policyDigest, version)
	}
	return release, err
}

func sameRelease(data, payload []byte, registration Registration, policyDigest, version string) (Release, error) {
	release, existing, err := verifyRelease(data, registration, policyDigest, version)
	if err != nil {
		return Release{}, err
	}
	if !bytes.Equal(existing, payload) {
		return Release{}, ErrConflict
	}
	return release, nil
}

func verifyRelease(data []byte, registration Registration, policyDigest, version string) (Release, []byte, error) {
	var signed envelope
	if decodeRecord(data, &signed) != nil || signed.Type != releaseType || len(signed.Signatures) != 1 ||
		signed.Signatures[0].KeyID != registration.Publisher.KeyID {
		return Release{}, nil, ErrCorrupt
	}
	key, err := registration.Publisher.key()
	sum := paeDigest(signed.Payload)
	if err != nil || !ecdsa.VerifyASN1(key, sum[:], signed.Signatures[0].Bytes) {
		return Release{}, nil, ErrCorrupt
	}
	var release Release
	if decodeRecord(signed.Payload, &release) != nil || release.Schema != recordVersion ||
		release.Registry != registration.Registry || release.Plugin != registration.Plugin || release.Version != version ||
		release.Owner != registration.Owner || release.Repository != registration.Publisher.Repository ||
		release.Workflow != registration.Publisher.Workflow || release.RegistrationDigest != policyDigest ||
		!validDigest(release.ArtifactDigest) || release.ArtifactBytes <= 0 || release.ArtifactBytes > MaxArtifactBytes {
		return Release{}, nil, ErrCorrupt
	}
	return release, signed.Payload, nil
}

// Inspect verifies publication metadata without changing state. Digest lookup
// is an inventory query, not an authoritative selection mechanism.
func (r Registry) Inspect(ctx context.Context, plugin, version, sum string) ([]Release, error) {
	if (version == "" && !validDigest(sum)) || (version != "" && (sum != "" || !versionPattern.MatchString(version))) {
		return nil, fmt.Errorf("%w: give exactly one release version or sha256 digest", ErrInvalid)
	}
	registration, policyDigest, err := r.registration(ctx, plugin)
	if err != nil {
		return nil, err
	}
	prefix := r.pluginKey(plugin) + "/releases/"
	var releases []Release
	read := func(key string) error {
		name, ok := strings.CutSuffix(strings.TrimPrefix(key, prefix), ".json")
		if !ok || !versionPattern.MatchString(name) {
			return ErrCorrupt
		}
		data, err := r.record(ctx, key)
		if err != nil {
			return err
		}
		release, _, err := verifyRelease(data, registration, policyDigest, name)
		if err != nil {
			return err
		}
		if sum == "" || release.ArtifactDigest == sum {
			releases = append(releases, release)
		}
		return nil
	}
	if version != "" {
		err = read(prefix + version + ".json")
	} else {
		err = r.store.List(ctx, prefix, read)
	}
	if err == nil && len(releases) == 0 {
		err = ErrNotFound
	}
	return releases, err
}

func (r Registry) record(ctx context.Context, key string) ([]byte, error) {
	body, err := r.store.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, MaxRecordBytes+1))
	if err == nil && len(data) > MaxRecordBytes {
		return nil, ErrCorrupt
	}
	return data, err
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
	if errors.Is(err, ErrNotFound) {
		return ErrCorrupt
	}
	if err != nil {
		return err
	}
	defer body.Close()
	h := sha256.New()
	length, err := io.Copy(h, io.LimitReader(body, size+1))
	if err != nil {
		return err
	}
	if length != size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != sum {
		return ErrCorrupt
	}
	return nil
}
