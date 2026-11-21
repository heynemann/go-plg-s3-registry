package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/heynemann/go-plg"
)

func (r Registry) releaseKey(plugin, sum string) string {
	return r.pluginKey(plugin) + "/releases/" + sum + ".json"
}

func (r Registry) stageRelease(ctx context.Context, plugin string, entry admission, signed, data []byte) error {
	if len(signed) > MaxRecordBytes {
		return fmt.Errorf("%w: signed release exceeds size limit", ErrInvalid)
	}
	if err := r.createArtifact(ctx, entry.ArtifactDigest, data); err != nil {
		return err
	}
	return r.createRecord(ctx, r.releaseKey(plugin, entry.EnvelopeDigest), signed)
}

type verifiedAdmission struct {
	release      Release
	signed       []byte
	registration []byte
}

func (r Registry) readAdmission(ctx context.Context, plugin, version string, entry admission) (verifiedAdmission, error) {
	signed, err := r.record(ctx, r.releaseKey(plugin, entry.EnvelopeDigest))
	if err != nil {
		return verifiedAdmission{}, requiredObject(err)
	}
	if digest(signed) != entry.EnvelopeDigest {
		return verifiedAdmission{}, ErrCorrupt
	}
	registration, err := r.readRegistration(ctx, plugin, entry.RegistrationDigest)
	if err != nil {
		return verifiedAdmission{}, err
	}
	if registration.Suspended || digest(registration.Publisher.PublicKey) != entry.PublisherKeyDigest {
		return verifiedAdmission{}, ErrCorrupt
	}
	release, err := verifyRelease(signed, registration, entry.RegistrationDigest, version)
	if err != nil || release.ArtifactDigest != entry.ArtifactDigest {
		return verifiedAdmission{}, ErrCorrupt
	}
	return verifiedAdmission{release, signed, registration.raw}, nil
}

func (r Registry) readArtifact(ctx context.Context, sum string, size int64) ([]byte, error) {
	body, err := r.store.Open(ctx, r.artifactKey(sum))
	if err != nil {
		return nil, requiredObject(err)
	}
	defer body.Close()
	// Size is bounded by the authenticated release; one extra byte detects a
	// longer object without trusting storage's declared content length.
	data := make([]byte, size+1)
	n, err := io.ReadFull(body, data)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if int64(n) != size || digest(data[:n]) != sum {
		return nil, ErrCorrupt
	}
	return data[:n], nil
}

func (r Registry) fetched(ctx context.Context, plugin, version, sum string) (admission, verifiedAdmission, []byte, *plg.Artifact, error) {
	if !versionPattern.MatchString(version) || !validDigest(sum) {
		return admission{}, verifiedAdmission{}, nil, nil, fmt.Errorf("%w: give an exact release version and sha256 digest", ErrInvalid)
	}
	index, _, err := r.readIndex(ctx, plugin)
	if err != nil {
		return admission{}, verifiedAdmission{}, nil, nil, err
	}
	entry, ok := index.Releases[version]
	if !ok || entry.ArtifactDigest != sum {
		return admission{}, verifiedAdmission{}, nil, nil, ErrNotFound
	}
	verified, err := r.readAdmission(ctx, plugin, version, entry)
	if err != nil {
		return admission{}, verifiedAdmission{}, nil, nil, err
	}
	release := verified.release
	data, err := r.readArtifact(ctx, sum, release.ArtifactBytes)
	if err != nil {
		return admission{}, verifiedAdmission{}, nil, nil, err
	}
	metadata, archive, err := parseArtifact(data, release.SourceCommit, version)
	if err != nil || metadata.Contract != release.Contract || metadata.Evidence != release.Evidence ||
		metadata.Capabilities.MemoryBytes != release.Capabilities.MemoryBytes ||
		!slices.Equal(metadata.Capabilities.Secrets, release.Capabilities.Secrets) {
		return admission{}, verifiedAdmission{}, nil, nil, ErrCorrupt
	}
	return entry, verified, data, archive, nil
}

// Fetch verifies an admitted version and digest, including its packed archive.
func (r Registry) Fetch(ctx context.Context, plugin, version, sum string) (Release, *plg.Artifact, error) {
	_, verified, _, archive, err := r.fetched(ctx, plugin, version, sum)
	return verified.release, archive, err
}

// Promote copies an exact verified publication into another bucket of the same registry.
// It admits that release without granting the source publisher any destination authority.
func (r Registry) Promote(ctx context.Context, destination Registry, plugin, version, sum string) (Release, error) {
	if r.id == "" || r.id != destination.id {
		return Release{}, fmt.Errorf("%w: promotion requires the same registry ID", ErrInvalid)
	}
	entry, verified, data, _, err := r.fetched(ctx, plugin, version, sum)
	if err != nil {
		return Release{}, err
	}
	index, etag, err := destination.readOrCreateIndex(ctx, plugin)
	if err != nil {
		return Release{}, err
	}
	if existing, ok := index.Releases[version]; ok {
		return destination.identicalPromotion(ctx, verified.release, entry, existing)
	}
	index.Releases[version] = entry
	next, err := encodeIndex(index)
	if err != nil {
		return Release{}, err
	}
	if err := destination.createRecord(ctx, destination.registrationKey(plugin, entry.RegistrationDigest), verified.registration); err != nil {
		return Release{}, err
	}
	if err := destination.stageRelease(ctx, plugin, entry, verified.signed, data); err != nil {
		return Release{}, err
	}
	if err := destination.saveIndex(ctx, plugin, etag, next); err != nil {
		latest, _, readErr := destination.readIndex(ctx, plugin)
		if readErr == nil {
			if existing, ok := latest.Releases[version]; ok {
				return destination.identicalPromotion(ctx, verified.release, entry, existing)
			}
		}
		return Release{}, err
	}
	return verified.release, nil
}

func (r Registry) identicalPromotion(ctx context.Context, release Release, verified, existing admission) (Release, error) {
	if existing != verified {
		return Release{}, ErrConflict
	}
	// The source was already checked against its archive. On the destination,
	// checking the identical content identities is enough without unpacking twice.
	if _, err := r.readAdmission(ctx, release.Plugin, release.Version, existing); err != nil {
		return Release{}, err
	}
	if err := r.verifyArtifact(ctx, release.ArtifactDigest, release.ArtifactBytes); err != nil {
		return Release{}, err
	}
	return release, nil
}
