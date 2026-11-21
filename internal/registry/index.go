package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"

	"github.com/bytedance/sonic"
)

// The publication index is the commit point for this plugin. Only protected
// publishing, administration and promotion executors may write it. Author
// credentials cannot write the index or its archived registration records.
type publicationIndex struct {
	Schema             int                  `json:"schema_version"`
	Registry           string               `json:"registry"`
	Plugin             string               `json:"plugin"`
	RegistrationDigest string               `json:"registration_digest,omitempty"`
	Releases           map[string]admission `json:"releases"`
}

type admission struct {
	EnvelopeDigest     string `json:"envelope_digest"`
	ArtifactDigest     string `json:"artifact_digest"`
	RegistrationDigest string `json:"registration_digest"`
	PublisherKeyDigest string `json:"publisher_key_digest"`
}

func (r Registry) indexKey(plugin string) string { return r.pluginKey(plugin) + "/index.json" }

func (r Registry) readIndex(ctx context.Context, plugin string) (publicationIndex, string, error) {
	if !idPattern.MatchString(plugin) {
		return publicationIndex{}, "", fmt.Errorf("%w: plugin ID must be a lowercase slug", ErrInvalid)
	}
	body, etag, err := r.store.Read(ctx, r.indexKey(plugin))
	if err != nil {
		return publicationIndex{}, "", err
	}
	data, err := readRecord(body)
	if err != nil {
		return publicationIndex{}, "", err
	}
	var index publicationIndex
	if etag == "" || decodeRecord(data, &index) != nil || index.Schema != recordVersion ||
		index.Registry != r.id || index.Plugin != plugin || index.Releases == nil ||
		(index.RegistrationDigest == "" && len(index.Releases) == 0) ||
		(index.RegistrationDigest != "" && !validDigest(index.RegistrationDigest)) {
		return publicationIndex{}, "", ErrCorrupt
	}
	for version, entry := range index.Releases {
		if !versionPattern.MatchString(version) || !validDigest(entry.EnvelopeDigest) || !validDigest(entry.ArtifactDigest) ||
			!validDigest(entry.RegistrationDigest) || !validDigest(entry.PublisherKeyDigest) {
			return publicationIndex{}, "", ErrCorrupt
		}
	}
	return index, etag, nil
}

func (r Registry) readOrCreateIndex(ctx context.Context, plugin string) (publicationIndex, string, error) {
	index, etag, err := r.readIndex(ctx, plugin)
	if !errors.Is(err, ErrNotFound) {
		return index, etag, err
	}
	return publicationIndex{
		Schema: recordVersion, Registry: r.id, Plugin: plugin, Releases: make(map[string]admission),
	}, "", nil
}

func encodeIndex(index publicationIndex) ([]byte, error) {
	data, err := sonic.ConfigStd.Marshal(index)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: plugin publication index exceeds size limit", ErrInvalid)
	}
	return data, nil
}

func (r Registry) saveIndex(ctx context.Context, plugin, etag string, data []byte) error {
	return r.store.CompareAndSwap(ctx, r.indexKey(plugin), etag, data)
}

func (r Registry) registrationKey(plugin, sum string) string {
	return r.pluginKey(plugin) + "/registrations/" + sum + ".json"
}

type verifiedRegistration struct {
	Registration
	key *ecdsa.PublicKey
	raw []byte
}

func (r Registry) readRegistration(ctx context.Context, plugin, sum string) (verifiedRegistration, error) {
	data, err := r.record(ctx, r.registrationKey(plugin, sum))
	if err != nil {
		return verifiedRegistration{}, requiredObject(err)
	}
	var record Registration
	if digest(data) != sum || decodeRecord(data, &record) != nil || record.Schema != recordVersion ||
		record.Registry != r.id || record.Plugin != plugin {
		return verifiedRegistration{}, ErrCorrupt
	}
	key, err := record.check()
	if err != nil {
		return verifiedRegistration{}, ErrCorrupt
	}
	return verifiedRegistration{record, key, data}, nil
}

func (r Registry) publisher(ctx context.Context, index publicationIndex) (verifiedRegistration, error) {
	if index.RegistrationDigest == "" {
		return verifiedRegistration{}, ErrNotFound
	}
	return r.readRegistration(ctx, index.Plugin, index.RegistrationDigest)
}

func (r Registry) saveRegistration(ctx context.Context, index *publicationIndex, etag string, raw []byte, sum string) error {
	index.RegistrationDigest = sum
	next, err := encodeIndex(*index)
	if err != nil {
		return err
	}
	if err := r.createRecord(ctx, r.registrationKey(index.Plugin, sum), raw); err != nil {
		return err
	}
	if err := r.saveIndex(ctx, index.Plugin, etag, next); err != nil {
		latest, _, readErr := r.readIndex(ctx, index.Plugin)
		if readErr == nil && latest.RegistrationDigest == sum {
			*index = latest
			return nil
		}
		return err
	}
	return nil
}

// Onboard reserves a plugin's local publisher authority once. A promoted
// release does not reserve it, and an onboard retry cannot roll back rotation.
func (r Registry) Onboard(ctx context.Context, registration Registration) (Registration, error) {
	registration.Schema, registration.Registry, registration.Revision, registration.Suspended = recordVersion, r.id, 1, false
	if _, err := registration.check(); err != nil {
		return Registration{}, err
	}
	raw, err := sonic.ConfigStd.Marshal(registration)
	if err != nil {
		return Registration{}, err
	}
	sum := digest(raw)
	index, etag, err := r.readOrCreateIndex(ctx, registration.Plugin)
	if err != nil {
		return Registration{}, err
	}
	if index.RegistrationDigest != "" {
		if index.RegistrationDigest != sum {
			return Registration{}, ErrConflict
		}
		current, err := r.publisher(ctx, index)
		return current.Registration, err
	}
	if err := r.saveRegistration(ctx, &index, etag, raw, sum); err != nil {
		return Registration{}, err
	}
	return registration, nil
}

// PublisherStatus reports the current local publisher binding and its digest.
func (r Registry) PublisherStatus(ctx context.Context, plugin string) (Registration, string, error) {
	index, _, err := r.readIndex(ctx, plugin)
	if err != nil {
		return Registration{}, "", err
	}
	current, err := r.publisher(ctx, index)
	if err != nil {
		return Registration{}, "", err
	}
	return current.Registration, index.RegistrationDigest, nil
}

func (r Registry) expectPublisher(ctx context.Context, plugin, expected string) (publicationIndex, string, Registration, error) {
	if !validDigest(expected) {
		return publicationIndex{}, "", Registration{}, fmt.Errorf("%w: give the current registration digest", ErrInvalid)
	}
	index, etag, err := r.readIndex(ctx, plugin)
	if err != nil {
		return publicationIndex{}, "", Registration{}, err
	}
	if index.RegistrationDigest == "" {
		return publicationIndex{}, "", Registration{}, ErrNotFound
	}
	if index.RegistrationDigest != expected {
		return publicationIndex{}, "", Registration{}, ErrConflict
	}
	current, err := r.publisher(ctx, index)
	return index, etag, current.Registration, err
}

// Rotate replaces the publisher with a new signing key, including when the
// old binding was suspended. Previously admitted releases retain their binding.
func (r Registry) Rotate(ctx context.Context, plugin, expected string, publisher Publisher) (Registration, string, error) {
	index, etag, next, err := r.expectPublisher(ctx, plugin, expected)
	if err != nil {
		return Registration{}, "", err
	}
	if next.Publisher.KeyID == publisher.KeyID || bytes.Equal(next.Publisher.PublicKey, publisher.PublicKey) {
		return Registration{}, "", fmt.Errorf("%w: rotation requires a different key ID and public key", ErrInvalid)
	}
	if _, err := publisher.key(); err != nil {
		return Registration{}, "", err
	}
	next.Publisher, next.Suspended = publisher, false
	return r.updatePublisher(ctx, &index, etag, next)
}

// Suspend blocks new publications under the current publisher and returns the
// admitted digests signed by its key. It never changes invocation authority.
func (r Registry) Suspend(ctx context.Context, plugin, expected string) (Registration, string, []string, error) {
	index, etag, next, err := r.expectPublisher(ctx, plugin, expected)
	if err != nil {
		return Registration{}, "", nil, err
	}
	if !next.Suspended {
		next.Suspended = true
		next, expected, err = r.updatePublisher(ctx, &index, etag, next)
		if err != nil {
			return Registration{}, "", nil, err
		}
	}
	keyDigest := digest(next.Publisher.PublicKey)
	affected := []string{}
	for _, entry := range index.Releases {
		if entry.PublisherKeyDigest == keyDigest {
			affected = append(affected, entry.ArtifactDigest)
		}
	}
	slices.Sort(affected)
	return next, expected, slices.Compact(affected), nil
}

func (r Registry) updatePublisher(ctx context.Context, index *publicationIndex, etag string, next Registration) (Registration, string, error) {
	if next.Revision == ^uint64(0) {
		return Registration{}, "", ErrCorrupt
	}
	next.Revision++
	raw, err := sonic.ConfigStd.Marshal(next)
	if err != nil {
		return Registration{}, "", err
	}
	sum := digest(raw)
	if err := r.saveRegistration(ctx, index, etag, raw, sum); err != nil {
		return Registration{}, "", err
	}
	return next, sum, nil
}
