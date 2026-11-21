package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

// Store adapts S3's exact-key and create-only operations to the registry.
type Store struct {
	client *s3.Client
	bucket *string
	owner  *string
}

func New(client *s3.Client, bucket, owner string) Store {
	store := Store{client: client, bucket: aws.String(bucket)}
	if owner != "" {
		store.owner = aws.String(owner)
	}
	return store
}

func (s Store) Create(ctx context.Context, key string, data []byte) error {
	return s.CompareAndSwap(ctx, key, "", data)
}

// CompareAndSwap creates an absent object or replaces an exact ETag.
func (s Store) CompareAndSwap(ctx context.Context, key, etag string, data []byte) error {
	input := s3.PutObjectInput{
		Bucket: s.bucket, Key: &key, Body: bytes.NewReader(data), ExpectedBucketOwner: s.owner,
	}
	if etag == "" {
		input.IfNoneMatch = aws.String("*")
	} else {
		input.IfMatch = &etag
	}
	_, err := s.client.PutObject(ctx, &input)
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "PreconditionFailed" {
		return registry.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create S3 object: %w", err)
	}
	return nil
}

func (s Store) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	body, _, err := s.Read(ctx, key)
	return body, err
}

// Read returns the object and its opaque conditional-write token.
func (s Store) Read(ctx context.Context, key string) (io.ReadCloser, string, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: s.bucket, Key: &key, ExpectedBucketOwner: s.owner})
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "NoSuchKey" {
		return nil, "", registry.ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("read S3 object: %w", err)
	}
	etag := aws.ToString(result.ETag)
	if etag == "" {
		_ = result.Body.Close()
		return nil, "", fmt.Errorf("S3 object has no ETag: %w", registry.ErrCorrupt)
	}
	return result.Body, etag, nil
}

func (s Store) List(ctx context.Context, prefix string, yield func(string) error) error {
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: s.bucket, Prefix: &prefix, ExpectedBucketOwner: s.owner,
	}, func(options *s3.ListObjectsV2PaginatorOptions) { options.StopOnDuplicateToken = true })
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list S3 objects: %w", err)
		}
		for _, object := range page.Contents {
			if err = yield(aws.ToString(object.Key)); err != nil {
				return err
			}
		}
	}
	return nil
}
