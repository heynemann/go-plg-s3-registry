//go:build integration

package main_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// requireConditionalWrites proves the safety primitives this emulator must
// provide for the lifecycle scenario to exercise the real protocol.
func requireConditionalWrites(t *testing.T, client *s3.Client) {
	t.Helper()
	ctx := t.Context()
	name, key, star := "registry-floci-capability", "pointer", "*"
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name})
	require.NoError(t, err)
	_, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &name,
		VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}})
	require.NoError(t, err)
	original, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &name, Key: &key, IfNoneMatch: &star, Body: bytes.NewReader([]byte("initial"))})
	require.NoError(t, err)
	require.NotEmpty(t, aws.ToString(original.VersionId))
	require.NotEmpty(t, aws.ToString(original.ETag))
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &name, Key: &key, IfNoneMatch: &star, Body: bytes.NewReader([]byte("duplicate"))})
	var api smithy.APIError
	require.ErrorAs(t, err, &api)
	require.Equal(t, "PreconditionFailed", api.ErrorCode())
	type outcome struct {
		value string
		err   error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for _, value := range []string{"left", "right"} {
		go func() {
			<-start
			_, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &name, Key: &key, IfMatch: original.ETag, Body: bytes.NewReader([]byte(value))})
			results <- outcome{value, err}
		}()
	}
	close(start)
	var winner string
	for range 2 {
		res := <-results
		if res.err == nil {
			require.Empty(t, winner, "S3 CAS allowed two winners")
			winner = res.value
			continue
		}
		require.ErrorAs(t, res.err, &api)
		require.Equal(t, "PreconditionFailed", api.ErrorCode())
	}
	require.Contains(t, []string{"left", "right"}, winner)
	read := func(version *string) string {
		t.Helper()
		obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &name, Key: &key, VersionId: version})
		require.NoError(t, err)
		defer obj.Body.Close()
		data, err := io.ReadAll(obj.Body)
		require.NoError(t, err)
		return string(data)
	}
	require.Equal(t, winner, read(nil))
	require.Equal(t, "initial", read(original.VersionId))
	versions, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &name, Prefix: &key})
	require.NoError(t, err)
	require.Len(t, versions.Versions, 2)
}
