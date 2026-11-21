//go:build integration

package main_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bytedance/sonic"
	"github.com/heynemann/go-plg"
	"github.com/stretchr/testify/require"

	"github.com/heynemann/go-plg-s3-registry/dataplane"
	"github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

const environmentBucket = "registry-environment"

type authorityFixture struct {
	Role   string `json:"role"`
	ID     string `json:"key_id"`
	Public []byte `json:"public_key_pkix"`
}

type bucketFixture struct {
	Bucket string `json:"bucket"`
	Region string `json:"region"`
}

type deploymentFixture struct {
	Schema      int                       `json:"schema_version"`
	Scope       rollout.Scope             `json:"scope"`
	Destination bucketFixture             `json:"destination"`
	Publication bucketFixture             `json:"publication"`
	MaxLease    string                    `json:"max_lease"`
	Authorities []authorityFixture        `json:"authorities"`
	Recovery    *rollout.RecoveryEvidence `json:"recovery,omitempty"`
}

type lifecycle struct {
	t                            *testing.T
	dir, cli, endpoint, config   string
	client                       *s3.Client
	deployment                   deploymentFixture
	keys                         map[string]string
	first, second                rollout.Ref
	secondArtifact, secondCommit string
	sequence                     int
	trust                        dataplane.Trust
}

func startLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	endpoint, client := startFloci(t)
	requireConditionalWrites(t, client)
	dir := t.TempDir()
	plgCLI, registryCLI := filepath.Join(dir, "plg"), filepath.Join(dir, "plg-registry")
	repo, err := filepath.Abs("../..")
	require.NoError(t, err)
	run(t, repo, nil, "go", "build", "-o", plgCLI, "github.com/heynemann/go-plg/cmd/plg")
	run(t, repo, nil, "go", "build", "-o", registryCLI, "./cmd/plg-registry")
	first, firstCommit, second, secondCommit := authorWorkflow(t, dir, plgCLI)
	newBucket(t, client, environmentBucket)
	f := &lifecycle{t: t, dir: dir, cli: registryCLI, endpoint: endpoint, client: client, keys: make(map[string]string),
		secondArtifact: second, secondCommit: secondCommit, trust: dataplane.Trust{MaxLease: 10 * time.Minute},
		deployment: deploymentFixture{Schema: 1, Scope: rollout.Scope{Registry: "demo", Environment: "prod", Plugin: "eligibility", Epoch: "initial"},
			Destination: bucketFixture{environmentBucket, "us-east-1"}, Publication: bucketFixture{bucket, "us-east-1"}, MaxLease: "10m"}}
	for _, item := range []struct {
		role string
		keys *[]dataplane.Key
	}{
		{"proposer", &f.trust.Proposers}, {"approver", &f.trust.Approvers}, {"decider", &f.trust.Deciders},
		{"responder", &f.trust.Responders}, {"renewer", &f.trust.Renewers}, {"recoverer", &f.trust.Recoverers},
		{"publisher-admin", nil},
	} {
		private, public := signingKey(t, dir, item.role)
		data, err := os.ReadFile(public)
		require.NoError(t, err)
		block, _ := pem.Decode(data)
		require.NotNil(t, block)
		id := "local:" + item.role
		f.deployment.Authorities = append(f.deployment.Authorities, authorityFixture{item.role, id, block.Bytes})
		if item.keys != nil {
			*item.keys = append(*item.keys, dataplane.Key{ID: id, Principal: id, PublicKey: publicECDSA(t, block.Bytes)})
		}
		f.keys[item.role] = private
	}
	f.config = f.file(f.deployment)
	priv, pub := signingKey(t, dir, "author")
	f.keys["author"] = priv
	f.publication(0, "plugin", "onboard", "--plugin", "eligibility", "--owner", "rewards", "--on-call", "rewards-ops",
		"--runbook", "https://example.com/runbooks/rewards", "--repository", "example/author",
		"--workflow", workflow(), "--key-id", "local:author", "--public-key", pub)
	f.first = f.publish("v1.0.0", first, firstCommit, "author", 0)
	f.second = f.publish("v2.0.0", second, secondCommit, "author", 0)
	return f
}

func workflow() string {
	return "heynemann/go-plg-s3-registry/.github/workflows/publish-plugin.yml@" + strings.Repeat("a", 40)
}

func newBucket(t *testing.T, c *s3.Client, name string) {
	t.Helper()
	_, err := c.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &name})
	require.NoError(t, err)
}

func (f *lifecycle) file(value any) string {
	f.t.Helper()
	f.sequence++
	path := filepath.Join(f.dir, "request-"+strconv.Itoa(f.sequence)+".json")
	data, err := sonic.ConfigStd.Marshal(value)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(path, data, 0o600))
	return path
}

func (f *lifecycle) args(role string, args ...string) []string {
	base := []string{"--endpoint", f.endpoint, "--config", f.config, "--output", "json"}
	if role != "" {
		base = append(base, "--local-key", f.keys[role])
	}
	return append(base, args...)
}

func (f *lifecycle) cliResult(code int, args ...string) []byte {
	f.t.Helper()
	data, err := command(f.t, f.dir, nil, f.cli, args...).CombinedOutput()
	if code == 0 {
		require.NoError(f.t, err, "%s", data)
		return data
	}
	var exit *exec.ExitError
	require.ErrorAs(f.t, err, &exit, "%s", data)
	require.Equal(f.t, code, exit.ExitCode(), "%s", data)
	return data
}

func (f *lifecycle) control(role string, code int, args ...string) []byte {
	f.t.Helper()
	return f.cliResult(code, f.args(role, args...)...)
}

func (f *lifecycle) publication(code int, args ...string) []byte {
	f.t.Helper()
	base := []string{"--endpoint", f.endpoint, "--registry", "demo", "--bucket", bucket, "--output", "json"}
	return f.cliResult(code, append(base, args...)...)
}

func (f *lifecycle) publish(version, artifact, commit, author string, code int) rollout.Ref {
	f.t.Helper()
	out := f.publication(code, "release", "publish", "--plugin", "eligibility", "--version", version,
		"--artifact", artifact, "--source-commit", commit, "--key-id", "local:"+author, "--local-key", f.keys[author])
	if code != 0 {
		return rollout.Ref{}
	}
	r := decodeJSON[registry.Release](f.t, out)
	data, err := os.ReadFile(artifact)
	require.NoError(f.t, err)
	sum := sha256.Sum256(data)
	require.Equal(f.t, "sha256:"+hex.EncodeToString(sum[:]), r.ArtifactDigest)
	return rollout.Ref{Version: r.Version, Digest: r.ArtifactDigest}
}

type decisionJSON struct {
	rollout.Decision
	DecisionID string `json:"decision_id"`
}

type appliedJSON struct {
	Decision       decisionJSON `json:"decision"`
	AlreadyApplied bool         `json:"already_applied"`
}

func decodeJSON[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	require.NoError(t, sonic.ConfigStd.Unmarshal(data, &result), "%s", data)
	return result
}

func (f *lifecycle) approve(plan rollout.Plan) (string, string) {
	f.t.Helper()
	proposed := decodeJSON[struct {
		Plan      string            `json:"plan_id"`
		Candidate registry.Release  `json:"candidate"`
		Baseline  *registry.Release `json:"baseline"`
	}](f.t,
		f.control("proposer", 0, "rollout", "propose", "--plan", f.file(plan)))
	require.Equal(f.t, plan.Candidate.Digest, proposed.Candidate.ArtifactDigest)
	if plan.Baseline != (rollout.Ref{}) {
		require.NotNil(f.t, proposed.Baseline)
		require.Equal(f.t, plan.Baseline.Digest, proposed.Baseline.ArtifactDigest)
	}
	approved := decodeJSON[struct {
		Approval string `json:"approval_id"`
	}](f.t,
		f.control("approver", 0, "rollout", "approve", "--plan-id", proposed.Plan))
	return proposed.Plan, approved.Approval
}

func (f *lifecycle) execute(role, group, action string, c rollout.Command) decisionJSON {
	f.t.Helper()
	return decodeJSON[appliedJSON](f.t, f.control(role, 0, group, action, "--command", f.file(c))).Decision
}

func (f *lifecycle) renew() time.Time {
	f.t.Helper()
	return decodeJSON[struct {
		Expiry time.Time `json:"expires_at"`
	}](f.t,
		f.control("renewer", 0, "freshness", "renew", "--duration", "10m")).Expiry
}

func (f *lifecycle) host(memory uint64, offset *atomic.Int64, telemetry dataplane.Telemetry) *dataplane.Host[contract.Rule] {
	f.t.Helper()
	scope := f.deployment.Scope
	h, err := dataplane.Attach[contract.Rule](f.t.Context(), nil, dataplane.Config{
		Client: f.client, Bucket: f.deployment.Destination.Bucket, Registry: scope.Registry, Environment: scope.Environment,
		Plugin: scope.Plugin, Epoch: scope.Epoch, Trust: f.trust, Unavailable: dataplane.Hold, RetryHorizon: time.Hour,
		RetentionMargin: time.Minute, MemoryLimit: 64 << 20, MemoryBudget: memory, ContractModule: contract.Module,
		ContractVersion: contract.Version, Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }, Telemetry: telemetry,
	}, plg.WithLuaPlugins())
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(f.t, h.Close(ctx))
	})
	return h
}

func selectReceipt(t *testing.T, h *dataplane.Host[contract.Rule], region, digest string) dataplane.Receipt {
	t.Helper()
	receipt, err := h.Select([]byte("user-2"), map[string]any{"region": region})
	require.NoError(t, err)
	require.Equal(t, digest, receipt.Digest)
	return receipt
}

func invokeRule(t *testing.T, h *dataplane.Host[contract.Rule], receipt dataplane.Receipt, retry, want bool) {
	t.Helper()
	call := func(plugin contract.Rule) error {
		got, err := plugin.Accept(t.Context(), "silver")
		if err == nil && got != want {
			return errors.New("the wrong plugin digest answered the call")
		}
		return err
	}
	if retry {
		require.NoError(t, h.InvokeRetry(t.Context(), receipt, call))
		return
	}
	require.NoError(t, h.Invoke(t.Context(), receipt, call))
}

func snapshot(t *testing.T, c *s3.Client, src, dst string) {
	t.Helper()
	ctx := t.Context()
	pages := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: &src})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		require.NoError(t, err)
		for _, obj := range page.Contents {
			_, err = c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &dst, Key: obj.Key, CopySource: aws.String(src + "/" + aws.ToString(obj.Key))})
			require.NoError(t, err)
		}
	}
}

func persisted(t *testing.T, dir string, receipt dataplane.Receipt) dataplane.Receipt {
	t.Helper()
	data, err := sonic.ConfigStd.Marshal(receipt)
	require.NoError(t, err)
	path := filepath.Join(dir, "persisted-operation.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	read, err := os.ReadFile(path)
	require.NoError(t, err)
	// The invocation uses the serialized receipt read from the operation store.
	return decodeJSON[dataplane.Receipt](t, read)
}

func publicECDSA(t *testing.T, der []byte) *ecdsa.PublicKey {
	t.Helper()
	key, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)
	point, ok := key.(*ecdsa.PublicKey)
	require.True(t, ok)
	return point
}
