//go:build integration

package main_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bytedance/sonic"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"

	"github.com/heynemann/go-plg-s3-registry/internal/testcontract"
)

const (
	flociImage   = "floci/floci@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19"
	contractPath = "github.com/heynemann/go-plg-s3-registry/internal/testcontract"
	bucket       = "registry-integration"
)

func TestPublishRelease(t *testing.T) {
	endpoint, s3client := startFloci(t)
	dir := t.TempDir()
	plg, cli := filepath.Join(dir, "plg"), filepath.Join(dir, "plg-registry")
	repo, err := filepath.Abs("../..")
	require.NoError(t, err)
	run(t, repo, nil, "go", "build", "-o", plg, "github.com/heynemann/go-plg/cmd/plg")
	run(t, repo, nil, "go", "build", "-race", "-o", cli, "./cmd/plg-registry")
	artifact, commit, conflicting, conflictingCommit := authorWorkflow(t, dir, plg)
	priv, pub := signingKey(t, dir, "publisher")
	wrong, _ := signingKey(t, dir, "other")
	base := []string{"--endpoint", endpoint, "--bucket", bucket, "--registry", "demo", "--output", "json"}
	invoke := func(args ...string) []byte {
		t.Helper()
		return run(t, dir, nil, cli, append(append([]string(nil), base...), args...)...)
	}
	fail := func(code int, args ...string) string {
		t.Helper()
		output, err := command(t, dir, nil, cli, append(append([]string(nil), base...), args...)...).CombinedOutput()
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit, "%s", output)
		require.Equal(t, code, exit.ExitCode(), "%s", output)
		return string(output)
	}
	onboard := []string{"plugin", "onboard", "--plugin", "eligibility", "--owner", "rewards", "--on-call", "rewards-ops",
		"--runbook", "https://example.com/runbooks/rewards", "--repository", "example/author",
		"--workflow", "heynemann/go-plg-s3-registry/.github/workflows/publish-plugin.yml@" + strings.Repeat("a", 40),
		"--key-id", "local:author", "--public-key", pub}
	registered := invoke(onboard...)
	require.JSONEq(t, string(registered), string(invoke(onboard...)))
	conflictOnboard := append(append([]string(nil), onboard...), "--owner", "spoofed")
	require.Contains(t, fail(4, conflictOnboard...), "immutable plugin ID")
	publish := func(file, source, key string) []string {
		return []string{"release", "publish", "--plugin", "eligibility", "--version", "v1.0.0", "--source-commit", source,
			"--artifact", file, "--key-id", "local:author", "--local-key", key}
	}
	require.Contains(t, fail(3, publish(artifact, commit, wrong)...), "publisher not authorized")
	require.Contains(t, fail(2, publish(artifact, conflictingCommit, priv)...), "clean checkout")
	objects, err := s3client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	require.Len(t, objects.Contents, 2, "refused publication must not write bytes")

	first := invoke(publish(artifact, commit, priv)...)
	require.JSONEq(t, string(first), string(invoke(publish(artifact, commit, priv)...)))
	require.Contains(t, fail(4, publish(conflicting, conflictingCommit, priv)...), "immutable")
	var release struct {
		Digest   string `json:"artifact_digest"`
		Commit   string `json:"source_commit"`
		Owner    string `json:"owner"`
		Workflow string `json:"workflow"`
		Contract struct {
			Interface string `json:"interface"`
		} `json:"contract"`
		Evidence struct {
			Tests int `json:"passed_author_tests"`
		} `json:"evidence"`
	}
	require.NoError(t, sonic.ConfigStd.Unmarshal(first, &release))
	content, err := os.ReadFile(artifact)
	require.NoError(t, err)
	sum := sha256.Sum256(content)
	require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), release.Digest)
	require.Equal(t, commit, release.Commit)
	require.Equal(t, "rewards", release.Owner, "artifact owner is self-declared")
	require.Contains(t, release.Workflow, "/.github/workflows/publish-plugin.yml@")
	require.Equal(t, contractPath+".Rule@v1.0.0", release.Contract.Interface)
	require.Equal(t, 1, release.Evidence.Tests)
	want := fmt.Sprintf(`{"schema_version":1,"releases":[%s]}`, first)
	inspect := []string{"release", "inspect", "--plugin", "eligibility"}
	require.JSONEq(t, want, string(invoke(append(append([]string(nil), inspect...), "--version", "v1.0.0")...)))
	require.JSONEq(t, want, string(invoke(append(append([]string(nil), inspect...), "--digest", release.Digest)...)))

	objects, err = s3client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	var keys []string
	for _, object := range objects.Contents {
		keys = append(keys, aws.ToString(object.Key))
	}
	artifactKey := "v1/demo/artifacts/" + release.Digest + ".plg"
	var index struct {
		Registration string `json:"registration_digest"`
		Releases map[string]struct {
			Envelope string `json:"envelope_digest"`
		} `json:"releases"`
	}
	prefix := "v1/demo/plugins/eligibility/"
	indexKey := prefix + "index.json"
	require.NoError(t, sonic.ConfigStd.Unmarshal(objectBytes(t, s3client, indexKey), &index))
	releaseKey := prefix + "releases/" + index.Releases["v1.0.0"].Envelope + ".json"
	require.ElementsMatch(t, []string{artifactKey, releaseKey, indexKey, prefix+"registrations/"+index.Registration+".json"}, keys,
		"publication must not create an active plan or mutate the registration")
	require.Equal(t, content, objectBytes(t, s3client, artifactKey))
	// Preserve well-formed DSSE but alter the signed payload; inspect must refuse it.
	var envelope struct {
		Type       string `json:"payloadType"`
		Data       []byte `json:"payload"`
		Signatures []struct {
			KeyID     string `json:"keyid"`
			Signature []byte `json:"sig"`
		} `json:"signatures"`
	}
	require.NoError(t, sonic.ConfigStd.Unmarshal(objectBytes(t, s3client, releaseKey), &envelope))
	envelope.Data = bytes.Replace(envelope.Data, []byte(commit), []byte(conflictingCommit), 1)
	tampered, err := sonic.ConfigStd.Marshal(envelope)
	require.NoError(t, err)
	_, err = s3client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(bucket), Key: &releaseKey, Body: bytes.NewReader(tampered)})
	require.NoError(t, err)
	require.Contains(t, fail(6, append(inspect, "--version", "v1.0.0")...), "failed verification")
}

func startFloci(t *testing.T) (string, *s3.Client) {
	t.Helper()
	ctx := t.Context()
	ctr, err := testcontainers.Run(ctx, flociImage,
		testcontainers.WithEnv(map[string]string{"FLOCI_STORAGE_MODE": "memory"}),
		testcontainers.WithExposedPorts("4566/tcp"),
		testcontainers.WithHostConfigModifier(func(cfg *container.HostConfig) {
			cfg.PortBindings = network.PortMap{
				network.MustParsePort("4566/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}},
			}
		}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/_floci/health").WithPort("4566/tcp").WithStartupTimeout(time.Minute)))
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "4566/tcp")
	require.NoError(t, err)
	endpoint := "http://" + net.JoinHostPort("127.0.0.1", port.Port())
	client := s3.New(s3.Options{
		BaseEndpoint: &endpoint, UsePathStyle: true, Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
	})
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	return endpoint, client
}

func objectBytes(t *testing.T, client *s3.Client, key string) []byte {
	t.Helper()
	result, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: &key})
	require.NoError(t, err)
	defer result.Body.Close()
	data, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	return data
}

func signingKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	require.NoError(t, os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600))
	require.NoError(t, os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0o600))
	return priv, pub
}

func command(t *testing.T, dir string, env []string, binary string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func run(t *testing.T, dir string, env []string, binary string, args ...string) []byte {
	t.Helper()
	cmd := command(t, dir, env, binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "%s: %s%s", cmd, out, stderr.Bytes())
	return out
}

func authorWorkflow(t *testing.T, dir, plg string) (first, commit, second, newCommit string) {
	t.Helper()
	src, proxy, author := filepath.Join(dir, "contract"), filepath.Join(dir, "proxy"), filepath.Join(dir, "author")
	versionDir := filepath.Join(proxy, contractPath, "@v")
	for _, path := range []string{src, versionDir, author} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	goMod := []byte("module " + contractPath + "\n\ngo 1.27\n")
	require.NoError(t, os.WriteFile(filepath.Join(src, "go.mod"), goMod, 0o600))
	code, err := testcontract.Source.ReadFile("contract.go")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(src, "contract.go"), code, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "v1.0.0.mod"), goMod, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "v1.0.0.info"), []byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`), 0o600))
	archive, err := os.Create(filepath.Join(versionDir, "v1.0.0.zip"))
	require.NoError(t, err)
	err = zip.CreateFromDir(archive, module.Version{Path: contractPath, Version: "v1.0.0"}, src)
	require.NoError(t, archive.Close())
	require.NoError(t, err)
	proxyURL := (&url.URL{Scheme: "file", Path: proxy}).String()
	env := []string{
		"GOPROXY=" + proxyURL, "GOMODCACHE=" + filepath.Join(dir, "modcache"),
		"GOFLAGS=-modcacherw", "GONOSUMDB=" + contractPath, "GOPRIVATE=", "GONOPROXY=none",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_COUNT=0",
	}
	run(t, author, env, "git", "init", "-q")
	run(t, author, env, plg, "init", "-lang", "lua", "-implements", contractPath+".Rule@v1.0.0", "eligibility")
	plugin := filepath.Join(author, "eligibility")
	sourceFile := filepath.Join(plugin, "plugin.lua")
	writeSource := func(accept string) {
		t.Helper()
		code := `local Rule = {}
function Rule:Accept(value)
  return ` + accept + `
end
function Create()
  return setmetatable({}, { __index = Rule })
end
`
		require.NoError(t, os.WriteFile(sourceFile, []byte(code), 0o600))
	}
	writeSource(`value == "gold"`)
	require.NoError(t, os.WriteFile(filepath.Join(plugin, "tests", "example.yaml"), []byte(`cases:
  - name: accepts gold
    call: Accept
    input:
      value: gold
    expect:
      result: true
`), 0o600))
	// This valid-looking ownership claim must not become registry authority.
	require.NoError(t, os.WriteFile(filepath.Join(plugin, "plugin.yaml"), []byte(`implements: `+contractPath+`.Rule@v1.0.0
language: lua
entrypoint: plugin.lua
owner:
  maintainers:
    - name: Example Author
      email: author@example.com
      handle: "@author"
  team:
    name: self-declared
    department: authoring
  org: example
  company: example
  contact:
    oncall: unverified
    channel: "#example"
    email: author@example.com
  links:
    repository: https://example.com/rule
    runbook: https://example.com/unverified
`), 0o600))
	pack := func(out string) (string, string) {
		t.Helper()
		run(t, author, env, "git", "add", "--all")
		run(t, author, env, "git", "-c", "user.name=Author", "-c", "user.email=author@example.com",
			"-c", "commit.gpgsign=false", "commit", "-qm", out)
		commit := strings.TrimSpace(string(run(t, author, env, "git", "rev-parse", "HEAD")))
		output := filepath.Join(dir, out)
		run(t, author, env, plg, "pack", "-color", "never", "-o", output, "eligibility")
		return filepath.Join(output, "eligibility.plg"), commit
	}
	run(t, author, env, plg, "validate", "-color", "never", "eligibility")
	first, commit = pack("first")
	writeSource(`value == "gold" or value == "silver"`)
	second, newCommit = pack("second")
	return first, commit, second, newCommit
}
