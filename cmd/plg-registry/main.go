// plg-registry is the control-plane CLI. It does not run plugins.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bytedance/sonic"
	"github.com/spf13/cobra"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/s3store"
)

var accountID = regexp.MustCompile(`^[0-9]{12}$`)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		message, code := failure(err)
		fmt.Fprintln(os.Stderr, "plg-registry:", message)
		os.Exit(code)
	}
}

type options struct {
	registry, bucket, region, account, endpoint, output, localKey string
}

func newRoot() *cobra.Command {
	var opts options
	root := &cobra.Command{
		Use: "plg-registry", Short: "Publish signed go-plg releases and manage rollout authority",
		SilenceUsage: true, SilenceErrors: true,
	}
	flags := root.PersistentFlags()
	flags.StringVar(&opts.registry, "registry", "", "registry ID")
	flags.StringVar(&opts.bucket, "bucket", "", "registry S3 bucket")
	flags.StringVar(&opts.region, "region", "us-east-1", "AWS region of the S3 bucket")
	flags.StringVar(&opts.account, "bucket-owner", "", "expected AWS account owning the bucket (required without --endpoint)")
	flags.StringVar(&opts.endpoint, "endpoint", "", "loopback HTTP endpoint for local S3 tests only")
	flags.StringVar(&opts.output, "output", "text", "output format: text or json")
	flags.StringVar(&opts.localKey, "local-key", "", "PEM PKCS#8 P-256 signing key (only with --endpoint)")
	plugin := &cobra.Command{Use: "plugin", Short: "Manage registered plugin identities"}
	plugin.AddCommand(opts.onboard())
	release := &cobra.Command{Use: "release", Short: "Manage immutable plugin releases"}
	release.AddCommand(opts.publish(), opts.inspect())
	root.AddCommand(plugin, release)
	o := controlOptions{global: &opts}
	o.addCommands(root, release)
	return root
}

func (o *options) connect(ctx context.Context) (registry.Registry, aws.Config, error) {
	if o.registry == "" || o.bucket == "" || (o.output != "text" && o.output != "json") {
		return registry.Registry{}, aws.Config{}, fmt.Errorf("%w: --registry, --bucket and a text or json output format are required", registry.ErrInvalid)
	}
	cfg, err := o.awsConfig(ctx)
	if err != nil {
		return registry.Registry{}, aws.Config{}, err
	}
	bucket := bucketLocation{Bucket: o.bucket, Owner: o.account, Region: o.region}
	r, err := registry.New(bucket.store(cfg, o.endpoint), o.registry)
	return r, cfg, err
}

func (o *options) awsConfig(ctx context.Context) (aws.Config, error) {
	if o.endpoint != "" {
		if !loopbackEndpoint(o.endpoint) || o.account != "" {
			return aws.Config{}, fmt.Errorf("%w: --endpoint is a loopback HTTP origin for testing and cannot be combined with --bucket-owner", registry.ErrInvalid)
		}
		origin, _ := url.Parse(o.endpoint) // Validated above.
		dialer := net.Dialer{Timeout: 5 * time.Second}
		transport := &http.Transport{
			IdleConnTimeout: 30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != origin.Host {
					return nil, errors.New("local S3 transport only dials its configured loopback origin")
				}
				return dialer.DialContext(ctx, network, addr)
			},
		}
		return aws.Config{
			Region:      o.region,
			Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
			HTTPClient: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}},
		}, nil
	}
	if !accountID.MatchString(o.account) {
		return aws.Config{}, fmt.Errorf("%w: --bucket-owner must be a 12-digit AWS account", registry.ErrInvalid)
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(o.region))
	if err != nil {
		return aws.Config{}, err
	}
	// Application endpoints cannot be redirected through AWS_ENDPOINT_URL
	// or a shared service-endpoint profile.
	cfg.BaseEndpoint = nil
	cfg.ConfigSources = nil
	return cfg, nil
}

func (b bucketLocation) store(cfg aws.Config, endpoint string) s3store.Store {
	cfg.Region = b.Region
	client := s3.NewFromConfig(cfg, func(opt *s3.Options) {
		if endpoint != "" {
			opt.BaseEndpoint = &endpoint
			opt.UsePathStyle = true
		}
	})
	return s3store.New(client, b.Bucket, b.Owner)
}

func loopbackEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" ||
		u.Path != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host, err := netip.ParseAddr(u.Hostname())
	return err == nil && host.IsLoopback()
}

func (o *options) onboard() *cobra.Command {
	var r registry.Registration
	var publicFile string
	cmd := &cobra.Command{
		Use: "onboard", Short: "Reserve a plugin ID and bind an authorized publisher", Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			if err := o.checkKeyMode(r.Publisher.KeyID); err != nil {
				return err
			}
			pub, err := keyPEM(publicFile, "PUBLIC KEY")
			if err != nil {
				return err
			}
			r.Publisher.PublicKey = pub
			service, _, err := o.connect(ctx)
			if err != nil {
				return err
			}
			record, err := service.Onboard(ctx, r)
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), record)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "registered %s (owner %s, workflow %s/%s)\n",
				record.Plugin, record.Owner, record.Publisher.Repository, record.Publisher.Workflow)
			return err
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&r.Plugin, "plugin", "", "stable plugin ID")
	flags.StringVar(&r.Owner, "owner", "", "verified owner ID")
	flags.StringVar(&r.OnCall, "on-call", "", "on-call route ID")
	flags.StringVar(&r.Runbook, "runbook", "", "HTTPS runbook URL")
	flags.StringVar(&r.Publisher.Repository, "repository", "", "authorized CI repository (owner/name)")
	flags.StringVar(&r.Publisher.Workflow, "workflow", "", "trusted reusable workflow (owner/repo/.github/workflows/file.yml@commit)")
	flags.StringVar(&r.Publisher.KeyID, "key-id", "", "exact KMS key ARN, or local:<name> for tests")
	flags.StringVar(&publicFile, "public-key", "", "PEM PKIX P-256 public key")
	return cmd
}

func (o *options) publish() *cobra.Command {
	var plugin, version, source, artifact, keyID string
	cmd := &cobra.Command{
		Use: "publish", Short: "Publish an exact packed artifact without activating it", Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			if err := o.checkKeyMode(keyID); err != nil {
				return err
			}
			data, err := boundedFile(artifact, registry.MaxArtifactBytes)
			if err != nil {
				return fmt.Errorf("%w: cannot read a nonempty .plg archive of at most 64 MiB", registry.ErrInvalid)
			}
			service, cfg, err := o.connect(ctx)
			if err != nil {
				return err
			}
			sign, err := o.signer(ctx, cfg, keyID, o.localKey)
			if err != nil {
				return err
			}
			release, err := service.Publish(ctx, plugin, version, source, keyID, data, sign)
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), release)
			}
			return writeRelease(cmd.OutOrStdout(), release)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&plugin, "plugin", "", "registered plugin ID")
	flags.StringVar(&version, "version", "", "immutable release version")
	flags.StringVar(&source, "source-commit", "", "full commit that produced the artifact")
	flags.StringVar(&artifact, "artifact", "", "packed .plg archive")
	flags.StringVar(&keyID, "key-id", "", "exact registered signing key ID")
	return cmd
}

func (o *options) inspect() *cobra.Command {
	var plugin, version, sum string
	cmd := &cobra.Command{
		Use: "inspect", Short: "Verify and show published release metadata", Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			service, _, err := o.connect(ctx)
			if err != nil {
				return err
			}
			releases, err := service.Inspect(ctx, plugin, version, sum)
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), struct {
					Schema   int                `json:"schema_version"`
					Releases []registry.Release `json:"releases"`
				}{1, releases})
			}
			for _, release := range releases {
				if err = writeRelease(cmd.OutOrStdout(), release); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&plugin, "plugin", "", "registered plugin ID")
	cmd.Flags().StringVar(&version, "version", "", "release version to inspect")
	cmd.Flags().StringVar(&sum, "digest", "", "exact artifact SHA-256 to inspect instead of version")
	return cmd
}

func boundedFile(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > max {
		return nil, registry.ErrInvalid
	}
	data := make([]byte, info.Size())
	if _, err = io.ReadFull(file, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	if _, err = file.Read(extra[:]); !errors.Is(err, io.EOF) {
		return nil, registry.ErrInvalid
	}
	return data, nil
}

func writeJSON[T any](out io.Writer, value T) error {
	return sonic.ConfigStd.NewEncoder(out).Encode(value)
}

func writeRelease(out io.Writer, r registry.Release) error {
	_, err := fmt.Fprintf(out, "%s@%s %s (%d bytes)\nowner: %s\nsource: %s %s\nworkflow: %s\ncontract: %s\nauthor tests passed: %d\nvalidation report: %s\n",
		r.Plugin, r.Version, r.ArtifactDigest, r.ArtifactBytes, r.Owner, r.Repository, r.SourceCommit, r.Workflow,
		r.Contract.Interface, r.Evidence.PassedTests, r.Evidence.ValidationDigest)
	return err
}

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: use flags instead of positional arguments; see --help", registry.ErrInvalid)
	}
	return nil
}

func failure(err error) (string, int) {
	var control *controlError
	if errors.As(err, &control) {
		return control.failure()
	}
	switch {
	case errors.Is(err, registry.ErrInvalid):
		return err.Error(), 2
	case errors.Is(err, registry.ErrDenied):
		return "publisher not authorized for this plugin; check the registered signing key and workflow role", 3
	case errors.Is(err, registry.ErrConflict):
		return "an immutable plugin ID or release version already has different contents", 4
	case errors.Is(err, registry.ErrNotFound):
		return "registry record not found; check the plugin ID, version and registry", 5
	case errors.Is(err, registry.ErrCorrupt):
		return "registry record failed verification; do not use this release", 6
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "operation interrupted or timed out; inspect the registry before retrying", 1
	default:
		return "command failed; check --help, credentials, bucket and signing configuration", 1
	}
}
