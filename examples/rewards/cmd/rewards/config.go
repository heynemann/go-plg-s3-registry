package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bytedance/sonic"
	"github.com/heynemann/go-plg-s3-registry/dataplane"
	"github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
)

// Only the consumer-facing subset of the CLI deployment file is needed. The
// publication bucket, private signing material, and control actions stay out of
// the rewards process.
type deployment struct {
	Schema int `json:"schema_version"`
	Scope  struct {
		Registry    string `json:"registry"`
		Environment string `json:"environment"`
		Plugin      string `json:"plugin"`
		Epoch       string `json:"epoch"`
	} `json:"scope"`
	Destination struct {
		Bucket string `json:"bucket"`
		Region string `json:"region"`
		Owner  string `json:"owner"`
	} `json:"destination"`
	MaxLease     string `json:"max_lease"`
	MaxClockSkew string `json:"max_clock_skew"`
	Authorities  []struct {
		Role      string `json:"role"`
		KeyID     string `json:"key_id"`
		PublicKey []byte `json:"public_key_pkix"`
		AWSRole   string `json:"aws_role_arn"`
		AWSRoleID string `json:"aws_role_id"`
	} `json:"authorities"`
}

var localKeyName = regexp.MustCompile(`^local:[a-z0-9][a-z0-9-]{0,62}$`)

func loadHostConfig(path string, transport *http.Transport, endpoint string, poll time.Duration) (dataplane.Config, error) {
	var d deployment
	data, err := os.ReadFile(path)
	if err != nil {
		return dataplane.Config{}, err
	}
	if err := sonic.ConfigStd.Unmarshal(data, &d); err != nil {
		return dataplane.Config{}, errors.New("invalid deployment JSON")
	}
	if d.Schema != 1 || d.Destination.Bucket == "" || d.Destination.Region == "" || d.Destination.Owner != "" {
		return dataplane.Config{}, errors.New("expected a schema-version 1 loopback deployment with a destination bucket and region")
	}
	lease, err := time.ParseDuration(d.MaxLease)
	if err != nil || lease <= 0 {
		return dataplane.Config{}, errors.New("invalid max_lease")
	}
	var skew time.Duration
	if d.MaxClockSkew != "" {
		skew, err = time.ParseDuration(d.MaxClockSkew)
		if err != nil || skew < 0 || skew >= lease {
			return dataplane.Config{}, errors.New("invalid max_clock_skew")
		}
	}
	if len(d.Authorities) < 1 || len(d.Authorities) > 64 {
		return dataplane.Config{}, errors.New("expected between one and 64 public authority bindings")
	}
	trust := dataplane.Trust{MaxLease: lease}
	roles := map[string]*[]dataplane.Key{
		"proposer": &trust.Proposers, "approver": &trust.Approvers, "decider": &trust.Deciders,
		"responder": &trust.Responders, "renewer": &trust.Renewers, "recoverer": &trust.Recoverers,
	}
	seen := make([]dataplane.Key, 0, len(d.Authorities))
	for _, a := range d.Authorities {
		if !localKeyName.MatchString(a.KeyID) || a.AWSRole != "" || a.AWSRoleID != "" {
			return dataplane.Config{}, errors.New("local authorities require a local key ID and cannot bind AWS roles")
		}
		value, err := x509.ParsePKIXPublicKey(a.PublicKey)
		pub, ok := value.(*ecdsa.PublicKey)
		if err != nil || !ok || pub.Curve != elliptic.P256() {
			return dataplane.Config{}, errors.New("authority public_key_pkix must contain a base64 PKIX P-256 key")
		}
		for _, prev := range seen {
			if a.KeyID == prev.ID || pub.Equal(prev.PublicKey) {
				return dataplane.Config{}, errors.New("authority bindings must use distinct keys and IDs")
			}
		}
		key := dataplane.Key{ID: a.KeyID, Principal: a.KeyID, PublicKey: pub}
		seen = append(seen, key)
		if keys := roles[a.Role]; keys != nil {
			*keys = append(*keys, key)
		} else if a.Role != "publisher-admin" {
			return dataplane.Config{}, errors.New("unsupported authority role")
		}
	}
	return dataplane.Config{
		Client: localS3(transport, endpoint, d.Destination.Region), Bucket: d.Destination.Bucket,
		Registry: d.Scope.Registry, Environment: d.Scope.Environment, Plugin: d.Scope.Plugin, Epoch: d.Scope.Epoch,
		Trust: trust, MaxClockSkew: skew, Unavailable: dataplane.Hold,
		ContractModule: contract.Module, ContractVersion: contract.Version,
		PollInterval: poll, SyncTimeout: 10 * time.Second,
		RetryHorizon: time.Hour, RetentionMargin: time.Minute, MemoryLimit: 64 << 20,
	}, nil
}

// Normalize localhost without DNS and never let this example dial a proxy or
// follow an emulator redirect out of loopback, even with ambient AWS settings.
func loopbackAddress(addr string, allowZero bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if host != "127.0.0.1" && host != "::1" {
		return "", errors.New("host must be localhost, 127.0.0.1 or ::1")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (n == 0 && !allowZero) {
		return "", errors.New("invalid TCP port")
	}
	return net.JoinHostPort(host, port), nil
}

func localTransport(endpoint string) (*http.Transport, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Path != "" && u.Path != "/") || u.ForceQuery ||
		u.RawQuery != "" || strings.Contains(endpoint, "#") {
		return nil, "", errors.New("--endpoint must be a loopback HTTP origin with a port")
	}
	addr, err := loopbackAddress(u.Host, false)
	if err != nil {
		return nil, "", fmt.Errorf("--endpoint: %w", err)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if requested != addr {
				return nil, errors.New("S3 destination must be the configured loopback origin")
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return transport, "http://" + addr, nil
}

func localS3(transport *http.Transport, endpoint, region string) *s3.Client {
	return s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint), UsePathStyle: true, Region: region,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	})
}
