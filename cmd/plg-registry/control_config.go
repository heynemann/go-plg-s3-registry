package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

const (
	proposerRole   = "proposer"
	approverRole   = "approver"
	deciderRole    = "decider"
	responderRole  = "responder"
	renewerRole    = "renewer"
	recovererRole  = "recoverer"
	publisherAdmin = "publisher-admin"
)

// A deployment file is an operator-distributed trust root, not workflow
// input supplied by release authors. Keep it outside the buckets it verifies.
type deploymentConfig struct {
	Schema       int                       `json:"schema_version"`
	Scope        rollout.Scope             `json:"scope"`
	Destination  bucketLocation            `json:"destination"`
	Publication  bucketLocation            `json:"publication"`
	MaxLease     string                    `json:"max_lease"`
	MaxClockSkew string                    `json:"max_clock_skew"`
	Authorities  []authorityConfig         `json:"authorities"`
	Recovery     *rollout.RecoveryEvidence `json:"recovery,omitempty"`
	GitHub       *githubDeployment         `json:"github,omitempty"`
}

type bucketLocation struct {
	Bucket string `json:"bucket"`
	Owner  string `json:"owner,omitempty"`
	Region string `json:"region"`
}

type authorityConfig struct {
	Role      string `json:"role"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey []byte `json:"public_key_pkix,omitempty"`
	AWSRole   string `json:"aws_role_arn,omitempty"`
	AWSRoleID string `json:"aws_role_id,omitempty"`
}

type authority struct {
	role, awsRoleID string
	awsRole         arn.ARN
	key             rollout.Key
}

type controlSession struct {
	service     rollout.Service
	actor       rollout.Identity
	publication bucketLocation
	endpoint    string
	cfg         *aws.Config
}

func (s *controlSession) sourceRegistry() (registry.Registry, error) {
	return registry.New(s.publication.store(*s.cfg, s.endpoint), s.service.Scope.Registry)
}

func (s *controlSession) targetRegistry() (registry.Registry, error) {
	return registry.New(s.service.Store, s.service.Scope.Registry)
}

var (
	deploymentID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	bucketName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	awsRegion    = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+$`)
	awsRoleID    = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}$`)
	kmsKeyName   = regexp.MustCompile(`^key/[A-Za-z0-9-]+$`)
	roleName     = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
)

func (d deploymentConfig) validate(local bool) (rollout.Service, []authority, error) {
	scope := d.Scope
	if d.Schema != 1 || !deploymentID.MatchString(scope.Registry) || !deploymentID.MatchString(scope.Environment) ||
		!deploymentID.MatchString(scope.Plugin) || !deploymentID.MatchString(scope.Epoch) {
		return rollout.Service{}, nil, invalidInput("deployment requires schema version 1 and a complete scope")
	}
	if !d.Destination.valid(local) || !d.Publication.valid(local) || d.Destination.Bucket == d.Publication.Bucket ||
		(!local && d.Destination.Owner == d.Publication.Owner) {
		return rollout.Service{}, nil, invalidInput("deployment requires distinct destination and publication buckets, separately owned in AWS")
	}
	if (!local && (d.GitHub == nil || !d.GitHub.valid())) || (local && d.GitHub != nil) {
		return rollout.Service{}, nil, invalidInput("AWS requires a pinned GitHub repository, repository ID, and protected branch")
	}
	lease, err := time.ParseDuration(d.MaxLease)
	if err != nil || lease <= 0 {
		return rollout.Service{}, nil, invalidInput("deployment max_lease must be a positive duration")
	}
	var skew time.Duration
	if d.MaxClockSkew != "" {
		skew, err = time.ParseDuration(d.MaxClockSkew)
		if err != nil || skew < 0 {
			return rollout.Service{}, nil, invalidInput("deployment max_clock_skew must be a nonnegative duration")
		}
	}
	if len(d.Authorities) == 0 || len(d.Authorities) > 64 {
		return rollout.Service{}, nil, invalidInput("deployment requires between one and 64 authority bindings")
	}
	if d.Recovery != nil {
		old := d.Recovery.Scope
		if old.Registry != scope.Registry || old.Environment != scope.Environment || old.Plugin != scope.Plugin ||
			old.Epoch == scope.Epoch || !deploymentID.MatchString(old.Epoch) || d.Recovery.Generation == 0 || d.Recovery.Decision == "" {
			return rollout.Service{}, nil, invalidInput("recovery requires an independently recorded checkpoint in another epoch of the same scope")
		}
	}

	trust := rollout.Trust{MaxLease: lease}
	authorities := make([]authority, 0, len(d.Authorities))
	for _, entry := range d.Authorities {
		a, err := entry.parse(local)
		if err != nil {
			return rollout.Service{}, nil, err
		}
		for _, prev := range authorities {
			if (a.key.ID != "" && a.key.ID == prev.key.ID) ||
				(a.key.PublicKey != nil && prev.key.PublicKey != nil && a.key.PublicKey.Equal(prev.key.PublicKey)) ||
				(a.awsRoleID != "" && (a.awsRoleID == prev.awsRoleID || a.awsRole == prev.awsRole)) {
				return rollout.Service{}, nil, invalidInput("authority bindings must use distinct keys and AWS roles")
			}
		}
		switch a.role {
		case proposerRole:
			trust.Proposers = append(trust.Proposers, a.key)
		case approverRole:
			trust.Approvers = append(trust.Approvers, a.key)
		case deciderRole:
			trust.Deciders = append(trust.Deciders, a.key)
		case responderRole:
			trust.Responders = append(trust.Responders, a.key)
		case renewerRole:
			trust.Renewers = append(trust.Renewers, a.key)
		case recovererRole:
			trust.Recoverers = append(trust.Recoverers, a.key)
		case publisherAdmin:
			// Publisher trust changes use the separate publication role and CAS.
		default:
			return rollout.Service{}, nil, invalidInput("deployment has an unsupported authority role")
		}
		authorities = append(authorities, a)
	}
	return rollout.Service{
		Scope: scope, Trust: trust, MaxClockSkew: skew, Recovery: d.Recovery,
	}, authorities, nil
}

func (b bucketLocation) valid(local bool) bool {
	return bucketName.MatchString(b.Bucket) && awsRegion.MatchString(b.Region) &&
		(local && b.Owner == "" || !local && accountID.MatchString(b.Owner))
}

func (entry authorityConfig) parse(local bool) (authority, error) {
	a := authority{role: entry.Role, awsRoleID: entry.AWSRoleID}
	if local {
		keyName, ok := strings.CutPrefix(entry.KeyID, "local:")
		if !ok || !deploymentID.MatchString(keyName) || entry.AWSRole != "" || entry.AWSRoleID != "" {
			return authority{}, invalidInput("loopback authorities require a local key and cannot bind AWS roles")
		}
		a.key.Principal = entry.KeyID
	} else {
		r, err := arn.Parse(entry.AWSRole)
		path, ok := strings.CutPrefix(r.Resource, "role/")
		if err != nil || !ok || !roleName.MatchString(lastSegment(path)) || r.Service != "iam" || r.Region != "" ||
			!accountID.MatchString(r.AccountID) || !awsRoleID.MatchString(entry.AWSRoleID) || !strings.HasPrefix(r.Partition, "aws") {
			return authority{}, invalidInput("AWS authorities require an exact IAM role ARN and immutable role ID")
		}
		a.awsRole, a.key.Principal = r, entry.AWSRole
		if entry.Role == publisherAdmin && entry.KeyID == "" && len(entry.PublicKey) == 0 {
			return a, nil
		}
		k, err := arn.Parse(entry.KeyID)
		if err != nil || k.Partition != r.Partition || k.Service != "kms" || !awsRegion.MatchString(k.Region) ||
			!accountID.MatchString(k.AccountID) || !kmsKeyName.MatchString(k.Resource) {
			return authority{}, invalidInput("AWS signing authorities require an exact KMS key ARN, not an alias")
		}
	}
	key, err := x509.ParsePKIXPublicKey(entry.PublicKey)
	pub, ok := key.(*ecdsa.PublicKey)
	if err != nil || !ok || pub.Curve != elliptic.P256() {
		return authority{}, invalidInput("authority public_key_pkix must contain a base64 PKIX P-256 key")
	}
	a.key.ID, a.key.PublicKey = entry.KeyID, pub
	return a, nil
}

func lastSegment(path string) string {
	return path[strings.LastIndexByte(path, '/')+1:]
}

func (a authority) matchesAWS(id *sts.GetCallerIdentityOutput) bool {
	caller, err := arn.Parse(aws.ToString(id.Arn))
	if err != nil || caller.Service != "sts" || caller.Region != "" || caller.Partition != a.awsRole.Partition ||
		caller.AccountID != a.awsRole.AccountID || aws.ToString(id.Account) != a.awsRole.AccountID {
		return false
	}
	prefix := "assumed-role/" + lastSegment(a.awsRole.Resource) + "/"
	session, ok := strings.CutPrefix(caller.Resource, prefix)
	return ok && session != "" && !strings.Contains(session, "/") && aws.ToString(id.UserId) == a.awsRoleID+":"+session
}

func (o *controlOptions) connect(ctx context.Context, cmd *cobra.Command, role string) (controlSession, error) {
	for _, name := range [...]string{"registry", "bucket", "bucket-owner", "region"} {
		if cmd.Flags().Changed(name) {
			return controlSession{}, invalidInput("control scope and storage come exclusively from --config")
		}
	}
	var d deploymentConfig
	if err := readInput(o.config, &d); err != nil {
		return controlSession{}, err
	}
	local := o.global.endpoint != ""
	if o.global.localKey != "" && (!local || role == "") {
		return controlSession{}, invalidInput("--local-key is for authorized loopback mutations only")
	}
	service, authorities, err := d.validate(local)
	if err != nil {
		return controlSession{}, err
	}
	connection := options{region: d.Destination.Region, account: d.Destination.Owner, endpoint: o.global.endpoint}
	cfg, err := connection.awsConfig(ctx)
	if err != nil {
		return controlSession{}, err
	}
	var actor rollout.Identity
	if role != "" {
		actor, err = o.bindAuthority(ctx, &cfg, authorities, role, d.GitHub)
		if err != nil {
			return controlSession{}, err
		}
	}
	session := controlSession{service: service, actor: actor, publication: d.Publication, endpoint: o.global.endpoint, cfg: &cfg}
	session.service.Store = d.Destination.store(cfg, session.endpoint)
	if role == recovererRole {
		target, err := session.targetRegistry()
		if err != nil {
			return controlSession{}, err
		}
		plugin := d.Scope.Plugin
		session.service.VerifyRelease = func(ctx context.Context, ref rollout.Ref) error {
			_, _, err := target.Fetch(ctx, plugin, ref.Version, ref.Digest)
			return err
		}
	}
	return session, nil
}

func (o *controlOptions) bindAuthority(ctx context.Context, cfg *aws.Config, authorities []authority, role string, github *githubDeployment) (rollout.Identity, error) {
	if o.global.endpoint != "" {
		key, err := localSigningKey(o.global.localKey)
		if err != nil {
			return rollout.Identity{}, err
		}
		for _, a := range authorities {
			if a.role == role && key.PublicKey.Equal(a.key.PublicKey) {
				return rollout.Identity{ID: a.key.ID, Sign: signLocal(key)}, nil
			}
		}
		return rollout.Identity{}, registry.ErrDenied
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return rollout.Identity{}, err
	}
	if creds.SessionToken == "" {
		return rollout.Identity{}, fmt.Errorf("%w: AWS control mutations require short-lived role credentials", registry.ErrDenied)
	}
	// The same credential must identify the actor, write S3, and sign in KMS.
	cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return creds, nil })
	id, err := sts.NewFromConfig(*cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return rollout.Identity{}, err
	}
	for _, a := range authorities {
		if a.role != role || !a.matchesAWS(id) {
			continue
		}
		var provenance *rollout.Provenance
		if role != renewerRole {
			_, session, _ := strings.Cut(aws.ToString(id.UserId), ":")
			provenance, err = github.evidence(ctx, session, role)
			if err != nil {
				return rollout.Identity{}, err
			}
		}
		if role == publisherAdmin {
			return rollout.Identity{Provenance: provenance}, nil // No separate KMS signing for a binding CAS.
		}
		kmsConfig := *cfg
		keyARN, _ := arn.Parse(a.key.ID) // Parsed and checked at configuration load.
		kmsConfig.Region = keyARN.Region
		return rollout.Identity{ID: a.key.ID, Sign: kmsSigner(kmsConfig, a.key.ID), Provenance: provenance}, nil
	}
	return rollout.Identity{}, registry.ErrDenied
}
