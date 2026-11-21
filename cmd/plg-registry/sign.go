package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

func keyPEM(path, kind string) ([]byte, error) {
	data, err := boundedFile(path, 16<<10)
	if err == nil {
		block, rest := pem.Decode(data)
		if block != nil && block.Type == kind && len(bytes.TrimSpace(rest)) == 0 {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("%w: expected one PEM %s block", registry.ErrInvalid, kind)
}

func (o *options) checkKeyMode(id string) error {
	if o.endpoint != "" && strings.HasPrefix(id, "local:") ||
		o.endpoint == "" && strings.HasPrefix(id, "arn:") {
		return nil
	}
	return fmt.Errorf("%w: use a local signing key with --endpoint or an exact KMS key ARN with AWS", registry.ErrInvalid)
}

func (o *options) signer(ctx context.Context, cfg aws.Config, keyID, privateFile string) (registry.Signer, error) {
	if o.endpoint != "" {
		der, err := keyPEM(privateFile, "PRIVATE KEY")
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		signing, ok := key.(*ecdsa.PrivateKey)
		if err != nil || !ok || signing.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: expected a PKCS#8 P-256 private key", registry.ErrInvalid)
		}
		return func(_ context.Context, digest [sha256.Size]byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, signing, digest[:])
		}, nil
	}
	if privateFile != "" {
		return nil, fmt.Errorf("%w: --local-key is only usable with --endpoint", registry.ErrInvalid)
	}
	identity, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	// The SDK cannot infer an expiry for STS credentials injected by a CI
	// action. Those sessions still carry a token; AWS enforces their expiry.
	if !identity.CanExpire && identity.SessionToken == "" {
		return nil, fmt.Errorf("%w: publishing to AWS requires short-lived CI credentials", registry.ErrInvalid)
	}
	client := kms.NewFromConfig(cfg)
	return func(ctx context.Context, digest [sha256.Size]byte) ([]byte, error) {
		res, err := client.Sign(ctx, &kms.SignInput{
			KeyId: &keyID, Message: digest[:], MessageType: types.MessageTypeDigest,
			SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		})
		if err != nil {
			return nil, err
		}
		if aws.ToString(res.KeyId) != keyID || res.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
			return nil, registry.ErrDenied
		}
		return res.Signature, nil
	}, nil
}
