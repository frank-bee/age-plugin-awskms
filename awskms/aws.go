package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// KMSAPI is the subset of the KMS client used by this package.
type KMSAPI interface {
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// STSAPI is the subset of the STS client used by this package.
type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Clients creates AWS clients lazily using the standard SDK credential chain
// (environment, shared config and SSO, web identity, container and instance
// roles). Nothing is loaded until the first AWS call is needed.
type Clients struct {
	// Profile selects a shared config profile. Empty uses the SDK default
	// (AWS_PROFILE or "default").
	Profile string

	// NewKMS and NewSTS override client construction, for tests.
	NewKMS func(region string) (KMSAPI, error)
	NewSTS func(region string) (STSAPI, error)

	once sync.Once
	cfg  aws.Config
	err  error
}

func (c *Clients) config(ctx context.Context) (aws.Config, error) {
	c.once.Do(func() {
		var opts []func(*config.LoadOptions) error
		if c.Profile != "" {
			opts = append(opts, config.WithSharedConfigProfile(c.Profile))
		}
		c.cfg, c.err = config.LoadDefaultConfig(ctx, opts...)
		if c.err != nil {
			c.err = fmt.Errorf("loading AWS configuration: %w", c.err)
		}
	})
	return c.cfg, c.err
}

// KMS returns a KMS client for region, or for the configured default region
// when region is empty.
func (c *Clients) KMS(ctx context.Context, region string) (KMSAPI, error) {
	if c.NewKMS != nil {
		return c.NewKMS(region)
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	if region == "" && cfg.Region == "" {
		return nil, errors.New("no AWS region configured; set AWS_REGION or use a full key ARN")
	}
	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		if region != "" {
			o.Region = region
		}
	}), nil
}

// STS returns an STS client. fallbackRegion is used when no default region is
// configured, so the caller's account can be resolved without extra setup.
func (c *Clients) STS(ctx context.Context, fallbackRegion string) (STSAPI, error) {
	if c.NewSTS != nil {
		return c.NewSTS(fallbackRegion)
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(cfg, func(o *sts.Options) {
		if o.Region == "" {
			o.Region = fallbackRegion
		}
	}), nil
}

// describeAWSError turns SDK errors into short messages with an actionable
// hint, without echoing arbitrary response data.
func describeAWSError(op string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s failed: timed out waiting for AWS", op)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		hint := ""
		switch {
		case code == "AccessDeniedException" || code == "AccessDenied":
			hint = " (check IAM and key policy permissions)"
		case code == "ExpiredTokenException" || code == "ExpiredToken" ||
			code == "UnrecognizedClientException" || code == "InvalidClientTokenId":
			hint = " (credentials expired or invalid; try 'aws sso login')"
		case code == "NotFoundException":
			hint = " (key not found in this account and region)"
		case code == "DisabledException" || code == "KMSInvalidStateException":
			hint = " (key is disabled or pending deletion)"
		}
		return fmt.Errorf("%s failed: %s%s", op, code, hint)
	}
	msg := err.Error()
	if strings.Contains(msg, "failed to retrieve credentials") ||
		strings.Contains(msg, "no EC2 IMDS role found") ||
		strings.Contains(msg, "token") && strings.Contains(msg, "expired") {
		return fmt.Errorf("%s failed: no valid AWS credentials (try 'aws sso login' or set AWS_PROFILE)", op)
	}
	return fmt.Errorf("%s failed: %w", op, err)
}
