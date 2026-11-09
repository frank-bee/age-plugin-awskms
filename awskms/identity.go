package awskms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// KeyEnv names the environment variable that selects the KMS key when an
// identity without a configured key is used for encryption (age -e -j awskms).
const KeyEnv = "AGE_AWSKMS_KEY_ID"

// AnyAccount in IdentityOptions.Accounts allows keys in every AWS account.
const AnyAccount = "*"

var accountPattern = regexp.MustCompile(`^\d{12}$`)

// IdentityOptions is the (non-secret) configuration carried inside an
// AGE-PLUGIN-AWSKMS-1... identity. The zero value is the identity used by
// "age -j awskms".
type IdentityOptions struct {
	// Accounts lists the AWS account IDs whose keys this identity may call
	// kms:Decrypt on. Empty means only the account of the current
	// credentials (resolved with sts:GetCallerIdentity). AnyAccount ("*")
	// disables the check.
	//
	// The check matters because an archive names the key to call: without
	// it, a crafted file could make you call kms:Decrypt on a key in an
	// account controlled by someone else, revealing your principal ARN in
	// their CloudTrail.
	Accounts []string `json:"accounts,omitempty"`

	// Key is the key used when the identity encrypts (age -e -i FILE).
	// Empty falls back to the AGE_AWSKMS_KEY_ID environment variable.
	Key string `json:"key,omitempty"`

	// Profile selects an AWS shared config profile. Empty uses the SDK
	// default (AWS_PROFILE or "default").
	Profile string `json:"profile,omitempty"`
}

func (o IdentityOptions) validate() error {
	for _, a := range o.Accounts {
		if a != AnyAccount && !accountPattern.MatchString(a) {
			return fmt.Errorf("invalid AWS account ID %q", a)
		}
	}
	if len(o.Accounts) > 1 && slices.Contains(o.Accounts, AnyAccount) {
		return errors.New("account wildcard cannot be combined with account IDs")
	}
	return nil
}

func (o IdentityOptions) isZero() bool {
	return len(o.Accounts) == 0 && o.Key == "" && o.Profile == ""
}

// EncodeIdentity returns the AGE-PLUGIN-AWSKMS-1... encoding of o.
func EncodeIdentity(o IdentityOptions) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}
	if o.isZero() {
		return plugin.EncodeIdentity(PluginName, nil), nil
	}
	data, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return plugin.EncodeIdentity(PluginName, data), nil
}

// ParseIdentityOptions decodes the Bech32 payload of an identity.
func ParseIdentityOptions(data []byte) (IdentityOptions, error) {
	var o IdentityOptions
	if len(data) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return o, fmt.Errorf("malformed awskms identity: %w", err)
	}
	if dec.More() {
		return o, errors.New("malformed awskms identity: trailing data")
	}
	return o, o.validate()
}

// Identity unwraps awskms stanzas with kms:Decrypt.
type Identity struct {
	opts    IdentityOptions
	clients *Clients

	// Warn, if set, reports keys skipped by the account check, so the user
	// sees why no identity matched.
	Warn func(msg string)

	mu     sync.Mutex
	caller string
}

var _ age.Identity = (*Identity)(nil)

// NewIdentity returns an Identity using opts. If clients is nil, AWS clients
// are created from the standard SDK configuration.
func NewIdentity(opts IdentityOptions, clients *Clients) (*Identity, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if clients == nil {
		clients = &Clients{Profile: opts.Profile}
	}
	return &Identity{opts: opts, clients: clients}, nil
}

// Unwrap implements age.Identity.
func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ctx := context.Background()
	var lastErr error
	for _, s := range stanzas {
		if s.Type != StanzaType {
			continue
		}
		if len(s.Args) != 1 {
			return nil, errors.New("malformed awskms stanza")
		}
		arn, err := ParseKeyARN(s.Args[0])
		if err != nil {
			return nil, fmt.Errorf("malformed awskms stanza: %w", err)
		}
		ok, err := i.allowed(ctx, arn)
		if err != nil {
			return nil, err
		}
		if !ok {
			if i.Warn != nil {
				i.Warn(fmt.Sprintf("skipping %s: account %s is not allowed by this identity", arn, arn.Account))
			}
			continue
		}
		fileKey, err := decryptStanza(ctx, i.clients, arn, s)
		if err == nil {
			return fileKey, nil
		}
		lastErr = fmt.Errorf("%s: %w", arn, err)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *Identity) allowed(ctx context.Context, arn KeyARN) (bool, error) {
	switch {
	case slices.Contains(i.opts.Accounts, AnyAccount):
		return true, nil
	case len(i.opts.Accounts) > 0:
		return slices.Contains(i.opts.Accounts, arn.Account), nil
	}
	caller, err := i.callerAccount(ctx, arn.Region)
	if err != nil {
		return false, err
	}
	return caller == arn.Account, nil
}

func (i *Identity) callerAccount(ctx context.Context, region string) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.caller != "" {
		return i.caller, nil
	}
	client, err := i.clients.STS(ctx, region)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", describeAWSError("sts:GetCallerIdentity", err)
	}
	account := aws.ToString(out.Account)
	if !accountPattern.MatchString(account) {
		return "", errors.New("unexpected sts:GetCallerIdentity response")
	}
	i.caller = account
	return account, nil
}

// Recipient returns the recipient for encrypting with this identity: the
// configured key, or AGE_AWSKMS_KEY_ID. It calls kms:GetPublicKey.
func (i *Identity) Recipient(ctx context.Context) (*Recipient, error) {
	key := i.opts.Key
	if key == "" {
		key = os.Getenv(KeyEnv)
	}
	if key == "" {
		return nil, fmt.Errorf("no KMS key for encryption: create the identity with -key or set %s", KeyEnv)
	}
	return FetchRecipient(ctx, i.clients, key)
}
