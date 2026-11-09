package awskms

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// callTimeout bounds every individual AWS call.
const callTimeout = 30 * time.Second

// FetchRecipient resolves keyID (key ID, key ARN, alias name or alias ARN)
// with kms:GetPublicKey and returns an offline Recipient for the concrete key
// it points to. The key must be an RSA key with key usage ENCRYPT_DECRYPT that
// supports RSAES_OAEP_SHA_256.
func FetchRecipient(ctx context.Context, c *Clients, keyID string) (*Recipient, error) {
	if keyID == "" {
		return nil, errors.New("no KMS key specified")
	}
	region := ""
	if arn, err := ParseKeyARN(keyID); err == nil {
		region = arn.Region
	} else if r, ok := aliasARNRegion(keyID); ok {
		region = r
	}
	client, err := c.KMS(ctx, region)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, describeAWSError("kms:GetPublicKey", err)
	}
	if out.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("key usage is %s, want ENCRYPT_DECRYPT", out.KeyUsage)
	}
	if !slices.Contains(out.EncryptionAlgorithms, types.EncryptionAlgorithmSpecRsaesOaepSha256) {
		return nil, errors.New("key does not support RSAES_OAEP_SHA_256 (use an RSA_2048, RSA_3072 or RSA_4096 key)")
	}
	return NewRecipient(aws.ToString(out.KeyId), out.PublicKey)
}

// Verify checks that r and KMS agree: it wraps a random file key offline and
// unwraps it with kms:Decrypt. Run it before distributing a recipient, so a
// wrong or tampered public key is caught before anything is encrypted to it.
func Verify(ctx context.Context, c *Clients, r *Recipient) error {
	probe := make([]byte, 16)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	stanzas, err := r.Wrap(probe)
	if err != nil {
		return err
	}
	got, err := decryptStanza(ctx, c, r.arn, stanzas[0])
	if err != nil {
		return err
	}
	if !bytes.Equal(got, probe) {
		return errors.New("KMS round trip returned a different file key")
	}
	return nil
}

func decryptStanza(ctx context.Context, c *Clients, arn KeyARN, s *age.Stanza) ([]byte, error) {
	switch len(s.Body) {
	case 256, 384, 512: // RSA-2048, RSA-3072, RSA-4096
	default:
		return nil, errors.New("malformed awskms stanza: unexpected wrapped key length")
	}
	client, err := c.KMS(ctx, arn.Region)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(arn.String()),
		CiphertextBlob:      s.Body,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return nil, describeAWSError("kms:Decrypt", err)
	}
	if aws.ToString(out.KeyId) != arn.String() ||
		out.EncryptionAlgorithm != types.EncryptionAlgorithmSpecRsaesOaepSha256 ||
		len(out.Plaintext) != 16 {
		return nil, errors.New("unexpected kms:Decrypt response")
	}
	return out.Plaintext, nil
}

func aliasARNRegion(s string) (string, bool) {
	m := aliasARNPattern.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}
