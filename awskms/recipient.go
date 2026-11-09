// Package awskms implements age recipients and identities backed by
// asymmetric RSA keys in AWS Key Management Service.
//
// Encryption is fully offline: a Recipient carries the key ARN and its RSA
// public key, and wraps age's random file key with RSAES-OAEP-SHA-256.
// Decryption sends only the wrapped file key (a few hundred bytes) to
// kms:Decrypt; the private key never leaves KMS and the payload never leaves
// the local machine.
package awskms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// PluginName is the age plugin name. Recipients are encoded as age1awskms1...
// and identities as AGE-PLUGIN-AWSKMS-1..., and age runs age-plugin-awskms.
const PluginName = "awskms"

// StanzaType is the age header stanza type. The single argument is the key
// ARN; the body is the RSAES_OAEP_SHA_256 ciphertext of the 16-byte file key.
const StanzaType = "awskms"

const recipientVersion = 1

// Recipient wraps age file keys for a KMS RSA key, without contacting AWS.
type Recipient struct {
	arn KeyARN
	pub *rsa.PublicKey
}

var _ age.Recipient = (*Recipient)(nil)

// NewRecipient builds a Recipient from a key ARN and the DER-encoded
// SubjectPublicKeyInfo returned by kms:GetPublicKey.
func NewRecipient(keyARN string, spki []byte) (*Recipient, error) {
	arn, err := ParseKeyARN(keyARN)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("KMS key is not an RSA key")
	}
	switch pub.N.BitLen() {
	case 2048, 3072, 4096:
	default:
		return nil, fmt.Errorf("unsupported RSA key size %d (want 2048, 3072 or 4096)", pub.N.BitLen())
	}
	if pub.E != 65537 {
		return nil, errors.New("unsupported RSA public exponent")
	}
	return &Recipient{arn: arn, pub: pub}, nil
}

// KeyARN returns the ARN of the KMS key this recipient encrypts to.
func (r *Recipient) KeyARN() string { return r.arn.String() }

// Wrap implements age.Recipient.
func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if len(fileKey) != 16 {
		return nil, errors.New("unexpected file key length")
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, fileKey, nil)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{Type: StanzaType, Args: []string{r.arn.String()}, Body: wrapped}}, nil
}

// String returns the recipient encoding, age1awskms1...
func (r *Recipient) String() string {
	spki, err := x509.MarshalPKIXPublicKey(r.pub)
	if err != nil {
		panic("awskms: cannot marshal RSA public key: " + err.Error())
	}
	arn := r.arn.String()
	data := []byte{recipientVersion}
	data = binary.AppendUvarint(data, uint64(len(arn)))
	data = append(data, arn...)
	data = append(data, spki...)
	return plugin.EncodeRecipient(PluginName, data)
}

// ParseRecipient parses an age1awskms1... recipient string.
func ParseRecipient(s string) (*Recipient, error) {
	name, data, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, err
	}
	if name != PluginName {
		return nil, fmt.Errorf("not an %s recipient", PluginName)
	}
	return parseRecipientData(data)
}

func parseRecipientData(data []byte) (*Recipient, error) {
	if len(data) < 2 || data[0] != recipientVersion {
		return nil, errors.New("unsupported or malformed awskms recipient")
	}
	n, k := binary.Uvarint(data[1:])
	if k <= 0 || n > 256 || uint64(len(data)-1-k) < n {
		return nil, errors.New("malformed awskms recipient")
	}
	arn := string(data[1+k : 1+k+int(n)])
	return NewRecipient(arn, data[1+k+int(n):])
}
