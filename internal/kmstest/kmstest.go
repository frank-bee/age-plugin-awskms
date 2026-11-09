// Package kmstest provides an in-memory fake of the KMS and STS operations
// used by age-plugin-awskms, both as Go interfaces and as an HTTP server that
// speaks the AWS wire protocols (for end-to-end tests through the real SDK).
package kmstest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// Example account and region, as used in AWS documentation.
const (
	Account = "111122223333"
	Region  = "us-east-1"
)

// Key is a fake KMS key.
type Key struct {
	ARN     string
	Alias   string
	Private *rsa.PrivateKey
	Usage   types.KeyUsageType
	Denied  bool // kms:Decrypt returns AccessDeniedException
}

// KMS is a fake KMS and STS backend.
type KMS struct {
	mu     sync.Mutex
	keys   []*Key
	Caller string // account returned by sts:GetCallerIdentity

	decryptCalls int
	// Tamper, if set, alters plaintexts returned by Decrypt.
	Tamper func([]byte) []byte
}

// New returns a fake whose caller is Account.
func New() *KMS { return &KMS{Caller: Account} }

// AddKey creates an RSA key with the given size and alias ("" for none).
func (f *KMS) AddKey(bits int, alias string) *Key {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return f.AddExistingKey(priv, NewARN(Account, len(f.keys)), alias)
}

// AddExistingKey registers priv under arn.
func (f *KMS) AddExistingKey(priv *rsa.PrivateKey, arn, alias string) *Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := &Key{ARN: arn, Alias: alias, Private: priv, Usage: types.KeyUsageTypeEncryptDecrypt}
	f.keys = append(f.keys, k)
	return k
}

// NewARN returns a deterministic key ARN in account.
func NewARN(account string, n int) string {
	return fmt.Sprintf("arn:aws:kms:%s:%s:key/%08x-0000-4000-8000-000000000000", Region, account, n+1)
}

func (f *KMS) lookup(id string) *Key {
	for _, k := range f.keys {
		if id == k.ARN || (k.Alias != "" && (id == k.Alias ||
			id == fmt.Sprintf("arn:aws:kms:%s:%s:%s", Region, Account, k.Alias))) {
			return k
		}
	}
	return nil
}

func apiError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code}
}

// Keys returns the registered keys.
func (f *KMS) Keys() []*Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys)
}

// DecryptCalls returns and resets the number of kms:Decrypt calls.
func (f *KMS) DecryptCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.decryptCalls
	f.decryptCalls = 0
	return n
}

// SetDenied makes kms:Decrypt on k fail with AccessDeniedException.
func (f *KMS) SetDenied(k *Key, denied bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k.Denied = denied
}

// GetPublicKey implements awskms.KMSAPI.
func (f *KMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.lookup(aws.ToString(in.KeyId))
	if k == nil {
		return nil, apiError("NotFoundException")
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.Private.PublicKey)
	if err != nil {
		return nil, err
	}
	out := &kms.GetPublicKeyOutput{
		KeyId: aws.String(k.ARN), PublicKey: spki, KeyUsage: k.Usage,
		KeySpec: types.KeySpec(fmt.Sprintf("RSA_%d", k.Private.N.BitLen())),
	}
	if k.Usage == types.KeyUsageTypeEncryptDecrypt {
		out.EncryptionAlgorithms = []types.EncryptionAlgorithmSpec{
			types.EncryptionAlgorithmSpecRsaesOaepSha1, types.EncryptionAlgorithmSpecRsaesOaepSha256,
		}
	}
	return out, nil
}

// Decrypt implements awskms.KMSAPI.
func (f *KMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decryptCalls++
	k := f.lookup(aws.ToString(in.KeyId))
	switch {
	case k == nil:
		return nil, apiError("NotFoundException")
	case k.Denied:
		return nil, apiError("AccessDeniedException")
	case in.EncryptionAlgorithm != types.EncryptionAlgorithmSpecRsaesOaepSha256:
		return nil, apiError("InvalidCiphertextException")
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), nil, k.Private, in.CiphertextBlob, nil)
	if err != nil {
		return nil, apiError("InvalidCiphertextException")
	}
	if f.Tamper != nil {
		pt = f.Tamper(pt)
	}
	return &kms.DecryptOutput{KeyId: aws.String(k.ARN), Plaintext: pt,
		EncryptionAlgorithm: in.EncryptionAlgorithm}, nil
}

// GetCallerIdentity implements awskms.STSAPI.
func (f *KMS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.Caller),
		Arn: aws.String("arn:aws:iam::" + f.Caller + ":user/test"), UserId: aws.String("AIDATEST")}, nil
}

// ServeHTTP speaks the KMS (JSON 1.1) and STS (query) protocols, for use
// with AWS_ENDPOINT_URL_KMS and AWS_ENDPOINT_URL_STS.
func (f *KMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	target := r.Header.Get("X-Amz-Target")
	if target == "" {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "GetCallerIdentity" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		out, _ := f.GetCallerIdentity(ctx, nil)
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">`+
			`<GetCallerIdentityResult><Arn>%s</Arn><UserId>%s</UserId><Account>%s</Account></GetCallerIdentityResult>`+
			`<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>`+
			`</GetCallerIdentityResponse>`, *out.Arn, *out.UserId, *out.Account)
		return
	}
	var in struct {
		KeyId               string
		CiphertextBlob      []byte
		EncryptionAlgorithm string
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, "SerializationException")
		return
	}
	var resp any
	var err error
	switch strings.TrimPrefix(target, "TrentService.") {
	case "GetPublicKey":
		var out *kms.GetPublicKeyOutput
		out, err = f.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &in.KeyId})
		if err == nil {
			resp = map[string]any{"KeyId": out.KeyId, "PublicKey": out.PublicKey, "KeyUsage": out.KeyUsage,
				"KeySpec": out.KeySpec, "EncryptionAlgorithms": out.EncryptionAlgorithms}
		}
	case "Decrypt":
		var out *kms.DecryptOutput
		out, err = f.Decrypt(ctx, &kms.DecryptInput{KeyId: &in.KeyId, CiphertextBlob: in.CiphertextBlob,
			EncryptionAlgorithm: types.EncryptionAlgorithmSpec(in.EncryptionAlgorithm)})
		if err == nil {
			resp = map[string]any{"KeyId": out.KeyId, "Plaintext": base64.StdEncoding.EncodeToString(out.Plaintext),
				"EncryptionAlgorithm": out.EncryptionAlgorithm}
		}
	default:
		err = apiError("UnsupportedOperationException")
	}
	if err != nil {
		var apiErr smithy.APIError
		code := "InternalException"
		if errors.As(err, &apiErr) {
			code = apiErr.ErrorCode()
		}
		writeJSONError(w, code)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": code})
}
