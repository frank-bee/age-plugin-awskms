package awskms_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/frank-bee/age-plugin-awskms/awskms"
	"github.com/frank-bee/age-plugin-awskms/internal/kmstest"
)

const vectorARN = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-0000000000ff"

// TestVector decrypts an archive written by an earlier build, so that
// changes to the stanza or recipient format cannot slip in unnoticed.
func TestVector(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/testkey.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	f := kmstest.New()
	f.AddExistingKey(key.(*rsa.PrivateKey), vectorARN, "")

	archive, err := os.ReadFile("testdata/vector.age")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, clientsFor(f))
	got, err := decrypt(archive, id)
	if err != nil || string(got) != "age-plugin-awskms test vector\n" {
		t.Fatalf("got %q, %v", got, err)
	}

	recipient, err := os.ReadFile("testdata/recipient.txt")
	if err != nil {
		t.Fatal(err)
	}
	r, err := awskms.ParseRecipient(strings.TrimSpace(string(recipient)))
	if err != nil || r.KeyARN() != vectorARN {
		t.Fatalf("recipient: %v", err)
	}
}
