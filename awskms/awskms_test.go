package awskms_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/frank-bee/age-plugin-awskms/awskms"
	"github.com/frank-bee/age-plugin-awskms/internal/kmstest"
)

func clientsFor(f *kmstest.KMS) *awskms.Clients {
	return &awskms.Clients{
		NewKMS: func(string) (awskms.KMSAPI, error) { return f, nil },
		NewSTS: func() (awskms.STSAPI, error) { return f, nil },
	}
}

func encrypt(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decrypt(archive []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(archive), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTripKeySizes(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		f := kmstest.New()
		f.AddKey(bits, "alias/test")
		c := clientsFor(f)
		r, err := awskms.FetchRecipient(context.Background(), c, "alias/test")
		if err != nil {
			t.Fatalf("RSA-%d: %v", bits, err)
		}
		archive := encrypt(t, []byte("hello"), r)
		id, err := awskms.NewIdentity(awskms.IdentityOptions{}, c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decrypt(archive, id)
		if err != nil || string(got) != "hello" {
			t.Fatalf("RSA-%d: got %q, %v", bits, got, err)
		}
	}
}

func TestRecipientEncoding(t *testing.T) {
	f := kmstest.New()
	k := f.AddKey(3072, "")
	r, err := awskms.FetchRecipient(context.Background(), clientsFor(f), k.ARN)
	if err != nil {
		t.Fatal(err)
	}
	s := r.String()
	if !strings.HasPrefix(s, "age1awskms1") {
		t.Fatalf("unexpected encoding %q", s)
	}
	parsed, err := awskms.ParseRecipient(s)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyARN() != k.ARN || parsed.String() != s {
		t.Fatal("recipient did not round-trip")
	}
	for _, bad := range []string{
		"age1yubikey1qwqsl9w8m9n5zzg4pl6n9l2m7c9zvl3r6dna7nsyqvh9nykgq0jjzklc6h",
		s[:len(s)-1] + flipped(s[len(s)-1]),
		"age1awskms1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
	} {
		if _, err := awskms.ParseRecipient(bad); err == nil {
			t.Errorf("accepted bad recipient %q", bad)
		}
	}
}

func TestRecipientRejectsUnsuitableKeys(t *testing.T) {
	f := kmstest.New()
	f.AddKey(1024, "alias/small")
	f.AddKey(2048, "alias/sign").Usage = types.KeyUsageTypeSignVerify
	c := clientsFor(f)
	for _, alias := range []string{"alias/small", "alias/sign", "alias/missing"} {
		if _, err := awskms.FetchRecipient(context.Background(), c, alias); err == nil {
			t.Errorf("%s: expected error", alias)
		}
	}
}

func TestParseKeyARN(t *testing.T) {
	good := []string{
		"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",
	}
	bad := []string{
		"arn:aws:kms:us-west-2:111122223333:alias/test",
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:us-west-2:1111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab/x",
		"arn:aws:s3:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
	}
	for _, s := range good {
		a, err := awskms.ParseKeyARN(s)
		if err != nil || a.String() != s {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := awskms.ParseKeyARN(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestAccountCheck(t *testing.T) {
	f := kmstest.New()
	own := f.AddKey(2048, "")
	foreignARN := kmstest.NewARN("444455556666", 7)
	foreign := f.AddExistingKey(own.Private, foreignARN, "")
	c := clientsFor(f)
	ctx := context.Background()

	rForeign, err := awskms.FetchRecipient(ctx, c, foreign.ARN)
	if err != nil {
		t.Fatal(err)
	}
	archive := encrypt(t, []byte("x"), rForeign)

	// Default: only the caller's account.
	var warnings []string
	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, c)
	id.Warn = func(m string) { warnings = append(warnings, m) }
	f.DecryptCalls()
	if _, err := decrypt(archive, id); err == nil {
		t.Fatal("decrypted with key from a foreign account")
	}
	if f.DecryptCalls() != 0 {
		t.Fatal("kms:Decrypt was called for a disallowed key")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "444455556666") {
		t.Fatalf("warnings = %q", warnings)
	}

	// Explicit allow-list and wildcard.
	for _, accounts := range [][]string{{"444455556666"}, {awskms.AnyAccount}} {
		id, _ := awskms.NewIdentity(awskms.IdentityOptions{Accounts: accounts}, c)
		if got, err := decrypt(archive, id); err != nil || string(got) != "x" {
			t.Fatalf("accounts %v: %q %v", accounts, got, err)
		}
	}

	// An explicit list replaces the caller default.
	rOwn, _ := awskms.FetchRecipient(ctx, c, own.ARN)
	id, _ = awskms.NewIdentity(awskms.IdentityOptions{Accounts: []string{"444455556666"}}, c)
	if _, err := decrypt(encrypt(t, []byte("x"), rOwn), id); err == nil {
		t.Fatal("explicit account list did not restrict")
	}
}

func TestMultipleRecipients(t *testing.T) {
	f := kmstest.New()
	denied := f.AddKey(2048, "alias/denied")
	f.AddKey(2048, "alias/ok")
	c := clientsFor(f)
	ctx := context.Background()
	r1, _ := awskms.FetchRecipient(ctx, c, "alias/denied")
	r2, _ := awskms.FetchRecipient(ctx, c, "alias/ok")
	x, _ := age.GenerateX25519Identity()
	archive := encrypt(t, []byte("multi"), r1, r2, x.Recipient())
	f.SetDenied(denied, true)

	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, c)
	if got, err := decrypt(archive, id); err != nil || string(got) != "multi" {
		t.Fatalf("got %q, %v", got, err)
	}
	// Other identities still work without touching AWS.
	f.DecryptCalls()
	got, err := decrypt(archive, x)
	if calls := f.DecryptCalls(); err != nil || string(got) != "multi" || calls != 0 {
		t.Fatalf("x25519: %q %v calls=%d", got, err, calls)
	}
}

func TestErrors(t *testing.T) {
	f := kmstest.New()
	k := f.AddKey(2048, "")
	c := clientsFor(f)
	r, _ := awskms.FetchRecipient(context.Background(), c, k.ARN)
	archive := encrypt(t, []byte("x"), r)
	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, c)
	var warnings []string
	id.Warn = func(m string) { warnings = append(warnings, m) }

	// Access denied is not a match: age may try other identities, and the
	// reason is reported as a warning.
	f.SetDenied(k, true)
	_, err := decrypt(archive, id)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) || len(warnings) != 1 || !strings.Contains(warnings[0], "AccessDeniedException") {
		t.Fatalf("denied: %v, warnings %q", err, warnings)
	}
	f.SetDenied(k, false)

	f.Tamper = func(b []byte) []byte { return b[:8] }
	if _, err := decrypt(archive, id); err == nil {
		t.Fatal("accepted a short file key")
	}
	f.Tamper = nil

	// Files without awskms stanzas are not ours.
	x, _ := age.GenerateX25519Identity()
	other := encrypt(t, []byte("x"), x.Recipient())
	if _, err := decrypt(other, id); !errors.As(err, &noMatch) {
		t.Fatalf("foreign file: %v", err)
	}

	// Malformed stanzas are errors, not silent skips.
	for _, s := range []*age.Stanza{
		{Type: awskms.StanzaType, Args: []string{}},
		{Type: awskms.StanzaType, Args: []string{"alias/test"}, Body: make([]byte, 256)},
		{Type: awskms.StanzaType, Args: []string{k.ARN}, Body: make([]byte, 100)},
	} {
		if _, err := id.Unwrap([]*age.Stanza{s}); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("stanza %v: %v", s.Args, err)
		}
	}
}

func TestVerify(t *testing.T) {
	f := kmstest.New()
	f.AddKey(2048, "alias/a")
	other := f.AddKey(2048, "alias/b")
	c := clientsFor(f)
	ctx := context.Background()
	r, _ := awskms.FetchRecipient(ctx, c, "alias/a")
	if err := awskms.Verify(ctx, c, r); err != nil {
		t.Fatal(err)
	}
	// A recipient whose public key does not belong to its ARN fails.
	spki, err := x509.MarshalPKIXPublicKey(&other.Private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := awskms.NewRecipient(r.KeyARN(), spki)
	if err != nil {
		t.Fatal(err)
	}
	if err := awskms.Verify(ctx, c, forged); err == nil {
		t.Fatal("verified a mismatched public key")
	}
}

func TestIdentityOptionsEncoding(t *testing.T) {
	opts := awskms.IdentityOptions{Accounts: []string{"111122223333"}, Key: "alias/x", Profile: "p"}
	s, err := awskms.EncodeIdentity(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "AGE-PLUGIN-AWSKMS-1") {
		t.Fatal(s)
	}
	zero, _ := awskms.EncodeIdentity(awskms.IdentityOptions{})
	if zero != "AGE-PLUGIN-AWSKMS-1KFS0D8" {
		t.Fatalf("zero identity = %s", zero)
	}
	for _, bad := range []awskms.IdentityOptions{
		{Accounts: []string{"123"}},
		{Accounts: []string{"*", "111122223333"}},
	} {
		if _, err := awskms.EncodeIdentity(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, data := range []string{`{"accounts":["1"]}`, `{"unknown":1}`, `{}{}`, `nope`} {
		if _, err := awskms.ParseIdentityOptions([]byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}

func TestIdentityAsRecipient(t *testing.T) {
	f := kmstest.New()
	f.AddKey(2048, "alias/enc")
	c := clientsFor(f)
	ctx := context.Background()

	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, c)
	t.Setenv(awskms.KeyEnv, "")
	if _, err := id.Recipient(ctx); err == nil {
		t.Fatal("expected error without key")
	}
	t.Setenv(awskms.KeyEnv, "alias/enc")
	r, err := id.Recipient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decrypt(encrypt(t, []byte("e"), r), id); err != nil || string(got) != "e" {
		t.Fatalf("%q %v", got, err)
	}
	withKey, _ := awskms.NewIdentity(awskms.IdentityOptions{Key: "alias/enc"}, c)
	t.Setenv(awskms.KeyEnv, "alias/other")
	if _, err := withKey.Recipient(ctx); err != nil {
		t.Fatal("identity key should take precedence over the environment:", err)
	}
}

func TestFallbackToNextIdentity(t *testing.T) {
	f := kmstest.New()
	k := f.AddKey(2048, "")
	r, _ := awskms.FetchRecipient(context.Background(), clientsFor(f), k.ARN)
	archive := encrypt(t, []byte("fallback"), r)

	// The first identity's credentials may not use the key; the second may.
	deniedKMS := kmstest.New()
	deniedKMS.AddExistingKey(k.Private, k.ARN, "")
	deniedKMS.SetDenied(deniedKMS.Keys()[0], true)
	first, _ := awskms.NewIdentity(awskms.IdentityOptions{}, clientsFor(deniedKMS))
	second, _ := awskms.NewIdentity(awskms.IdentityOptions{}, clientsFor(f))
	if got, err := decrypt(archive, first, second); err != nil || string(got) != "fallback" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDecryptCallBudget(t *testing.T) {
	f := kmstest.New()
	k := f.AddKey(2048, "")
	r, _ := awskms.FetchRecipient(context.Background(), clientsFor(f), k.ARN)
	stanzas, err := r.Wrap(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	f.SetDenied(k, true)
	id, _ := awskms.NewIdentity(awskms.IdentityOptions{}, clientsFor(f))

	// Identical stanzas are tried once.
	dup := []*age.Stanza{stanzas[0], stanzas[0], stanzas[0]}
	if _, err := id.Unwrap(dup); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatal(err)
	}
	if n := f.DecryptCalls(); n != 1 {
		t.Fatalf("duplicates: %d kms:Decrypt calls", n)
	}

	// Many distinct stanzas are capped.
	var many []*age.Stanza
	for range 50 {
		s, _ := r.Wrap(make([]byte, 16))
		many = append(many, s[0])
	}
	if _, err := id.Unwrap(many); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatal(err)
	}
	if n := f.DecryptCalls(); n > 8 {
		t.Fatalf("%d kms:Decrypt calls for one file", n)
	}

	// A malformed stanza anywhere fails before any AWS call.
	bad := append([]*age.Stanza{}, many[:3]...)
	bad = append(bad, &age.Stanza{Type: awskms.StanzaType, Args: []string{k.ARN}, Body: make([]byte, 100)})
	if _, err := id.Unwrap(bad); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("malformed: %v", err)
	}
	if n := f.DecryptCalls(); n != 0 {
		t.Fatalf("malformed: %d kms:Decrypt calls", n)
	}
}

func TestIdentityOptionsTrailingData(t *testing.T) {
	for _, data := range []string{`{}]`, `{}}`, `{} {}`, `{}x`} {
		if _, err := awskms.ParseIdentityOptions([]byte(data)); err == nil {
			t.Errorf("%q accepted", data)
		}
	}
	if _, err := awskms.ParseIdentityOptions([]byte(`{"accounts":["111122223333"]}` + "\n")); err != nil {
		t.Error(err)
	}
}

// flipped returns a Bech32 character different from c, so changing the
// checksum always invalidates it.
func flipped(c byte) string {
	if c == 'q' {
		return "p"
	}
	return "q"
}
