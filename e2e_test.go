package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/frank-bee/age-plugin-awskms/internal/kmstest"
)

// TestEndToEnd drives the real age CLI, which runs this plugin as a separate
// process, which talks to a fake KMS/STS through the real AWS SDK. It needs
// an age binary (AGE_BIN or "age" in PATH) and is skipped otherwise.
func TestEndToEnd(t *testing.T) {
	ageBin := os.Getenv("AGE_BIN")
	if ageBin == "" {
		var err error
		if ageBin, err = exec.LookPath("age"); err != nil {
			t.Skip("age not found; install it or set AGE_BIN")
		}
	}
	if testing.Short() {
		t.Skip("short mode")
	}

	dir := t.TempDir()
	exe := "age-plugin-awskms"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, exe), ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building plugin: %v\n%s", err, out)
	}

	fake := kmstest.New()
	key := fake.AddKey(3072, "alias/e2e")
	srv := httptest.NewServer(fake)
	defer srv.Close()

	home := t.TempDir()
	env := []string{
		"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home, "USERPROFILE=" + home,
		"AWS_ACCESS_KEY_ID=AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY=example",
		"AWS_REGION=" + kmstest.Region,
		"AWS_CONFIG_FILE=" + filepath.Join(home, "none"),
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(home, "none"),
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_ENDPOINT_URL_KMS=" + srv.URL,
		"AWS_ENDPOINT_URL_STS=" + srv.URL,
	}
	if root := os.Getenv("SYSTEMROOT"); root != "" {
		env = append(env, "SYSTEMROOT="+root)
	}
	run := func(extraEnv []string, name string, args ...string) (string, string, error) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = append(append([]string{}, env...), extraEnv...)
		cmd.Dir = dir
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	plugin := filepath.Join(dir, exe)
	plain := write("plain.txt", "end to end\n")

	// 1. Generate and verify a recipient.
	recipient, stderr, err := run(nil, plugin, "-recipient", "-key", "alias/e2e")
	if err != nil {
		t.Fatalf("-recipient: %v\n%s", err, stderr)
	}
	recipient = strings.TrimSpace(recipient)
	if !strings.HasPrefix(recipient, "age1awskms1") || !strings.Contains(stderr, key.ARN) {
		t.Fatalf("recipient %q, stderr %q", recipient, stderr)
	}

	// 2. Encrypting to the recipient is offline: point the SDK nowhere.
	offline := []string{"AWS_ENDPOINT_URL_KMS=http://127.0.0.1:1", "AWS_ENDPOINT_URL_STS=http://127.0.0.1:1"}
	fake.DecryptCalls()
	if _, stderr, err := run(offline, ageBin, "-r", recipient, "-o", "a.age", plain); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, stderr)
	}

	// 3. Decrypt with the data-less identity (age -j awskms).
	if _, stderr, err := run(nil, ageBin, "-d", "-j", "awskms", "-o", "a.txt", "a.age"); err != nil {
		t.Fatalf("decrypt -j: %v\n%s", err, stderr)
	}
	if calls := fake.DecryptCalls(); read("a.txt") != "end to end\n" || calls != 1 {
		t.Fatalf("plaintext %q, kms:Decrypt calls %d", read("a.txt"), calls)
	}

	// 4. Encrypt with -e -j and AGE_AWSKMS_KEY_ID, decrypt with an identity file.
	if _, stderr, err := run([]string{"AGE_AWSKMS_KEY_ID=alias/e2e"}, ageBin, "-e", "-j", "awskms", "-o", "b.age", plain); err != nil {
		t.Fatalf("encrypt -e -j: %v\n%s", err, stderr)
	}
	idOut, _, err := run(nil, plugin, "-identity", "-allow-account", kmstest.Account)
	if err != nil {
		t.Fatal(err)
	}
	idFile := write("identity.txt", idOut)
	if _, stderr, err := run(nil, ageBin, "-d", "-i", idFile, "-o", "b.txt", "b.age"); err != nil {
		t.Fatalf("decrypt -i: %v\n%s", err, stderr)
	}

	// 5. An identity restricted to another account must not call KMS.
	otherID, _, _ := run(nil, plugin, "-identity", "-allow-account", "444455556666")
	otherFile := write("other.txt", otherID)
	fake.DecryptCalls()
	_, stderr, err = run(nil, ageBin, "-d", "-i", otherFile, "-o", "c.txt", "a.age")
	if calls := fake.DecryptCalls(); err == nil || calls != 0 || !strings.Contains(stderr, "not allowed") {
		t.Fatalf("restricted identity: err=%v calls=%d\n%s", err, calls, stderr)
	}

	// 6. AWS errors are reported, not hidden.
	fake.SetDenied(key, true)
	_, stderr, err = run(nil, ageBin, "-d", "-j", "awskms", "-o", "d.txt", "a.age")
	fake.SetDenied(key, false)
	if err == nil || !strings.Contains(stderr, "AccessDeniedException") {
		t.Fatalf("denied: err=%v\n%s", err, stderr)
	}

	// 7. Mixed recipients: an X25519 identity decrypts without AWS.
	keygen, err := exec.LookPath("age-keygen")
	if err == nil {
		x, _, err := run(nil, keygen)
		if err != nil {
			t.Fatal(err)
		}
		xFile := write("x.txt", x)
		pub := ""
		for _, l := range strings.Split(x, "\n") {
			if strings.HasPrefix(l, "# public key: ") {
				pub = strings.TrimPrefix(l, "# public key: ")
			}
		}
		if _, stderr, err := run(offline, ageBin, "-r", recipient, "-r", pub, "-o", "m.age", plain); err != nil {
			t.Fatalf("mixed encrypt: %v\n%s", err, stderr)
		}
		if _, stderr, err := run(offline, ageBin, "-d", "-i", xFile, "-o", "m.txt", "m.age"); err != nil {
			t.Fatalf("mixed decrypt: %v\n%s", err, stderr)
		}
	}
}

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-recipient"}, &out, &errOut); code != 2 {
		t.Fatalf("missing -key: exit %d", code)
	}
	errOut.Reset()
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "Usage") {
		t.Fatalf("no args: exit %d", code)
	}
	out.Reset()
	if code := run([]string{"-identity", "-allow-account", "111122223333"}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "AGE-PLUGIN-AWSKMS-1") {
		t.Fatalf("identity: %q", out.String())
	}
	if code := run([]string{"-identity", "-allow-account", "12"}, &out, &errOut); code == 0 {
		t.Fatal("accepted invalid account")
	}
}
