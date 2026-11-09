// Command age-plugin-awskms is an age plugin for asymmetric RSA keys in AWS
// KMS. See README.md for usage.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/frank-bee/age-plugin-awskms/awskms"
)

// version is set by the release build.
var version = ""

const usage = `Usage:
    age-plugin-awskms -recipient -key KEY [-no-verify] [-profile NAME]
    age-plugin-awskms -identity [-allow-account ID]... [-allow-any-account]
                      [-key KEY] [-profile NAME]
    age-plugin-awskms -version

age plugin for asymmetric RSA keys in AWS Key Management Service.

  -recipient   Print the age1awskms1... recipient for KEY. Calls
               kms:GetPublicKey and, unless -no-verify, checks a
               kms:Decrypt round trip. Encrypting to the recipient is
               offline and needs no AWS access.
  -identity    Print an AGE-PLUGIN-AWSKMS-1... identity. Identities hold
               no secret, only options. Without options, "age -j awskms"
               is equivalent and needs no identity file.

  -key KEY              Key ID, key ARN, alias name (alias/NAME) or alias ARN.
  -allow-account ID     Allow keys in this AWS account (repeatable). By default
                        only keys in the account of the current credentials
                        are used for decryption.
  -allow-any-account    Allow keys in any AWS account.
  -profile NAME         AWS shared config profile to use.

Examples:
    $ age-plugin-awskms -recipient -key alias/backups > recipient.txt
    $ age -R recipient.txt -o secrets.tar.age secrets.tar
    $ age -d -j awskms -o secrets.tar secrets.tar.age

AWS credentials come from the standard SDK chain (environment, AWS_PROFILE,
SSO, web identity, container or instance roles), for example after
"aws sso login".
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	p, err := plugin.New(awskms.PluginName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fs := flag.NewFlagSet("age-plugin-awskms", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	p.RegisterFlags(fs)

	var (
		recipientFlag = fs.Bool("recipient", false, "")
		identityFlag  = fs.Bool("identity", false, "")
		versionFlag   = fs.Bool("version", false, "")
		noVerify      = fs.Bool("no-verify", false, "")
		allowAny      = fs.Bool("allow-any-account", false, "")
		key           = fs.String("key", "", "")
		profile       = fs.String("profile", "", "")
		accounts      stringList
	)
	fs.Var(&accounts, "allow-account", "")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if sm := fs.Lookup("age-plugin").Value.String(); sm != "" {
		return runPlugin(p)
	}

	switch {
	case *versionFlag:
		fmt.Fprintln(stdout, buildVersion())
		return 0
	case *recipientFlag && !*identityFlag:
		if *key == "" {
			fmt.Fprintln(stderr, "age-plugin-awskms: -recipient requires -key")
			return 2
		}
		return printRecipient(stdout, stderr, *key, *profile, !*noVerify)
	case *identityFlag && !*recipientFlag:
		opts := awskms.IdentityOptions{Accounts: accounts, Key: *key, Profile: *profile}
		if *allowAny {
			opts.Accounts = append(opts.Accounts, awskms.AnyAccount)
		}
		return printIdentity(stdout, stderr, opts)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func runPlugin(p *plugin.Plugin) int {
	newIdentity := func(data []byte) (*awskms.Identity, error) {
		opts, err := awskms.ParseIdentityOptions(data)
		if err != nil {
			return nil, err
		}
		return awskms.NewIdentity(opts, nil)
	}
	p.HandleRecipientEncoding(func(s string) (age.Recipient, error) {
		return awskms.ParseRecipient(s)
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		id, err := newIdentity(data)
		if err != nil {
			return nil, err
		}
		id.Warn = func(msg string) { _ = p.DisplayMessage(msg) }
		return id, nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		id, err := newIdentity(data)
		if err != nil {
			return nil, err
		}
		return id.Recipient(context.Background())
	})
	return p.Main()
}

func printRecipient(stdout, stderr io.Writer, key, profile string, verify bool) int {
	ctx := context.Background()
	clients := &awskms.Clients{Profile: profile}
	r, err := awskms.FetchRecipient(ctx, clients, key)
	if err != nil {
		fmt.Fprintf(stderr, "age-plugin-awskms: %v\n", err)
		return 1
	}
	if verify {
		if err := awskms.Verify(ctx, clients, r); err != nil {
			fmt.Fprintf(stderr, "age-plugin-awskms: round-trip verification failed: %v\n"+
				"(use -no-verify if this principal may only read the public key)\n", err)
			return 1
		}
	}
	fmt.Fprintf(stderr, "# key: %s\n", r.KeyARN())
	fmt.Fprintln(stdout, r.String())
	return 0
}

func printIdentity(stdout, stderr io.Writer, opts awskms.IdentityOptions) int {
	s, err := awskms.EncodeIdentity(opts)
	if err != nil {
		fmt.Fprintf(stderr, "age-plugin-awskms: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "# created: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(stdout, "# this identity contains no secret; access is controlled by AWS IAM")
	fmt.Fprintln(stdout, s)
	return 0
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
