# age-plugin-awskms

An [age](https://age-encryption.org) plugin that encrypts to asymmetric RSA
keys in [AWS KMS](https://aws.amazon.com/kms/).

- **Encryption is offline.** A recipient contains the key's public half, so
  devices, build jobs or anyone else can encrypt without AWS credentials or
  network access.
- **Decryption is controlled by IAM.** There are no private key files to
  distribute or leak. Whoever may call `kms:Decrypt` on the key can decrypt,
  and every decryption is logged in CloudTrail.
- **Your data stays local.** Only the wrapped 16-byte file key (a few hundred
  bytes) is sent to KMS. The payload is encrypted and decrypted by age on
  your machine.
- **It's just age.** Use the standard `age` CLI, mix KMS recipients with
  X25519, SSH or other plugin recipients, and stream files of any size.

```sh
age -r age1awskms1... -o backup.tar.age backup.tar     # offline
age -d -j awskms -o backup.tar backup.tar.age          # calls kms:Decrypt
```

## Install

You need [age](https://github.com/FiloSottile/age) v1.2.1 or later (older
versions are affected by a [plugin name vulnerability](https://github.com/FiloSottile/age/security/advisories/GHSA-32gq-x56h-299c);
v1.3.2 is tested) and the
`age-plugin-awskms` binary in your `PATH`.

**Homebrew (macOS)**

```sh
brew install frank-bee/tap/age-plugin-awskms
```

The binaries are not yet signed or notarized by Apple. So that macOS runs the
plugin when age starts it, the cask removes the quarantine attribute after
installing. Homebrew verifies the download against the checksum in the tap
first. If you prefer to keep Gatekeeper in the loop, install with Go instead.

**Pre-built binaries** for macOS, Linux and Windows (amd64, arm64) are on the
[releases page](https://github.com/frank-bee/age-plugin-awskms/releases).
Verify the archive against `SHA256SUMS`, then put `age-plugin-awskms`
(`age-plugin-awskms.exe` on Windows) somewhere in your `PATH`.

**Go**

```sh
go install github.com/frank-bee/age-plugin-awskms@latest
```

## Quick start

### 1. Create a KMS key

The key must be an RSA key (`RSA_2048`, `RSA_3072` or `RSA_4096`) with key
usage `ENCRYPT_DECRYPT`. RSA-3072 or larger is recommended.

```sh
aws kms create-key --key-spec RSA_3072 --key-usage ENCRYPT_DECRYPT \
    --description "age-plugin-awskms"
aws kms create-alias --alias-name alias/age --target-key-id <KeyId from above>
```

### 2. Get the recipient

```sh
age-plugin-awskms -recipient -key alias/age > recipient.txt
```

This calls `kms:GetPublicKey`, then checks a full `kms:Decrypt` round trip so
a wrong key is caught before anything is encrypted to it. If the principal may
only read the public key, add `-no-verify`.

The recipient (`age1awskms1...`) is public. It is long because it contains the
RSA public key; that is what makes encryption work offline. It always names
the concrete key ARN, even when you pass an alias.

### 3. Encrypt

```sh
age -R recipient.txt -o secrets.tar.age secrets.tar
```

No AWS access is needed. You can add more recipients, for example a break-glass
X25519 key kept offline:

```sh
age-keygen -o break-glass.txt        # store this file offline
age -R recipient.txt -r <public key printed by age-keygen> \
    -o secrets.tar.age secrets.tar
```

### 4. Decrypt

```sh
aws sso login            # or any other way of getting AWS credentials
age -d -j awskms -o secrets.tar secrets.tar.age
```

`-j awskms` uses the plugin without an identity file. The key ARN is read from
the file itself, so decryption keeps working after you move an alias to a new
key.

The region comes from the key ARN in the file. Credentials come from the
standard AWS SDK chain: environment variables,
`AWS_PROFILE`, SSO, web identity (EKS IRSA, GitHub Actions OIDC), container
and instance roles.

## Which keys may be used for decryption

An encrypted file names the KMS key to call. Without a restriction, a crafted
file could make you call `kms:Decrypt` on a key in someone else's account. That
would not reveal your data, but it would put your principal ARN into their
CloudTrail. The plugin therefore limits the accounts it will call:

- With `age -j awskms`, only keys in the **account of your current
  credentials** (found with `sts:GetCallerIdentity`, which needs no
  permissions) are used.
- For keys in other accounts (for example a central security account), create
  an identity file:

```sh
age-plugin-awskms -identity -allow-account 111122223333 -allow-account 444455556666 > awskms.txt
age -d -i awskms.txt -o secrets.tar secrets.tar.age
```

`-allow-any-account` disables the check. Skipped keys are reported, so you can
tell why no identity matched.

The current account is looked up with `sts:GetCallerIdentity` in your
configured region, or `us-east-1` if none is set; in the China and GovCloud
partitions, set `AWS_REGION`. A key this identity may not use (disallowed
account, access denied, disabled key) does not stop age: the reason is shown
and the next identity is tried. One file triggers at most 8 `kms:Decrypt`
calls and gives up after 2 minutes.

Identity files contain **no secret**, only these options, and can be shared or
committed. Access is always decided by IAM and the key policy. The `-key`
option only selects the key for encryption; it does not restrict decryption.

## Encrypting without a recipient string

When the encrypting side has AWS access, it can let the plugin fetch the
public key itself:

```sh
AGE_AWSKMS_KEY_ID=alias/age age -e -j awskms -o file.age file
```

or store the key in an identity file and use it in both directions:

```sh
age-plugin-awskms -identity -key alias/age > awskms.txt
age -e -i awskms.txt -o file.age file
age -d -i awskms.txt -o file file.age
```

This calls `kms:GetPublicKey` on every encryption. For offline or high-volume
encryption, use the recipient string.

## IAM permissions

Decrypting:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": [
    "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "arn:aws:kms:us-west-2:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321"
  ],
  "Condition": {
    "StringEquals": { "kms:EncryptionAlgorithm": "RSAES_OAEP_SHA_256" }
  }
}
```

List every key whose files must stay readable, including old keys kept after
rotation. Avoid `key/*`: the plugin restricts accounts, not keys, so a wildcard
would let a crafted file make you decrypt with any RSA key the principal can
use. For a key in another account, its key policy must also allow your
principal.

Creating recipients needs `kms:GetPublicKey` (and `kms:Decrypt` unless you use
`-no-verify`). Encrypting with a recipient string needs nothing.

Use `-profile NAME` on `age-plugin-awskms -recipient`, or put it into an
identity with `-identity -profile NAME`, to select a shared config profile
explicitly. Otherwise `AWS_PROFILE` applies.

## Key rotation

KMS cannot rotate asymmetric keys automatically. To rotate, create a new key,
move the alias and publish a new recipient. Files always record the key ARN
they were encrypted to, so **keep old keys enabled** as long as files
encrypted to them must remain readable. A key that is disabled or pending
deletion cannot decrypt; during the waiting period you can still cancel the
deletion and re-enable the key. Once the key is deleted, every file encrypted
only to that key is permanently undecryptable.

Multi-Region keys (`mrk-...`) work, but decryption always calls the region
recorded in the file; there is no automatic failover to a replica. If you need
regional recovery, add a second recipient for the replica's ARN.

## How it works

age encrypts each file with a random 16-byte file key and stores that key in
the header, wrapped once per recipient. This plugin wraps it with
RSAES-OAEP-SHA-256 under the KMS key's public key and writes the stanza

```
-> awskms arn:aws:kms:<region>:<account>:key/<key-id>
<base64 of the RSA-OAEP ciphertext>
```

To decrypt, the plugin sends that ciphertext to `kms:Decrypt` with
`RSAES_OAEP_SHA_256` and checks that the response is a 16-byte key from the
same key ARN. age then verifies the header MAC and decrypts the payload
locally.

| Encoding | Content |
| --- | --- |
| `age1awskms1...` | version, key ARN and DER public key (Bech32) |
| `AGE-PLUGIN-AWSKMS-1...` | optional JSON options: `accounts`, `key`, `profile` |
| stanza `awskms` | key ARN, RSA-OAEP-SHA-256 wrapped file key |

## Security notes

- **No sender authentication.** Like all age recipients, anyone with the
  recipient can create files for it. A file being decryptable does not prove
  who created it. Sign files separately if that matters.
- **Not post-quantum.** RSA-OAEP protects the file key. An attacker who stores
  files today and later breaks RSA could recover their contents.
- **Who can decrypt** is exactly who can call `kms:Decrypt` on the key: review
  the key policy and IAM, including administrators.
- **Distribute recipients over a trusted channel.** A recipient is public but
  not self-authenticating: someone who swaps it for their own RSA key (keeping
  your ARN) receives your data, and offline encryption cannot notice. The
  same applies to identity files, which choose the profile and allowed
  accounts. Where you have AWS access, regenerate a recipient with
  `age-plugin-awskms -recipient -key ARN` and compare; protect distributed copies.
- age authenticates each chunk before writing it, but if decryption fails
  midway the output is incomplete. Use it only after age exits successfully.

## Use as a Go library

Package [`awskms`](https://pkg.go.dev/github.com/frank-bee/age-plugin-awskms/awskms)
provides the recipient and identity as regular `age.Recipient` and
`age.Identity` values, for programs that use the age library directly:

```go
r, err := awskms.ParseRecipient("age1awskms1...")
w, err := age.Encrypt(out, r)
```

## Development

```sh
go test ./...
```

The tests use an in-memory fake of KMS and STS. `TestEndToEnd` runs the real
`age` binary against the plugin and the fake through the AWS SDK; it is skipped
if `age` is not in your `PATH`.

Releases are made by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org) and built
with [GoReleaser](https://goreleaser.com).

## License

[BSD-3-Clause](LICENSE)
