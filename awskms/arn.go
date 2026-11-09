package awskms

import (
	"fmt"
	"regexp"
)

// keyARNPattern matches a KMS key ARN (not an alias ARN) in any AWS partition.
// Multi-Region keys use the "mrk-" key ID prefix.
var keyARNPattern = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-[a-z]|aws-eusc):kms:` +
	`([a-z]{2,4}(?:-[a-z]+)+-\d+):(\d{12}):key/` +
	`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

// aliasARNPattern matches a KMS alias ARN, capturing the region.
var aliasARNPattern = regexp.MustCompile(`^arn:[a-z-]+:kms:([a-z0-9-]+):\d{12}:alias/[A-Za-z0-9/_-]+$`)

// KeyARN is a parsed KMS key ARN.
type KeyARN struct {
	Partition string
	Region    string
	Account   string
	KeyID     string
}

// ParseKeyARN parses and validates a full KMS key ARN. Aliases, bare key IDs
// and alias ARNs are rejected: archives must always name a concrete key.
func ParseKeyARN(s string) (KeyARN, error) {
	m := keyARNPattern.FindStringSubmatch(s)
	if m == nil {
		return KeyARN{}, fmt.Errorf("not a valid KMS key ARN: %q", s)
	}
	return KeyARN{Partition: m[1], Region: m[2], Account: m[3], KeyID: m[4]}, nil
}

func (a KeyARN) String() string {
	return "arn:" + a.Partition + ":kms:" + a.Region + ":" + a.Account + ":key/" + a.KeyID
}
