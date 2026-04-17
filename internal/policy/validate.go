package policy

import "regexp"

// Compiled once at package init. All regex use RE2 so they are linear-time
// and cannot be ReDoS'd from attacker-controlled input.

// validRolePattern accepts:
//   - a GCP primitive role (e.g. roles/owner, roles/viewer — no dot),
//   - a GCP predefined role (roles/<service>.<name>[.<more>]),
//   - a custom role under a project, organization, or billing account.
//
// Allowing dashes in the dotted suffix covers future GCP role names;
// anchors force a full match so trailing whitespace / newlines are rejected.
var validRolePattern = regexp.MustCompile(
	`^(roles/[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z0-9_\-]+)*|(projects|organizations|billingAccounts)/[a-zA-Z0-9][a-zA-Z0-9\-_\.]*/roles/[a-zA-Z][a-zA-Z0-9_\-\.]*)$`,
)

// validCustomRoleIDPattern is the intersection of what GCP accepts for a
// custom role id ([a-zA-Z0-9_]{3,64}) and what Terraform accepts for a
// resource address ([a-zA-Z_][a-zA-Z0-9_-]*). A leading letter keeps this
// safe for both positions.
var validCustomRoleIDPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{2,63}$`)

// IsValidRoleRef reports whether s is a well-formed GCP role reference.
// Used at two trust boundaries: user-edited roles in `review` and
// LLM/JSON-supplied roles at Terraform render time.
func IsValidRoleRef(s string) bool {
	return validRolePattern.MatchString(s)
}

// IsValidCustomRoleID reports whether s is safe to use as a GCP custom-role
// id AND as a Terraform resource address identifier.
func IsValidCustomRoleID(s string) bool {
	return validCustomRoleIDPattern.MatchString(s)
}
