package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Scope defines where the IAM binding applies.
//
// Type is the coarse scope level. When Type == "resource" the binding is
// scoped to a single GCP resource below the project, and ResourceType picks
// which `google_*_iam_member` resource the Terraform renderer emits. The
// other fields (Project, Location, Parent) carry the extra attributes those
// resource types need beyond the primary ID — for example a BigQuery table
// binding needs Project + Parent (dataset_id) + ID (table_id), and a Cloud
// Run service binding needs Project + Location + ID.
type Scope struct {
	Type    string `json:"type"`    // "project", "folder", "organization", "resource"
	ID      string `json:"id"`      // primary identifier (project id, folder number, org id, dataset/bucket/topic/secret/service id)
	Display string `json:"display"` // human-readable label

	// ResourceType selects the narrowly-scoped IAM resource kind when
	// Type == "resource". One of: "bigquery_dataset", "bigquery_table",
	// "storage_bucket", "pubsub_topic", "secret_manager_secret",
	// "cloud_run_service". Empty when Type != "resource".
	ResourceType string `json:"resource_type,omitempty"`

	// Project is the parent project id for resource-scoped bindings that
	// require one (BigQuery, Pub/Sub, Secret Manager, Cloud Run). Storage
	// buckets are globally named and do not need a project here.
	Project string `json:"project,omitempty"`

	// Location is the region for regional resources (Cloud Run).
	Location string `json:"location,omitempty"`

	// Parent carries an intermediate identifier when the resource is nested
	// under another (BigQuery table → dataset_id).
	Parent string `json:"parent,omitempty"`
}

func (s Scope) String() string {
	if s.Display != "" {
		return fmt.Sprintf("%s (%s: %s)", s.Display, s.Type, s.ID)
	}
	return fmt.Sprintf("%s/%s", s.Type, s.ID)
}

// Member is a GCP IAM member identity.
type Member struct {
	Type    string `json:"type"`    // "user", "group", "serviceAccount", "domain"
	Email   string `json:"email"`   // e.g. "team-data@company.com"
	Display string `json:"display"` // optional label
}

func (m Member) IAMIdentity() string {
	return fmt.Sprintf("%s:%s", m.Type, m.Email)
}

// Condition is an optional IAM condition for conditional bindings.
type Condition struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Expression  string `json:"expression"` // CEL expression
}

// Binding is a single IAM role binding.
type Binding struct {
	Role      string     `json:"role"`
	Members   []Member   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
}

// PermissionRationale explains why a permission/role was chosen.
type PermissionRationale struct {
	Permission string `json:"permission"`
	Reason     string `json:"reason"`
}

// RationaleField holds the AI's rationale for the policy in either of two
// shapes: a structured list of {permission, reason} pairs (the canonical
// schema we ask the model for), or a free-form string of explanatory prose
// (which the refinement pass sometimes returns when explaining what it
// changed and why).
//
// We accept both rather than rejecting the prose form, because a refusal to
// parse means we silently fall back to the unrefined first-pass result and
// throw away a higher-quality answer. See ErrRefinementFailed for the
// failure path this is meant to avoid.
type RationaleField struct {
	Items []PermissionRationale
	Text  string
}

// UnmarshalJSON tolerates either an array of PermissionRationale objects
// or a single string. Anything else is a hard error.
func (r *RationaleField) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		return json.Unmarshal(data, &r.Items)
	case '"':
		return json.Unmarshal(data, &r.Text)
	default:
		return fmt.Errorf("rationale must be an array or string, got %s", trimmed[:1])
	}
}

// MarshalJSON emits whichever shape was originally populated, preserving
// round-trip fidelity for `iam-assist generate --json | iam-assist review`.
func (r RationaleField) MarshalJSON() ([]byte, error) {
	if len(r.Items) > 0 {
		return json.Marshal(r.Items)
	}
	if r.Text != "" {
		return json.Marshal(r.Text)
	}
	return []byte("null"), nil
}

// PolicyRecommendation is the full AI-generated output.
type PolicyRecommendation struct {
	// Original natural language request.
	Request string `json:"request"`

	// Where the policy applies.
	Scope Scope `json:"scope"`

	// The recommended bindings.
	Bindings []Binding `json:"bindings"`

	// Permissions the AI considered, with rationale. Stored as RawMessage
	// so the parser can tolerate either the canonical structured shape
	// ([]PermissionRationale) or a free-form string from the refinement
	// pass. Use Rationale.Items() / Rationale.Text() to consume it.
	Rationale RationaleField `json:"rationale,omitempty"`

	// Warnings or notes (e.g., "this grants write access to all buckets").
	Warnings []string `json:"warnings,omitempty"`

	// Alternatives the user may want to consider.
	Alternatives []string `json:"alternatives,omitempty"`

	// Whether a custom role was recommended over a predefined one.
	UsesCustomRole bool `json:"uses_custom_role,omitempty"`

	// Custom role definition if applicable.
	CustomRole *CustomRole `json:"custom_role,omitempty"`
}

// CustomRole defines a GCP custom IAM role.
type CustomRole struct {
	ID          string   `json:"id"`          // e.g. "customBigQueryReader"
	Title       string   `json:"title"`       // human-readable
	Description string   `json:"description"`
	Permissions []string `json:"permissions"` // e.g. ["bigquery.datasets.get", ...]
	Stage       string   `json:"stage"`       // "GA", "BETA", "ALPHA"
}

// RiskLevel indicates how permissive the policy is.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// RiskAssessment evaluates the generated policy.
type RiskAssessment struct {
	Level   RiskLevel `json:"level"`
	Reasons []string  `json:"reasons"`
}

// AssessOptions tunes the risk assessor with caller-supplied context.
// Nil is always safe — callers that don't care just pass nothing.
type AssessOptions struct {
	// InternalDomains is the set of email domains considered "internal" to
	// the caller's organization. When set, user/group members from any
	// other domain get flagged as external (medium risk). When empty, the
	// external-member heuristic is skipped — the assessor won't guess.
	InternalDomains []string
}

// highRiskRoles maps privileged role names to the reason they're dangerous.
// Keeping the reasons here means every warning ships with context instead
// of a bare role string, which matters a lot for the "why is this flagged?"
// user experience.
var highRiskRoles = map[string]string{
	"roles/owner":                           "grants full control of project, billing, and IAM",
	"roles/editor":                          "grants write access to nearly every resource in the project",
	"roles/iam.securityAdmin":               "can modify any IAM policy (privilege-escalation surface)",
	"roles/iam.serviceAccountAdmin":         "can create, delete, and impersonate any service account",
	"roles/iam.serviceAccountTokenCreator":  "can mint access tokens for any service account in scope",
	"roles/iam.serviceAccountUser":          "can act as any service account in scope",
	"roles/iam.workloadIdentityUser":        "can impersonate workload identities",
	"roles/resourcemanager.projectIamAdmin": "can grant any role on the project",
	"roles/resourcemanager.organizationAdmin": "full organization control",
	"roles/resourcemanager.folderIamAdmin":  "can grant any role on a folder subtree",
	"roles/billing.admin":                   "can redirect or close billing accounts",
	"roles/cloudkms.admin":                  "can manage encryption keys (read ciphertext surface)",
}

// breakGlassHints are substrings that indicate the request is for temporary,
// emergency, or time-limited access. When any of these appear in the request
// text, we insist on a time-bound CEL condition on every binding — a binding
// described as "temporary" without an expression like request.time < timestamp(...)
// is almost always a bug that will never be cleaned up.
var breakGlassHints = []string{
	"break-glass", "break glass", "breakglass",
	"emergency", "incident response",
	"on-call", "on call", "oncall",
	"temporary", "temp access", "temp-access",
	"contractor", "contract employee",
	"time-limited", "time limited", "expire", "expiry", "expires",
	"until ", // e.g., "until 2026-04-30"
}

// publicMemberEmails are the literal IAM identities that grant access to
// anyone on the public internet. These are almost never intended outside
// of a public-bucket serving use case and get an automatic HIGH rating.
var publicMemberEmails = map[string]bool{
	"allusers":              true,
	"allauthenticatedusers": true,
}

// Assess evaluates the risk of a PolicyRecommendation. Optional AssessOptions
// unlock the external-member heuristic; without them the assessor focuses on
// signals it can evaluate from the policy alone (roles, conditions, public
// members, break-glass keywords).
func Assess(rec *PolicyRecommendation, opts ...AssessOptions) RiskAssessment {
	var o AssessOptions
	if len(opts) > 0 {
		o = opts[0]
	}

	var reasons []string
	level := RiskLow
	// bump upgrades the level monotonically: once we hit High we stay there,
	// Medium can only go up to High. This keeps the final level meaningful
	// regardless of the order we check things in.
	bump := func(to RiskLevel) {
		if to == RiskHigh {
			level = RiskHigh
			return
		}
		if to == RiskMedium && level == RiskLow {
			level = RiskMedium
		}
	}

	// Does the request text suggest time-bounded access? If so, every binding
	// must carry a time-bound condition or it's a latent issue.
	reqLower := strings.ToLower(rec.Request)
	looksBreakGlass := false
	for _, h := range breakGlassHints {
		if strings.Contains(reqLower, h) {
			looksBreakGlass = true
			break
		}
	}

	for _, b := range rec.Bindings {
		// 1. High-risk roles from the curated list.
		if why, ok := highRiskRoles[b.Role]; ok {
			bump(RiskHigh)
			reasons = append(reasons, fmt.Sprintf("%s: %s", b.Role, why))
		} else if strings.HasSuffix(b.Role, "Admin") || strings.HasSuffix(b.Role, "admin") {
			// Any other *Admin role is at least medium breadth.
			bump(RiskMedium)
			reasons = append(reasons, fmt.Sprintf("%s has admin-level breadth", b.Role))
		}

		// 2. Public / external members.
		for _, m := range b.Members {
			// Normalize before comparing: an attacker-controlled LLM
			// response can drop leading/trailing whitespace, zero-width
			// characters, or mixed case into the email or type fields to
			// slip past the public-access check. Trimming + case-fold +
			// EqualFold on both fields closes those bypasses.
			emailLower := strings.ToLower(strings.TrimSpace(m.Email))
			// Strip common zero-width / BOM characters that are invisible
			// when rendered but defeat a plain string compare.
			emailLower = strings.NewReplacer(
				"\u200B", "", "\u200C", "", "\u200D", "",
				"\uFEFF", "",
			).Replace(emailLower)
			typeNormalized := strings.TrimSpace(m.Type)
			if publicMemberEmails[emailLower] ||
				strings.EqualFold(typeNormalized, "allUsers") ||
				strings.EqualFold(typeNormalized, "allAuthenticatedUsers") {
				bump(RiskHigh)
				reasons = append(reasons, fmt.Sprintf("%s grants public access on %s", m.IAMIdentity(), b.Role))
				continue
			}
			if len(o.InternalDomains) > 0 && (m.Type == "user" || m.Type == "group") {
				domain := domainOf(m.Email)
				if domain != "" && !domainInList(domain, o.InternalDomains) {
					bump(RiskMedium)
					reasons = append(reasons, fmt.Sprintf("external member %s on %s", m.IAMIdentity(), b.Role))
				}
			}
		}

		// 3. Org-level bindings must carry conditions.
		if b.Condition == nil && rec.Scope.Type == "organization" {
			bump(RiskMedium)
			reasons = append(reasons, fmt.Sprintf("%s is bound at organization scope without an IAM condition", b.Role))
		}

		// 4. Break-glass language in the request + no time-bound condition = latent issue.
		if looksBreakGlass && !hasTimeBound(b.Condition) {
			bump(RiskMedium)
			reasons = append(reasons, fmt.Sprintf("request mentions temporary/break-glass access but %s lacks a time-bound condition", b.Role))
		}
	}

	if level == RiskLow && len(reasons) == 0 {
		reasons = append(reasons, "bindings use narrowly-scoped predefined or custom roles")
	}

	return RiskAssessment{Level: level, Reasons: reasons}
}

// domainOf returns the domain portion of an email-like identity, or "" if
// the string doesn't parse as email@host.
func domainOf(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 || i == len(email)-1 {
		return ""
	}
	return email[i+1:]
}

// domainInList does a case-insensitive match of a domain against an allow
// list, including "sub.example.com is internal if example.com is listed".
func domainInList(domain string, list []string) bool {
	domain = strings.ToLower(domain)
	for _, d := range list {
		d = strings.ToLower(d)
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// hasTimeBound returns true if the condition carries a CEL expression that
// actually constrains request.time against a concrete timestamp. We're
// deliberately strict here: a condition field that exists but doesn't
// reference request.time provides zero temporal protection.
func hasTimeBound(c *Condition) bool {
	if c == nil {
		return false
	}
	e := strings.ToLower(c.Expression)
	return strings.Contains(e, "request.time") && strings.Contains(e, "timestamp(")
}

// ToJSON serializes the recommendation.
func (r *PolicyRecommendation) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ParseRecommendation deserializes the AI's JSON response into a PolicyRecommendation.
func ParseRecommendation(raw string) (*PolicyRecommendation, error) {
	// Strip markdown code fences if present.
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	var rec PolicyRecommendation
	if err := json.Unmarshal([]byte(cleaned), &rec); err != nil {
		return nil, fmt.Errorf("failed to parse policy recommendation: %w\nraw response:\n%s", err, raw)
	}
	rec.normalize()
	return &rec, nil
}

// normalize cleans up common LLM output defects that the JSON schema can't
// prevent on its own:
//
//  1. Gemini's responseSchema dialect has no way to say "this object field
//     may be absent or null", so models sometimes emit a condition object
//     populated with the literal string "null" in every field rather than
//     omitting the field. Detect that shape and drop it to nil.
//  2. An all-empty Condition struct has the same effect — nothing useful to
//     render — and should also be dropped.
func (r *PolicyRecommendation) normalize() {
	for i := range r.Bindings {
		c := r.Bindings[i].Condition
		if c == nil {
			continue
		}
		if isBlankOrNullString(c.Title) && isBlankOrNullString(c.Description) && isBlankOrNullString(c.Expression) {
			r.Bindings[i].Condition = nil
		}
	}
	r.Warnings = dropBlankOrNullStrings(r.Warnings)
	r.Alternatives = dropBlankOrNullStrings(r.Alternatives)
}

func dropBlankOrNullStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, s := range in {
		if !isBlankOrNullString(s) {
			out = append(out, s)
		}
	}
	return out
}

func isBlankOrNullString(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.EqualFold(t, "null")
}
