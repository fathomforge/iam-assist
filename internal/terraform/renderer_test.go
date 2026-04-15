package terraform

import (
	"strings"
	"testing"

	"github.com/fathomforge/iam-assist/internal/policy"
)

func TestRenderProjectBinding(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Read BigQuery data in analytics-prod",
		Scope:   policy.Scope{Type: "project", ID: "analytics-prod", Display: "Analytics Prod"},
		Bindings: []policy.Binding{
			{
				Role: "roles/bigquery.dataViewer",
				Members: []policy.Member{
					{Type: "group", Email: "data-team@company.com", Display: "Data Team"},
				},
			},
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	checks := []string{
		`google_project_iam_member`,
		`project = "analytics-prod"`,
		`role    = "roles/bigquery.dataViewer"`,
		`member  = "group:data-team@company.com"`,
		`# Risk: low`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q\n\ngot:\n%s", check, output)
		}
	}
}

func TestRenderWithCondition(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Temporary access",
		Scope:   policy.Scope{Type: "project", ID: "staging"},
		Bindings: []policy.Binding{
			{
				Role:    "roles/viewer",
				Members: []policy.Member{{Type: "user", Email: "alice@co.com"}},
				Condition: &policy.Condition{
					Title:       "temp_access",
					Description: "Expires end of Q1",
					Expression:  `request.time < timestamp("2026-04-01T00:00:00Z")`,
				},
			},
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	if !strings.Contains(output, "condition {") {
		t.Errorf("output missing condition block\n\ngot:\n%s", output)
	}
	if !strings.Contains(output, "temp_access") {
		t.Errorf("output missing condition title\n\ngot:\n%s", output)
	}
}

func TestRenderCustomRole(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Narrow BigQuery access",
		Scope:   policy.Scope{Type: "project", ID: "my-proj"},
		Bindings: []policy.Binding{
			{
				Role:    "projects/my-proj/roles/customBqReader",
				Members: []policy.Member{{Type: "group", Email: "team@co.com"}},
			},
		},
		UsesCustomRole: true,
		CustomRole: &policy.CustomRole{
			ID:          "customBqReader",
			Title:       "Custom BigQuery Reader",
			Description: "Read-only BigQuery access without export",
			Permissions: []string{"bigquery.datasets.get", "bigquery.tables.getData", "bigquery.jobs.create"},
			Stage:       "GA",
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	if !strings.Contains(output, `google_project_iam_custom_role`) {
		t.Errorf("output missing custom role resource\n\ngot:\n%s", output)
	}
	if !strings.Contains(output, `"bigquery.datasets.get"`) {
		t.Errorf("output missing permission\n\ngot:\n%s", output)
	}
}

// TestRenderMultiMember verifies that a binding with multiple members emits
// one resource per member, not a single resource with multiple `member =`
// lines (which is invalid HCL — google_*_iam_member is single-member).
func TestRenderMultiMember(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Three contractors need viewer access",
		Scope:   policy.Scope{Type: "project", ID: "analytics-prod"},
		Bindings: []policy.Binding{
			{
				Role: "roles/bigquery.dataViewer",
				Members: []policy.Member{
					{Type: "user", Email: "alice@datacorp.com"},
					{Type: "user", Email: "bob@datacorp.com"},
					{Type: "user", Email: "carol@datacorp.com"},
				},
			},
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	// Exactly three resource blocks must be emitted, one per member.
	resourceCount := strings.Count(output, `resource "google_project_iam_member"`)
	if resourceCount != 3 {
		t.Errorf("expected 3 resource blocks, got %d\n\n%s", resourceCount, output)
	}

	// Each member must appear in its own resource. Resource addresses must
	// be unique — duplicate addresses would also fail terraform validate.
	for _, addr := range []string{
		`"bigquery_data_viewer_0_0"`,
		`"bigquery_data_viewer_0_1"`,
		`"bigquery_data_viewer_0_2"`,
	} {
		if !strings.Contains(output, addr) {
			t.Errorf("output missing unique resource address %s\n\n%s", addr, output)
		}
	}

	// Sanity: each member email shows up exactly once as a `member = ...`.
	for _, email := range []string{"alice@datacorp.com", "bob@datacorp.com", "carol@datacorp.com"} {
		want := `member  = "user:` + email + `"`
		if strings.Count(output, want) != 1 {
			t.Errorf("expected exactly one occurrence of %q\n\n%s", want, output)
		}
	}

	// Belt and suspenders: there should be no resource block that contains
	// two `member = ` lines (the original bug).
	for _, block := range strings.Split(output, "\nresource ") {
		if strings.Count(block, "member  = ") > 1 {
			t.Errorf("found resource block with multiple member lines (invalid HCL):\n\n%s", block)
		}
	}
}

// TestRenderConditionWithQuotes verifies that condition expressions
// containing double quotes (which CEL expressions almost always do —
// e.g. timestamp("2026-04-28T23:59:59Z")) are properly escaped so the
// emitted HCL string literal doesn't break out.
func TestRenderConditionWithQuotes(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Time-bounded contractor access",
		Scope:   policy.Scope{Type: "project", ID: "staging"},
		Bindings: []policy.Binding{
			{
				Role:    "roles/viewer",
				Members: []policy.Member{{Type: "user", Email: "alice@datacorp.com"}},
				Condition: &policy.Condition{
					Title:       "expires_2026_04_28",
					Description: `Auto-expires "end of incident window"`,
					Expression:  `request.time < timestamp("2026-04-28T23:59:59Z") && !resource.name.contains("_pii")`,
				},
			},
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	// The expression must be escaped — every literal " in the input
	// becomes \" in the output. The previously-broken renderer emitted the
	// raw quotes, producing invalid HCL.
	wantExpr := `expression  = "request.time < timestamp(\"2026-04-28T23:59:59Z\") && !resource.name.contains(\"_pii\")"`
	if !strings.Contains(output, wantExpr) {
		t.Errorf("expected escaped expression\nwant: %s\n\ngot:\n%s", wantExpr, output)
	}

	// Same for the description — a quote in a description would also break.
	wantDesc := `description = "Auto-expires \"end of incident window\""`
	if !strings.Contains(output, wantDesc) {
		t.Errorf("expected escaped description\nwant: %s\n\ngot:\n%s", wantDesc, output)
	}

	// And a regression check: there must be no place in the output where
	// a string literal "...something..."contains an unescaped inner quote
	// followed by additional content. Crude but catches the regression.
	if strings.Contains(output, `timestamp("2026-04-28T23:59:59Z")"`) {
		t.Errorf("found unescaped quote in expression — would produce invalid HCL\n\n%s", output)
	}
}

func TestRenderOrgBinding(t *testing.T) {
	rec := &policy.PolicyRecommendation{
		Request: "Org-wide viewer",
		Scope:   policy.Scope{Type: "organization", ID: "123456789"},
		Bindings: []policy.Binding{
			{
				Role:    "roles/viewer",
				Members: []policy.Member{{Type: "domain", Email: "company.com"}},
			},
		},
	}

	output, err := Render(rec)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	if !strings.Contains(output, `google_organization_iam_member`) {
		t.Errorf("output missing org resource type\n\ngot:\n%s", output)
	}
	if !strings.Contains(output, `org_id = "123456789"`) {
		t.Errorf("output missing org_id\n\ngot:\n%s", output)
	}
}
