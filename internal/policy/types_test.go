package policy

import (
	"encoding/json"
	"testing"
)

// TestRationaleFieldShapes locks in the tolerant parser: rationale may be
// either a structured array (canonical first-pass shape) or a free-form
// string (which the refinement pass sometimes returns when explaining
// changes between passes). Both must round-trip cleanly.
func TestRationaleFieldShapes(t *testing.T) {
	t.Run("structured array", func(t *testing.T) {
		raw := `{"rationale": [{"permission": "bigquery.tables.get", "reason": "read"}]}`
		var rec PolicyRecommendation
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(rec.Rationale.Items) != 1 || rec.Rationale.Items[0].Permission != "bigquery.tables.get" {
			t.Errorf("items not parsed: %+v", rec.Rationale)
		}
		if rec.Rationale.Text != "" {
			t.Errorf("text should be empty when array provided, got %q", rec.Rationale.Text)
		}
	})

	t.Run("free-form string", func(t *testing.T) {
		raw := `{"rationale": "Tightened bigquery.admin to bigquery.dataViewer because the request is read-only."}`
		var rec PolicyRecommendation
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(rec.Rationale.Items) != 0 {
			t.Errorf("items should be empty when string provided, got %+v", rec.Rationale.Items)
		}
		if rec.Rationale.Text == "" || rec.Rationale.Text[:9] != "Tightened" {
			t.Errorf("text not parsed: %q", rec.Rationale.Text)
		}
	})

	t.Run("missing field", func(t *testing.T) {
		raw := `{"scope": {"type": "project", "id": "p"}}`
		var rec PolicyRecommendation
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(rec.Rationale.Items) != 0 || rec.Rationale.Text != "" {
			t.Errorf("expected empty rationale, got %+v", rec.Rationale)
		}
	})

	t.Run("invalid type rejected", func(t *testing.T) {
		raw := `{"rationale": 42}`
		var rec PolicyRecommendation
		if err := json.Unmarshal([]byte(raw), &rec); err == nil {
			t.Errorf("expected error for numeric rationale, got none")
		}
	})

	t.Run("round-trip preserves shape", func(t *testing.T) {
		// Array shape in → array shape out.
		rec := PolicyRecommendation{
			Rationale: RationaleField{Items: []PermissionRationale{{Permission: "p", Reason: "r"}}},
		}
		out, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !contains(string(out), `"rationale":[{"permission":"p","reason":"r"}]`) {
			t.Errorf("array shape not preserved: %s", out)
		}

		// String shape in → string shape out.
		rec = PolicyRecommendation{Rationale: RationaleField{Text: "explained"}}
		out, _ = json.Marshal(rec)
		if !contains(string(out), `"rationale":"explained"`) {
			t.Errorf("string shape not preserved: %s", out)
		}
	})
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestParseRecommendation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, *PolicyRecommendation)
	}{
		{
			name: "basic bigquery viewer",
			input: `{
				"scope": {"type": "project", "id": "analytics-prod", "display": "Analytics Production"},
				"bindings": [{
					"role": "roles/bigquery.dataViewer",
					"members": [{"type": "group", "email": "data-team@company.com", "display": "Data Team"}],
					"condition": null
				}],
				"rationale": [{"permission": "bigquery.datasets.get", "reason": "read dataset metadata"}],
				"warnings": [],
				"alternatives": ["roles/bigquery.jobUser if they also need to run queries"]
			}`,
			check: func(t *testing.T, rec *PolicyRecommendation) {
				if rec.Scope.Type != "project" {
					t.Errorf("scope type = %q, want project", rec.Scope.Type)
				}
				if len(rec.Bindings) != 1 {
					t.Fatalf("got %d bindings, want 1", len(rec.Bindings))
				}
				if rec.Bindings[0].Role != "roles/bigquery.dataViewer" {
					t.Errorf("role = %q, want roles/bigquery.dataViewer", rec.Bindings[0].Role)
				}
			},
		},
		{
			name: "with markdown fences",
			input: "```json\n{\"scope\":{\"type\":\"project\",\"id\":\"p\",\"display\":\"p\"},\"bindings\":[],\"rationale\":[],\"warnings\":[],\"alternatives\":[]}\n```",
			check: func(t *testing.T, rec *PolicyRecommendation) {
				if rec.Scope.ID != "p" {
					t.Errorf("scope id = %q, want p", rec.Scope.ID)
				}
			},
		},
		{
			name:    "invalid json",
			input:   "this is not json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := ParseRecommendation(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.check != nil && rec != nil {
				tt.check(t, rec)
			}
		})
	}
}

func TestAssess(t *testing.T) {
	// timeBound is a reusable CEL condition used in break-glass cases to
	// prove the assessor recognizes time-constrained expressions.
	timeBound := &Condition{
		Title:      "expires 2026-04-30",
		Expression: `request.time < timestamp("2026-05-01T00:00:00Z")`,
	}

	tests := []struct {
		name       string
		rec        *PolicyRecommendation
		opts       *AssessOptions
		wantRisk   RiskLevel
		wantReason string // substring that must appear in at least one reason
	}{
		{
			name: "low risk viewer",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/bigquery.dataViewer", Members: []Member{{Type: "group", Email: "t@c.com"}}},
				},
			},
			wantRisk: RiskLow,
		},
		{
			name: "high risk owner",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/owner", Members: []Member{{Type: "user", Email: "u@c.com"}}},
				},
			},
			wantRisk:   RiskHigh,
			wantReason: "full control",
		},
		{
			name: "medium risk admin",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/bigquery.admin", Members: []Member{{Type: "group", Email: "t@c.com"}}},
				},
			},
			wantRisk:   RiskMedium,
			wantReason: "admin-level breadth",
		},
		{
			name: "medium risk org without condition",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "organization", ID: "123"},
				Bindings: []Binding{
					{Role: "roles/viewer", Members: []Member{{Type: "domain", Email: "c.com"}}},
				},
			},
			wantRisk:   RiskMedium,
			wantReason: "organization scope",
		},
		// --- New behaviors below ---
		{
			name: "high risk: iam.serviceAccountTokenCreator",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/iam.serviceAccountTokenCreator", Members: []Member{{Type: "user", Email: "u@c.com"}}},
				},
			},
			wantRisk:   RiskHigh,
			wantReason: "mint access tokens",
		},
		{
			name: "high risk: allUsers on a bucket",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "resource", ID: "projects/_/buckets/b"},
				Bindings: []Binding{
					{Role: "roles/storage.objectViewer", Members: []Member{{Type: "allUsers", Email: "allUsers"}}},
				},
			},
			wantRisk:   RiskHigh,
			wantReason: "public access",
		},
		{
			name: "medium risk: break-glass language without time-bound condition",
			rec: &PolicyRecommendation{
				Request: "Emergency break-glass access for on-call engineer to restart the service",
				Scope:   Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/run.developer", Members: []Member{{Type: "user", Email: "oncall@c.com"}}},
				},
			},
			wantRisk:   RiskMedium,
			wantReason: "time-bound condition",
		},
		{
			name: "low risk: break-glass language WITH time-bound condition",
			rec: &PolicyRecommendation{
				Request: "Temporary access for the contractor until 2026-04-30",
				Scope:   Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/bigquery.dataViewer", Members: []Member{{Type: "user", Email: "c@c.com"}}, Condition: timeBound},
				},
			},
			wantRisk: RiskLow,
		},
		{
			name: "medium risk: external member with internal domain configured",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/bigquery.dataViewer", Members: []Member{{Type: "user", Email: "alice@contractor.com"}}},
				},
			},
			opts:       &AssessOptions{InternalDomains: []string{"mycompany.com"}},
			wantRisk:   RiskMedium,
			wantReason: "external member",
		},
		{
			name: "low risk: internal member with internal domain configured",
			rec: &PolicyRecommendation{
				Scope: Scope{Type: "project", ID: "p"},
				Bindings: []Binding{
					{Role: "roles/bigquery.dataViewer", Members: []Member{{Type: "user", Email: "alice@mycompany.com"}}},
				},
			},
			opts:     &AssessOptions{InternalDomains: []string{"mycompany.com"}},
			wantRisk: RiskLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var risk RiskAssessment
			if tt.opts != nil {
				risk = Assess(tt.rec, *tt.opts)
			} else {
				risk = Assess(tt.rec)
			}
			if risk.Level != tt.wantRisk {
				t.Errorf("risk = %v, want %v (reasons: %v)", risk.Level, tt.wantRisk, risk.Reasons)
			}
			if tt.wantReason != "" {
				found := false
				for _, r := range risk.Reasons {
					if contains(r, tt.wantReason) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected a reason containing %q, got %v", tt.wantReason, risk.Reasons)
				}
			}
		})
	}
}

func TestMemberIAMIdentity(t *testing.T) {
	m := Member{Type: "serviceAccount", Email: "sa@proj.iam.gserviceaccount.com"}
	got := m.IAMIdentity()
	want := "serviceAccount:sa@proj.iam.gserviceaccount.com"
	if got != want {
		t.Errorf("IAMIdentity() = %q, want %q", got, want)
	}
}
