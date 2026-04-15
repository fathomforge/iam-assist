package policy

import (
	"testing"
)

func TestLookupRole(t *testing.T) {
	info := LookupRole("roles/bigquery.dataViewer")
	if info == nil {
		t.Fatal("expected non-nil for known role")
	}
	if info.Service != "bigquery" {
		t.Errorf("service = %q, want bigquery", info.Service)
	}

	unknown := LookupRole("roles/nonexistent.thing")
	if unknown != nil {
		t.Error("expected nil for unknown role")
	}
}

func TestValidateBindings(t *testing.T) {
	tests := []struct {
		name        string
		bindings    []Binding
		wantWarnings int
	}{
		{
			name: "narrow role, no warnings",
			bindings: []Binding{
				{Role: "roles/bigquery.dataViewer"},
			},
			wantWarnings: 0,
		},
		{
			name: "admin role flags narrower alts",
			bindings: []Binding{
				{Role: "roles/bigquery.admin"},
			},
			wantWarnings: 1,
		},
		{
			name: "compute admin flags both broad perms and narrower alts",
			bindings: []Binding{
				{Role: "roles/compute.admin"},
			},
			wantWarnings: 2, // narrower alts + >100 perms
		},
		{
			name: "owner is worst case",
			bindings: []Binding{
				{Role: "roles/owner"},
			},
			wantWarnings: 2, // narrower alts + >100 perms
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := ValidateBindings(tt.bindings)
			if len(warnings) != tt.wantWarnings {
				t.Errorf("got %d warnings, want %d: %v", len(warnings), tt.wantWarnings, warnings)
			}
		})
	}
}
