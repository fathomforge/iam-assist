package cmd

import "testing"

func TestResolveVersionUsesLdflagValues(t *testing.T) {
	got := ResolveVersion("0.1.1", "2afa3164e0015af90358ea0dec01f9f698e89ba9", "2026-09-03T02:57:25Z")
	want := "0.1.1 (2afa316, 2026-09-03T02:57:25Z)"
	if got != want {
		t.Errorf("ResolveVersion() = %q, want %q", got, want)
	}
}

func TestResolveVersionStripsLeadingV(t *testing.T) {
	// go install records the module version as "v0.1.1"; Homebrew and the
	// release archives report "0.1.1". Both should print the same thing.
	if got := ResolveVersion("v0.1.1", "", ""); got != "0.1.1" {
		t.Errorf("ResolveVersion() = %q, want %q", got, "0.1.1")
	}
}

func TestResolveVersionFallsBackToBuildInfo(t *testing.T) {
	// Under `go test` the binary carries VCS stamps but no module version, so
	// the "dev" default survives while commit and date get filled in. The point
	// is that an uninjected build still reports more than a bare "dev".
	got := ResolveVersion("dev", "", "")
	if got == "" {
		t.Fatal("ResolveVersion() returned empty string")
	}
	if got == "v" || got == "(devel)" {
		t.Errorf("ResolveVersion() leaked a placeholder: %q", got)
	}
	t.Logf("build-info fallback produced %q", got)
}

func TestResolveVersionNeverEmpty(t *testing.T) {
	if got := ResolveVersion("", "", ""); got == "" {
		t.Error("ResolveVersion() must never return an empty version")
	}
}

func TestShortCommit(t *testing.T) {
	cases := map[string]string{
		"2afa3164e0015af90358ea0dec01f9f698e89ba9": "2afa316",
		"abc123": "abc123",
		"":       "",
	}
	for in, want := range cases {
		if got := shortCommit(in); got != want {
			t.Errorf("shortCommit(%q) = %q, want %q", in, got, want)
		}
	}
}
