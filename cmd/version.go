package cmd

import (
	"runtime/debug"
	"strings"
)

// devVersion is the placeholder main.version carries when -ldflags did not
// inject a real value.
const devVersion = "dev"

// ResolveVersion builds the string shown by `iam-assist --version`.
//
// Release binaries get version, commit and date injected via -ldflags (see
// .goreleaser.yaml). `go install github.com/fathomforge/iam-assist@latest`
// does not run those flags, so the ldflags values arrive empty or as the "dev"
// default. In that case fall back to what the Go toolchain stamps into every
// binary: the module version for proxy installs, and the VCS revision and time
// for builds made from a checkout.
func ResolveVersion(version, commit, date string) string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		if isUnset(version) {
			// "(devel)" is what the toolchain reports for a build from a
			// working tree rather than a released module version.
			if v := info.Main.Version; v != "" && v != "(devel)" {
				version = v
			}
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				if date == "" {
					date = s.Value
				}
			}
		}
	}

	if isUnset(version) {
		version = devVersion
	}
	// Release tags are v-prefixed but GoReleaser strips it, so normalize the
	// build-info path to match rather than printing "v0.1.1" for go install and
	// "0.1.1" for the same code installed via Homebrew.
	version = strings.TrimPrefix(version, "v")

	if commit == "" && date == "" {
		return version
	}
	var parts []string
	if commit != "" {
		parts = append(parts, shortCommit(commit))
	}
	if date != "" {
		parts = append(parts, date)
	}
	return version + " (" + strings.Join(parts, ", ") + ")"
}

func isUnset(v string) bool {
	return v == "" || v == devVersion
}

// shortCommit trims a full SHA to the customary 7 characters, leaving anything
// already short (or non-SHA) alone.
func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}
