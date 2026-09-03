package main

import (
	"os"

	"github.com/fathomforge/iam-assist/cmd"
)

// Populated at build time via:
//
//	go build -ldflags "-X main.version=v0.1.0 -X main.commit=abc123 -X main.date=..." .
//
// They stay empty for `go install`, which does not apply our ldflags; in that
// case cmd.ResolveVersion falls back to the build info the Go toolchain stamps
// into every binary.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	cmd.SetVersion(cmd.ResolveVersion(version, commit, date))
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
