package main

import (
	"os"

	"github.com/fathomforge/iam-assist/cmd"
)

// version is populated at build time via:
//
//	go build -ldflags "-X main.version=v0.1.0" .
//
// It defaults to "dev" for local builds so `iam-assist --version` always
// prints something useful even when not built through the Makefile.
var version = "dev"

func main() {
	cmd.SetVersion(version)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
