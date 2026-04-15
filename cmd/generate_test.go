package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemoveStaleOutput_ExistingFile verifies that a stale output file left
// over from a previous run is removed on the fatal-error path, so a user
// running `cat <file>` after a failed generate doesn't see old content.
func TestRemoveStaleOutput_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.tf")

	if err := os.WriteFile(path, []byte("STALE CONTENT FROM PREVIOUS RUN"), 0644); err != nil {
		t.Fatalf("seeding stale file: %v", err)
	}

	removeStaleOutput(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected stale file to be removed, stat err = %v", err)
	}
}

// TestRemoveStaleOutput_MissingFile verifies that a missing path is a no-op
// (not an error), since the normal case for a first-time failing run is that
// no file exists yet.
func TestRemoveStaleOutput_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.tf")

	// Should not panic or log-fail; function returns void and swallows IsNotExist.
	removeStaleOutput(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file to still not exist, stat err = %v", err)
	}
}
