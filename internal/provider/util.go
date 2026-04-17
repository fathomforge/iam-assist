package provider

import (
	"errors"
	"io"
	"strings"
)

// maxResponseBytes caps how much of an LLM provider response we will buffer
// in memory. 8 MiB is comfortably above any realistic completion response
// but prevents a broken or malicious endpoint from exhausting memory.
const maxResponseBytes = 8 << 20 // 8 MiB

// maxErrorBodyBytes caps how much of a non-200 response body we surface in
// error messages. Provider error payloads are typically small, and clamping
// the output prevents a large HTML error page (from a misconfigured proxy,
// say) from flooding stderr or logs.
const maxErrorBodyBytes = 1024

// redactKey returns an error whose message is the original error with every
// occurrence of apiKey replaced by "<redacted>". Used as defense in depth so
// that even if the key ends up in a transport-layer error (e.g. via *url.Error)
// it is never written to logs or stderr.
func redactKey(err error, apiKey string) error {
	if err == nil || apiKey == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, apiKey) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, apiKey, "<redacted>"))
}

// readCappedBody reads up to maxResponseBytes from r. Any bytes beyond the
// cap are discarded. Returns the buffered body and any read error.
func readCappedBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxResponseBytes))
}

// truncateForError returns s clamped to maxErrorBodyBytes, with a truncation
// marker appended when clamped. Use before embedding a response body in an
// error message to keep errors from becoming unbounded.
func truncateForError(s string) string {
	if len(s) <= maxErrorBodyBytes {
		return s
	}
	return s[:maxErrorBodyBytes] + "... [truncated]"
}
