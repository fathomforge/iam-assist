package policy

import "strings"

// SanitizeDisplay returns s with ANSI escape bytes and other terminal-control
// characters stripped. Use this on every LLM- or JSON-controlled string that
// gets printed to a terminal: an attacker who can influence those fields
// could otherwise emit cursor-movement sequences that overwrite risk labels,
// clear the screen at an approval prompt, or disguise a URL via OSC 8.
//
// Preserved runes: printable (>= 0x20 and != 0x7F), tab, newline, carriage
// return. Stripped: C0 controls (including ESC/0x1B), DEL, and C1 controls
// (0x80-0x9F) — the latter because some terminal emulators interpret them
// as the 8-bit forms of ESC sequences.
func SanitizeDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(r)
		case r < 0x20:
			// C0 control (including 0x1B ESC) — strip.
		case r == 0x7F:
			// DEL — strip.
		case r >= 0x80 && r <= 0x9F:
			// C1 control — strip.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
