package utils

import (
	"fmt"
	"strings"
)

// UnifiedDiff renders a minimal single-hunk unified diff for one replaced line.
//
// Suggested fixes are far more useful as something a reader can eyeball and
// apply than as prose, and a one-line hunk covers almost every remediation this
// tool emits. Anything genuinely multi-line is written by the rule itself.
func UnifiedDiff(file string, line int, before, after string) string {
	if strings.TrimSpace(before) == strings.TrimSpace(after) {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", file)
	fmt.Fprintf(&b, "+++ b/%s\n", file)
	fmt.Fprintf(&b, "@@ -%d,1 +%d,1 @@\n", line, line)
	fmt.Fprintf(&b, "-%s\n", strings.TrimRight(before, "\n"))
	fmt.Fprintf(&b, "+%s\n", strings.TrimRight(after, "\n"))
	return b.String()
}

// Indent returns the leading whitespace of s, so a generated replacement keeps
// the surrounding YAML's indentation.
func Indent(s string) string {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return s[:i]
		}
	}
	return s
}
