// Package finding defines the security findings pipelinesentinel reports.
package finding

import "fmt"

// Severity is how urgently a finding needs attention.
type Severity string

// The closed severity set. Anything outside it is rejected by validation, so a
// model cannot invent its own scale.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// AllSeverities lists every severity, most urgent first.
func AllSeverities() []Severity {
	return []Severity{Critical, High, Medium, Low, Info}
}

// Valid reports whether s is a recognised severity.
func (s Severity) Valid() bool {
	for _, known := range AllSeverities() {
		if s == known {
			return true
		}
	}
	return false
}

// ParseSeverity converts a string to a Severity, erroring outside the set.
func ParseSeverity(in string) (Severity, error) {
	s := Severity(in)
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q", in)
	}
	return s, nil
}

// Rank orders severities for sorting and threshold comparison; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is as severe as min, used by --severity filtering.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// Label renders the severity for report headers.
func (s Severity) Label() string {
	switch s {
	case Critical:
		return "Critical"
	case High:
		return "High"
	case Medium:
		return "Medium"
	case Low:
		return "Low"
	case Info:
		return "Info"
	default:
		return string(s)
	}
}

// Emoji gives a compact severity marker for PR comments, where a reviewer scans
// a list rather than reading it.
func (s Severity) Emoji() string {
	switch s {
	case Critical:
		return "🛑"
	case High:
		return "🔴"
	case Medium:
		return "🟠"
	case Low:
		return "🟡"
	default:
		return "🔵"
	}
}

func (s Severity) String() string { return string(s) }
