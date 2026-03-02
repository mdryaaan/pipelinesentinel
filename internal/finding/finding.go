package finding

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RuleID identifies the check that produced a finding.
type RuleID string

// The rule catalogue. IDs are stable and appear in reports, so they are treated
// as a public contract.
const (
	RuleUnpinnedAction  RuleID = "unpinned-action"
	RulePwnRequest      RuleID = "pwn-request"
	RuleBroadPermission RuleID = "broad-permissions"
	RuleSecretLeak      RuleID = "secret-leak"
	RuleScriptInjection RuleID = "script-injection"
)

// AllRules lists every rule ID in report order.
func AllRules() []RuleID {
	return []RuleID{
		RuleScriptInjection,
		RulePwnRequest,
		RuleSecretLeak,
		RuleUnpinnedAction,
		RuleBroadPermission,
	}
}

// Valid reports whether r is a known rule.
func (r RuleID) Valid() bool {
	for _, known := range AllRules() {
		if r == known {
			return true
		}
	}
	return false
}

func (r RuleID) String() string { return string(r) }

// Confidence describes how sure the detector is.
type Confidence string

// Confidence levels. A rule that matches an unambiguous pattern is Certain; one
// that matches a pattern whose exploitability depends on surrounding context is
// Ambiguous and is what the LLM pass exists to adjudicate.
const (
	Certain   Confidence = "certain"
	Probable  Confidence = "probable"
	Ambiguous Confidence = "ambiguous"
)

// Finding is one detected risk in one workflow file.
type Finding struct {
	RuleID   RuleID   `json:"rule_id"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	// Line is 1-indexed, matching how editors and GitHub number lines.
	Line       int        `json:"line"`
	EndLine    int        `json:"end_line,omitempty"`
	Job        string     `json:"job,omitempty"`
	Step       string     `json:"step,omitempty"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Snippet    string     `json:"snippet"`
	Confidence Confidence `json:"confidence"`

	// Fix is a unified diff a maintainer can apply directly.
	Fix string `json:"fix,omitempty"`

	// The fields below are populated only by the LLM reasoning pass.
	LLMReviewed  bool     `json:"llm_reviewed,omitempty"`
	LLMVerdict   string   `json:"llm_verdict,omitempty"`
	LLMScore     float64  `json:"llm_confidence,omitempty"`
	CitedLines   []int    `json:"cited_lines,omitempty"`
	Hallucinated []int    `json:"hallucinated_lines,omitempty"`
	Dismissed    bool     `json:"dismissed,omitempty"`
	DismissedWhy string   `json:"dismissed_reason,omitempty"`
	References   []string `json:"references,omitempty"`
}

// ErrInvalid marks a finding that failed validation.
var ErrInvalid = errors.New("invalid finding")

// Validate checks the finding's required fields.
func (f Finding) Validate() error {
	if !f.RuleID.Valid() {
		return fmt.Errorf("%w: unknown rule %q", ErrInvalid, f.RuleID)
	}
	if !f.Severity.Valid() {
		return fmt.Errorf("%w: unknown severity %q", ErrInvalid, f.Severity)
	}
	if f.Line < 1 {
		return fmt.Errorf("%w: line must be 1-indexed, got %d", ErrInvalid, f.Line)
	}
	if strings.TrimSpace(f.Title) == "" {
		return fmt.Errorf("%w: empty title", ErrInvalid)
	}
	return nil
}

// Location renders a file:line reference that editors and GitHub both linkify.
func (f Finding) Location() string { return fmt.Sprintf("%s:%d", f.File, f.Line) }

// NeedsReasoning reports whether this finding should be escalated to the LLM.
//
// Only ambiguous findings are: sending the certain ones would spend inference on
// questions a regex already answered correctly, and would let a model overturn a
// deterministic result it has no better information about.
func (f Finding) NeedsReasoning() bool {
	return f.Confidence == Ambiguous && !f.LLMReviewed
}

// Sort orders findings for reporting: worst severity first, then by file and
// line so a report over unchanged input is byte-identical between runs.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// CountBySeverity tallies findings, skipping any the LLM dismissed.
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range findings {
		if f.Dismissed {
			continue
		}
		counts[f.Severity]++
	}
	return counts
}

// CountByRule tallies findings per rule, skipping dismissed ones.
func CountByRule(findings []Finding) map[RuleID]int {
	counts := make(map[RuleID]int)
	for _, f := range findings {
		if f.Dismissed {
			continue
		}
		counts[f.RuleID]++
	}
	return counts
}

// Active returns the findings that survived the reasoning pass.
func Active(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Dismissed {
			out = append(out, f)
		}
	}
	return out
}
