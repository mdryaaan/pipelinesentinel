// Package report renders audit results as JSON, Markdown, a PR comment, or a
// short digest.
package report

import (
	"time"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

// Audit is the complete result of one run, and the single structure every
// renderer reads from.
//
// Keeping one struct behind all four output formats is what stops the Markdown
// report and the JSON export from quietly disagreeing — a real risk when the
// JSON is what a policy gate reads and the Markdown is what a human reads.
type Audit struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Source      string    `json:"source"`
	GeneratedAt time.Time `json:"generated_at"`
	// Summary is derived from Findings and written into the JSON so consumers
	// that are not Go programs — a bash step in a composite action, a policy
	// gate, a dashboard — do not have to re-derive the counts by parsing the
	// finding list and re-applying the dismissal rules themselves.
	Summary   Summary           `json:"summary"`
	Files     []FileResult      `json:"files"`
	Findings  []finding.Finding `json:"findings"`
	Reasoning *ReasoningSummary `json:"reasoning,omitempty"`
	Errors    []FileError       `json:"errors,omitempty"`
}

// Summary is the headline count of what survived the audit.
type Summary struct {
	Total      int              `json:"total"`
	Worst      finding.Severity `json:"worst"`
	Dismissed  int              `json:"dismissed"`
	BySeverity map[string]int   `json:"by_severity"`
	ByRule     map[string]int   `json:"by_rule"`
}

// Summarise derives the summary from the findings.
func Summarise(findings []finding.Finding) Summary {
	summary := Summary{
		Worst:      finding.Info,
		BySeverity: map[string]int{},
		ByRule:     map[string]int{},
	}

	for _, f := range findings {
		if f.Dismissed {
			summary.Dismissed++
			continue
		}
		summary.Total++
		summary.BySeverity[string(f.Severity)]++
		summary.ByRule[string(f.RuleID)]++
		if f.Severity.Rank() > summary.Worst.Rank() {
			summary.Worst = f.Severity
		}
	}

	return summary
}

// FileResult records that a file was audited, so a report can distinguish
// "clean" from "never looked at".
type FileResult struct {
	Path     string `json:"path"`
	URL      string `json:"url,omitempty"`
	Findings int    `json:"findings"`
	Lines    int    `json:"lines"`
}

// FileError records a file that could not be parsed.
type FileError struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ReasoningSummary describes the LLM pass, if one ran.
type ReasoningSummary struct {
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	Candidates int    `json:"candidates"`
	Reviewed   int    `json:"reviewed"`
	Confirmed  int    `json:"confirmed"`
	Dismissed  int    `json:"dismissed"`
	Uncertain  int    `json:"uncertain"`
	Failed     int    `json:"failed"`
	Citations  int    `json:"citations"`
	Fabricated int    `json:"fabricated_citations"`
	// Disclaimer is non-empty when no model was involved. Renderers must print
	// it wherever they print the provider name.
	Disclaimer string `json:"disclaimer,omitempty"`
}

// SummariseReasoning converts reviewer stats into a report section, attaching
// the baseline disclaimer when the "provider" was not a model at all.
func SummariseReasoning(stats llm.Stats) *ReasoningSummary {
	summary := &ReasoningSummary{
		Provider:   stats.ProviderName,
		Model:      stats.ModelName,
		Candidates: stats.Candidates,
		Reviewed:   stats.Reviewed,
		Confirmed:  stats.Confirmed,
		Dismissed:  stats.Dismissed,
		Uncertain:  stats.Uncertain,
		Failed:     stats.Failed,
		Citations:  stats.TotalCited,
		Fabricated: stats.Fabricated,
	}
	if stats.ProviderName == llm.ProviderOffline {
		summary.Disclaimer = llm.OfflineDisclaimer
	}
	return summary
}

// Active returns the findings that survived the reasoning pass.
func (a Audit) Active() []finding.Finding { return finding.Active(a.Findings) }

// Counts tallies active findings by severity.
func (a Audit) Counts() map[finding.Severity]int { return finding.CountBySeverity(a.Findings) }

// Worst returns the highest severity present, or Info when the audit is clean.
func (a Audit) Worst() finding.Severity {
	worst := finding.Info
	for _, f := range a.Active() {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// Clean reports whether anything survived.
func (a Audit) Clean() bool { return len(a.Active()) == 0 }

// FailsAt reports whether the audit should fail a build at the given threshold.
func (a Audit) FailsAt(min finding.Severity) bool {
	for _, f := range a.Active() {
		if f.Severity.AtLeast(min) {
			return true
		}
	}
	return false
}
