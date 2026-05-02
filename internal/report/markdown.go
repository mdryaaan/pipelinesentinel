package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

// WriteMarkdown renders the full human-readable report.
//
// Findings are grouped by severity rather than by file. A reviewer with ten
// minutes wants the criticals, wherever they live; grouping by file makes them
// read every file to be sure they have not missed one.
func WriteMarkdown(w io.Writer, audit Audit) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# Workflow security audit\n\n")
	fmt.Fprintf(b, "**Source:** `%s`  \n", audit.Source)
	fmt.Fprintf(b, "**Scanned:** %s  \n", audit.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(b, "**Tool:** %s %s\n\n", audit.Tool, audit.Version)

	writeSummary(b, audit)
	writeReasoning(b, audit)
	writeFindings(b, audit)
	writeFiles(b, audit)
	writeErrors(b, audit)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeSummary(b *strings.Builder, audit Audit) {
	counts := audit.Counts()
	active := len(audit.Active())

	fmt.Fprintf(b, "## Summary\n\n")

	if active == 0 {
		fmt.Fprintf(b, "No findings. %d workflow file(s) audited against %d rules.\n\n",
			len(audit.Files), len(finding.AllRules()))
		return
	}

	fmt.Fprintf(b, "**%d finding(s)** across %d workflow file(s).\n\n", active, len(audit.Files))
	fmt.Fprintf(b, "| Severity | Count |\n|---|---|\n")
	for _, severity := range []finding.Severity{
		finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info,
	} {
		if counts[severity] > 0 {
			fmt.Fprintf(b, "| %s %s | %d |\n", severity.Emoji(), severity.Label(), counts[severity])
		}
	}
	fmt.Fprintln(b)

	byRule := finding.CountByRule(audit.Findings)
	fmt.Fprintf(b, "| Rule | Count |\n|---|---|\n")
	for _, id := range finding.AllRules() {
		if byRule[id] > 0 {
			fmt.Fprintf(b, "| `%s` | %d |\n", id, byRule[id])
		}
	}
	fmt.Fprintln(b)
}

func writeReasoning(b *strings.Builder, audit Audit) {
	r := audit.Reasoning
	if r == nil {
		return
	}

	fmt.Fprintf(b, "## Reasoning pass\n\n")

	// The disclaimer goes first and in bold, because everything below it is a
	// number that looks like a model's and is not.
	if r.Disclaimer != "" {
		fmt.Fprintf(b, "> **%s**\n\n", r.Disclaimer)
	}

	fmt.Fprintf(b, "Provider `%s`, model `%s`. %d ambiguous finding(s) escalated.\n\n",
		r.Provider, r.Model, r.Candidates)
	fmt.Fprintf(b, "| Outcome | Count |\n|---|---|\n")
	fmt.Fprintf(b, "| Confirmed exploitable | %d |\n", r.Confirmed)
	fmt.Fprintf(b, "| Dismissed as unreachable | %d |\n", r.Dismissed)
	fmt.Fprintf(b, "| Left uncertain | %d |\n", r.Uncertain)
	if r.Failed > 0 {
		fmt.Fprintf(b, "| Review failed | %d |\n", r.Failed)
	}
	fmt.Fprintln(b)

	if r.Citations > 0 {
		verified := r.Citations - r.Fabricated
		fmt.Fprintf(b, "%d of %d citations pointed at a line the reviewer was actually shown",
			verified, r.Citations)
		if r.Fabricated > 0 {
			fmt.Fprintf(b, "; %d fabricated citation(s) were dropped before you saw them",
				r.Fabricated)
		}
		fmt.Fprintf(b, ".\n\n")
	}
}

func writeFindings(b *strings.Builder, audit Audit) {
	active := audit.Active()
	if len(active) == 0 {
		return
	}

	fmt.Fprintf(b, "## Findings\n\n")

	current := finding.Severity("")
	for _, f := range active {
		if f.Severity != current {
			current = f.Severity
			fmt.Fprintf(b, "### %s %s\n\n", f.Severity.Emoji(), f.Severity.Label())
		}
		writeFinding(b, f)
	}
}

func writeFinding(b *strings.Builder, f finding.Finding) {
	fmt.Fprintf(b, "#### %s\n\n", f.Title)
	fmt.Fprintf(b, "`%s` · rule `%s` · confidence `%s`", f.Location(), f.RuleID, f.Confidence)
	if f.Job != "" {
		fmt.Fprintf(b, " · job `%s`", f.Job)
	}
	fmt.Fprintf(b, "\n\n%s\n\n", f.Detail)

	if f.Snippet != "" {
		fmt.Fprintf(b, "```yaml\n%s\n```\n\n", f.Snippet)
	}

	if f.LLMReviewed {
		fmt.Fprintf(b, "Reviewer verdict: `%s` (confidence %.2f)", f.LLMVerdict, f.LLMScore)
		if len(f.CitedLines) > 0 {
			fmt.Fprintf(b, ", citing line(s) %s", joinInts(f.CitedLines))
		}
		fmt.Fprintf(b, ".\n\n")
	}

	if f.Fix != "" {
		fmt.Fprintf(b, "<details>\n<summary>Suggested fix</summary>\n\n```diff\n%s\n```\n\n</details>\n\n",
			strings.TrimRight(f.Fix, "\n"))
	}

	if remediation, err := finding.RemediationFor(f.RuleID); err == nil {
		fmt.Fprintf(b, "**How to fix:** %s [Docs](%s)\n\n", remediation.Summary, remediation.Docs)
	}

	fmt.Fprintf(b, "---\n\n")
}

func writeFiles(b *strings.Builder, audit Audit) {
	if len(audit.Files) == 0 {
		return
	}

	fmt.Fprintf(b, "## Files audited\n\n")
	fmt.Fprintf(b, "| File | Lines | Findings |\n|---|---|---|\n")
	for _, file := range audit.Files {
		name := fmt.Sprintf("`%s`", file.Path)
		if file.URL != "" {
			name = fmt.Sprintf("[`%s`](%s)", file.Path, file.URL)
		}
		fmt.Fprintf(b, "| %s | %d | %d |\n", name, file.Lines, file.Findings)
	}
	fmt.Fprintln(b)
}

func writeErrors(b *strings.Builder, audit Audit) {
	if len(audit.Errors) == 0 {
		return
	}

	// A file that failed to parse was not audited, and silently reporting the
	// rest as clean would be the most dangerous possible way to be wrong.
	fmt.Fprintf(b, "## Not audited\n\n")
	for _, e := range audit.Errors {
		fmt.Fprintf(b, "- `%s`: %s\n", e.Path, e.Reason)
	}
	fmt.Fprintln(b)
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}
