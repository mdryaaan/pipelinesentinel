package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

// CommentMarker identifies pipelinesentinel's own comment so a CI job can
// update it in place instead of adding a new one on every push.
const CommentMarker = "<!-- pipelinesentinel:audit -->"

// MaxCommentFindings is how many findings a PR comment lists in full.
//
// A comment with forty findings is a comment nobody reads. The cap keeps the
// most severe ones visible and points at the full report for the rest.
const MaxCommentFindings = 10

// WritePRComment renders a compact comment for a pull request.
func WritePRComment(w io.Writer, audit Audit) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "%s\n", CommentMarker)

	active := audit.Active()
	if len(active) == 0 {
		fmt.Fprintf(b, "## Workflow security audit\n\n")
		fmt.Fprintf(b, "No findings across %d workflow file(s).\n", len(audit.Files))
		writeCommentFooter(b, audit)
		_, err := io.WriteString(w, b.String())
		return err
	}

	counts := audit.Counts()
	fmt.Fprintf(b, "## %s Workflow security audit — %d finding(s)\n\n",
		audit.Worst().Emoji(), len(active))

	var parts []string
	for _, severity := range []finding.Severity{
		finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info,
	} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("**%d %s**", counts[severity], severity.Label()))
		}
	}
	fmt.Fprintf(b, "%s\n\n", strings.Join(parts, " · "))

	fmt.Fprintf(b, "| Severity | Rule | Location | Issue |\n|---|---|---|---|\n")

	shown := active
	if len(shown) > MaxCommentFindings {
		shown = shown[:MaxCommentFindings]
	}
	for _, f := range shown {
		fmt.Fprintf(b, "| %s %s | `%s` | `%s` | %s |\n",
			f.Severity.Emoji(), f.Severity.Label(), f.RuleID, f.Location(), oneLine(f.Title))
	}
	fmt.Fprintln(b)

	if len(active) > len(shown) {
		fmt.Fprintf(b, "_%d more finding(s) omitted. Run `pipelinesentinel report` for the full audit._\n\n",
			len(active)-len(shown))
	}

	writeTopFix(b, active[0])
	writeCommentFooter(b, audit)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeTopFix expands the single worst finding, because a comment that only
// counts problems gives a reviewer nothing to act on.
func writeTopFix(b *strings.Builder, f finding.Finding) {
	fmt.Fprintf(b, "<details>\n<summary>Most severe: %s</summary>\n\n", oneLine(f.Title))
	fmt.Fprintf(b, "%s\n\n", f.Detail)
	if f.Snippet != "" {
		fmt.Fprintf(b, "```yaml\n%s\n```\n\n", f.Snippet)
	}
	if f.Fix != "" {
		fmt.Fprintf(b, "```diff\n%s\n```\n\n", strings.TrimRight(f.Fix, "\n"))
	}
	fmt.Fprintf(b, "</details>\n\n")
}

func writeCommentFooter(b *strings.Builder, audit Audit) {
	if audit.Reasoning != nil && audit.Reasoning.Disclaimer != "" {
		fmt.Fprintf(b, "> %s\n\n", audit.Reasoning.Disclaimer)
	}
	fmt.Fprintf(b, "<sub>%s %s · `%s`</sub>\n", audit.Tool, audit.Version, audit.Source)
}

// oneLine flattens text for a table cell, where a newline or a pipe would break
// the row.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}
