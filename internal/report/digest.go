package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

// WriteDigest renders the terminal summary: one line per finding, worst first.
//
// This is what someone sees when they run the tool by hand, so it is optimised
// for a 24-line terminal rather than for completeness. The full detail lives in
// `explain` and in the Markdown report.
func WriteDigest(w io.Writer, audit Audit) error {
	b := &strings.Builder{}

	active := audit.Active()
	if len(active) == 0 {
		fmt.Fprintf(b, "%s no findings in %d workflow file(s)\n",
			finding.Info.Emoji(), len(audit.Files))
		writeDigestFooter(b, audit)
		_, err := io.WriteString(w, b.String())
		return err
	}

	for _, f := range active {
		fmt.Fprintf(b, "%s  %-8s %-18s %s:%d  %s\n",
			f.Severity.Emoji(), f.Severity.Label(), f.RuleID, f.File, f.Line, oneLine(f.Title))
	}
	fmt.Fprintln(b)

	counts := audit.Counts()
	var parts []string
	for _, severity := range []finding.Severity{
		finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info,
	} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity.Label()))
		}
	}
	fmt.Fprintf(b, "%d finding(s) in %d file(s): %s\n",
		len(active), len(audit.Files), strings.Join(parts, ", "))

	writeDigestFooter(b, audit)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeDigestFooter(b *strings.Builder, audit Audit) {
	if r := audit.Reasoning; r != nil {
		if r.Disclaimer != "" {
			fmt.Fprintf(b, "%s\n", r.Disclaimer)
		}
		if r.Candidates > 0 {
			fmt.Fprintf(b, "reasoning pass (%s): %d escalated, %d confirmed, %d dismissed",
				r.Provider, r.Candidates, r.Confirmed, r.Dismissed)
			if r.Failed > 0 {
				fmt.Fprintf(b, ", %d failed", r.Failed)
			}
			fmt.Fprintln(b)
		}
	}

	for _, e := range audit.Errors {
		fmt.Fprintf(b, "not audited: %s (%s)\n", e.Path, e.Reason)
	}
}
