package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteJSON writes the machine-readable result.
func WriteJSON(w io.Writer, result Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encoding eval result: %w", err)
	}
	return nil
}

// WriteMarkdown renders the result as the table that goes in the README.
func WriteMarkdown(w io.Writer, result Result) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "## Evaluation\n\n")

	// The disclaimer comes before any number, because everything below it looks
	// like a model's score and is not.
	if result.Disclaimer != "" {
		fmt.Fprintf(b, "> **%s**\n\n", result.Disclaimer)
	}

	fmt.Fprintf(b, "Corpus `%s` · %d labelled cases · detector: %s",
		result.Corpus, result.Cases, result.Provider)
	if result.Model != "" && result.Model != "n/a" {
		fmt.Fprintf(b, " (`%s`)", result.Model)
	}
	fmt.Fprintf(b, " · %s\n\n", result.Duration.Round(1e6))

	s := result.Scores
	fmt.Fprintf(b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(b, "| Exact-match accuracy | **%.1f%%** (%d/%d) |\n",
		s.Accuracy*100, s.ExactMatches, s.Cases)
	fmt.Fprintf(b, "| Macro F1 | **%.3f** |\n", s.MacroF1)
	fmt.Fprintf(b, "| Clean workflows left silent | %.1f%% (%d/%d) |\n",
		s.CleanAccuracy()*100, s.CleanCorrect, s.CleanCases)
	if s.LinesChecked > 0 {
		fmt.Fprintf(b, "| Findings citing the labelled line | %.1f%% (%d/%d) |\n",
			s.CitationAccuracy()*100, s.LinesCorrect, s.LinesChecked)
	}
	fmt.Fprintln(b)

	fmt.Fprintf(b, "### Per-rule\n\n")
	fmt.Fprintf(b, "| Rule | Precision | Recall | F1 | TP | FP | FN |\n|---|---|---|---|---|---|---|\n")
	for _, rule := range s.PerRule {
		fmt.Fprintf(b, "| `%s` | %.3f | %.3f | %.3f | %d | %d | %d |\n",
			rule.Rule, rule.Precision, rule.Recall, rule.F1, rule.TP, rule.FP, rule.FN)
	}
	fmt.Fprintln(b)

	writeConfusion(b, s)

	if len(s.Failures) > 0 {
		fmt.Fprintf(b, "### Cases that could not be evaluated\n\n")
		for _, f := range s.Failures {
			fmt.Fprintf(b, "- %s\n", f)
		}
		fmt.Fprintln(b)
	}

	if r := result.Reasoning; r != nil && r.Candidates > 0 {
		fmt.Fprintf(b, "### Reasoning pass\n\n")
		fmt.Fprintf(b, "%d ambiguous finding(s) escalated: %d confirmed, %d dismissed, %d left uncertain",
			r.Candidates, r.Confirmed, r.Dismissed, r.Uncertain)
		if r.Failed > 0 {
			fmt.Fprintf(b, ", %d failed", r.Failed)
		}
		fmt.Fprintf(b, ".\n\n")
		if r.TotalCited > 0 {
			fmt.Fprintf(b, "Citations: %d of %d verified against the excerpt (%.1f%%).\n\n",
				r.TotalCited-r.Fabricated, r.TotalCited, r.CitationAccuracy()*100)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// writeConfusion renders the matrix of labelled category against what fired.
func writeConfusion(b *strings.Builder, s Scores) {
	if len(s.Confusion) == 0 {
		return
	}

	rows := make([]string, 0, len(s.Confusion))
	for row := range s.Confusion {
		rows = append(rows, row)
	}
	sort.Strings(rows)

	columnSet := map[string]bool{}
	for _, row := range s.Confusion {
		for col := range row {
			columnSet[col] = true
		}
	}
	columns := make([]string, 0, len(columnSet))
	for col := range columnSet {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	fmt.Fprintf(b, "### Confusion matrix\n\n")
	fmt.Fprintf(b, "Rows are the labelled category; columns are what actually fired. "+
		"The `%s` column is a miss.\n\n", NoFinding)

	fmt.Fprintf(b, "| labelled \\ fired |")
	for _, col := range columns {
		fmt.Fprintf(b, " %s |", short(col))
	}
	fmt.Fprintf(b, "\n|---|")
	for range columns {
		fmt.Fprintf(b, "---|")
	}
	fmt.Fprintln(b)

	for _, row := range rows {
		fmt.Fprintf(b, "| **%s** |", short(row))
		for _, col := range columns {
			fmt.Fprintf(b, " %d |", s.Confusion[row][col])
		}
		fmt.Fprintln(b)
	}
	fmt.Fprintln(b)
}

// short abbreviates a rule id so the matrix fits in a README column.
func short(id string) string {
	switch id {
	case "script-injection":
		return "inject"
	case "pwn-request":
		return "pwn"
	case "secret-leak":
		return "secret"
	case "unpinned-action":
		return "unpinned"
	case "broad-permissions":
		return "perms"
	}
	return id
}
