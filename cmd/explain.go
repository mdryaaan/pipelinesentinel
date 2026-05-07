package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/pipelinesentinel/internal/audit"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

var explainOpts struct {
	Rule string
	Line int
}

func newExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain [path | owner/repo]",
		Short: "Explain each finding in full, with the fix",
		Long: `Explain prints the complete reasoning for every finding: what was matched,
why it is dangerous, the source it came from, and a diff that fixes it.

Where audit answers "what is wrong", explain answers "what do I do about it".
Use --rule to focus on one rule, or --line to explain a single finding.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  pipelinesentinel explain --offline
  pipelinesentinel explain ./my-repo --rule script-injection
  pipelinesentinel explain ./my-repo --line 19`,
		RunE: runExplain,
	}

	cmd.Flags().StringVar(&explainOpts.Rule, "rule-id", "", "explain only findings from this rule")
	cmd.Flags().IntVar(&explainOpts.Line, "line", 0, "explain only the finding on this line")

	return cmd
}

func runExplain(cmd *cobra.Command, args []string) error {
	cfg, err := resolveConfig(cmd)
	if err != nil {
		return err
	}

	target := ""
	if len(args) == 1 {
		target = args[0]
	}
	source, err := resolveSource(target)
	if err != nil {
		return err
	}

	provider, err := resolveProvider(cfg)
	if err != nil {
		return err
	}

	result, err := (&audit.Runner{
		Source: source, Config: cfg, Provider: provider, Warn: cmd.ErrOrStderr(),
	}).Run(cmd.Context())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if result.Reasoning != nil && result.Reasoning.Disclaimer != "" {
		fmt.Fprintf(out, "%s\n\n", result.Reasoning.Disclaimer)
	}

	shown := 0
	for _, f := range result.Active() {
		if explainOpts.Rule != "" && string(f.RuleID) != explainOpts.Rule {
			continue
		}
		if explainOpts.Line > 0 && f.Line != explainOpts.Line {
			continue
		}
		explainFinding(cmd, f)
		shown++
	}

	if shown == 0 {
		fmt.Fprintf(out, "No findings to explain in %s.\n", result.Source)
		return nil
	}

	fmt.Fprintf(out, "%d finding(s) explained. Source: %s\n", shown, result.Source)
	return nil
}

func explainFinding(cmd *cobra.Command, f finding.Finding) {
	out := cmd.OutOrStdout()

	fmt.Fprintf(out, "%s %s  %s\n", f.Severity.Emoji(), strings.ToUpper(f.Severity.Label()), f.Title)
	fmt.Fprintf(out, "   %s  rule=%s  confidence=%s", f.Location(), f.RuleID, f.Confidence)
	if f.Job != "" {
		fmt.Fprintf(out, "  job=%s", f.Job)
	}
	if f.Step != "" {
		fmt.Fprintf(out, "  step=%q", f.Step)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	fmt.Fprintf(out, "%s\n\n", wrap(f.Detail, 88, "   "))

	if f.Snippet != "" {
		fmt.Fprintf(out, "%s\n\n", indent(f.Snippet, "   "))
	}

	if f.LLMReviewed {
		fmt.Fprintf(out, "   reasoning pass: %s (confidence %.2f)", f.LLMVerdict, f.LLMScore)
		if len(f.CitedLines) > 0 {
			fmt.Fprintf(out, ", citing line(s) %v", f.CitedLines)
		}
		if len(f.Hallucinated) > 0 {
			fmt.Fprintf(out, "; %d citation(s) outside the excerpt were dropped", len(f.Hallucinated))
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out)
	}

	if remediation, err := finding.RemediationFor(f.RuleID); err == nil {
		fmt.Fprintf(out, "   Why it matters\n%s\n\n", wrap(remediation.Why, 88, "   "))
		fmt.Fprintf(out, "   The safe pattern\n%s\n\n", indent(remediation.Example, "   "))
		fmt.Fprintf(out, "   Reference: %s\n\n", remediation.Docs)
	}

	if f.Fix != "" {
		fmt.Fprintf(out, "   Suggested change\n%s\n\n", indent(strings.TrimRight(f.Fix, "\n"), "   "))
	}

	fmt.Fprintf(out, "%s\n\n", strings.Repeat("-", 88))
}

// wrap reflows text to a width so a long explanation stays readable in a
// terminal, keeping paragraph breaks intact.
func wrap(text string, width int, prefix string) string {
	var b strings.Builder

	for i, paragraph := range strings.Split(text, "\n\n") {
		if i > 0 {
			b.WriteString("\n\n")
		}

		line := prefix
		for _, word := range strings.Fields(paragraph) {
			if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "" {
				b.WriteString(strings.TrimRight(line, " "))
				b.WriteString("\n")
				line = prefix
			}
			line += word + " "
		}
		b.WriteString(strings.TrimRight(line, " "))
	}

	return b.String()
}

func indent(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
