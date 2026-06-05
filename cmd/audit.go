package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/pipelinesentinel/internal/audit"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/report"
	"github.com/mdryaaan/pipelinesentinel/internal/rules"
)

var auditOpts struct {
	Format    string
	Output    string
	ListRules bool
}

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [path | owner/repo]",
		Short: "Audit workflows and print a summary",
		Long: `Audit reads every workflow file in the target and reports what the rules
matched, worst first.

The target may be a directory (audited from disk, with no network call), an
owner/repo reference (fetched over the GitHub API), or nothing at all, which
audits the current directory. --offline audits the workflows bundled in the
binary, which is the fastest way to see what the tool does.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  pipelinesentinel audit
  pipelinesentinel audit ./my-repo --fail-on critical
  pipelinesentinel audit mdryaaan/pipelinesentinel --format json
  pipelinesentinel audit --offline --reason --provider offline`,
		RunE: runAudit,
	}

	cmd.Flags().StringVarP(&auditOpts.Format, "format", "f", "digest",
		"output format: digest, markdown, json, sarif, or pr-comment")
	cmd.Flags().StringVarP(&auditOpts.Output, "output", "o", "",
		"write the output to a file instead of stdout")
	cmd.Flags().BoolVar(&auditOpts.ListRules, "list-rules", false,
		"list the rules and exit")

	return cmd
}

func runAudit(cmd *cobra.Command, args []string) error {
	if auditOpts.ListRules {
		return listRules(cmd)
	}

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

	runner := &audit.Runner{
		Source:   source,
		Config:   cfg,
		Provider: provider,
		Warn:     cmd.ErrOrStderr(),
	}

	result, err := runner.Run(cmd.Context())
	if err != nil {
		return err
	}

	// A baseline run must announce itself on stderr as well as in the report,
	// because a report is often skimmed and stderr is where a CI log looks.
	if result.Reasoning != nil && result.Reasoning.Disclaimer != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "pipelinesentinel: "+result.Reasoning.Disclaimer)
	}

	if err := writeAudit(cmd, result); err != nil {
		return err
	}

	threshold := cfg.FailThreshold()
	if result.FailsAt(threshold) {
		count := 0
		for _, f := range result.Active() {
			if f.Severity.AtLeast(threshold) {
				count++
			}
		}
		return &thresholdError{Worst: result.Worst(), Threshold: threshold, Count: count}
	}
	return nil
}

func writeAudit(cmd *cobra.Command, result report.Audit) error {
	format := auditOpts.Format
	if format == "" {
		format = formatDigest
	}
	return writeTo(cmd.OutOrStdout(), result, format, auditOpts.Output)
}

func listRules(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	for _, entry := range rules.NewEngine().Describe() {
		fmt.Fprintf(out, "%-18s %s\n", entry.ID, entry.Description)

		remediation, err := finding.RemediationFor(entry.ID)
		if err != nil {
			continue
		}
		fmt.Fprintf(out, "%-18s fix: %s\n\n", "", remediation.Summary)
	}
	return nil
}
