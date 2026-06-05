package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/pipelinesentinel/internal/audit"
)

var reportOpts struct {
	Output   string
	Format   string
	JSONPath string
}

func newReportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report [path | owner/repo]",
		Short: "Write a full audit report to a file",
		Long: `Report runs an audit and writes the full result somewhere durable.

It is the command a CI job runs: --format markdown for a job summary,
--format pr-comment for a pull request, --format sarif to upload to GitHub code
scanning, and --json to keep the machine-readable record alongside whichever
human-readable form you chose.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  pipelinesentinel report --offline -o report.md
  pipelinesentinel report ./my-repo --format pr-comment -o comment.md
  pipelinesentinel report ./my-repo --format sarif -o results.sarif
  pipelinesentinel report ./my-repo -o report.md --json audit.json`,
		RunE: runReport,
	}

	cmd.Flags().StringVarP(&reportOpts.Output, "output", "o", "",
		"file to write (default: stdout)")
	cmd.Flags().StringVarP(&reportOpts.Format, "format", "f", "markdown",
		"output format: markdown, json, sarif, pr-comment, or digest")
	cmd.Flags().StringVar(&reportOpts.JSONPath, "json", "",
		"also write the machine-readable result to this path")

	return cmd
}

func runReport(cmd *cobra.Command, args []string) error {
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

	if result.Reasoning != nil && result.Reasoning.Disclaimer != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "pipelinesentinel: "+result.Reasoning.Disclaimer)
	}

	format := reportOpts.Format
	if format == "" {
		format = formatMarkdown
	}
	if err := writeTo(cmd.OutOrStdout(), result, format, reportOpts.Output); err != nil {
		return err
	}

	// The JSON copy is written even when the primary format is human-readable,
	// so a job can post a comment and still keep the record a policy gate or a
	// dashboard reads.
	if reportOpts.JSONPath != "" {
		if err := writeTo(cmd.OutOrStdout(), result, formatJSON, reportOpts.JSONPath); err != nil {
			return err
		}
	}

	if reportOpts.Output != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d finding(s))\n",
			reportOpts.Output, len(result.Active()))
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
