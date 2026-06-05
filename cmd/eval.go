package cmd

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/pipelinesentinel/internal/eval"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

var evalOpts struct {
	Corpus   string
	Dir      string
	Format   string
	Output   string
	MinScore float64
}

func newEvalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Score the detector against the labelled corpus",
		Long: `Eval runs the rules over a corpus of labelled workflows and reports
precision, recall, F1 per rule, a confusion matrix, and how often a finding
cited the line it was labelled against.

By default it scores the rules alone. Adding --reason scores the rules plus the
reasoning pass, which is the comparison that actually matters: a model that
cannot beat the deterministic baseline is not earning its inference cost.

The corpus ships inside the binary, so this runs anywhere with no network.`,
		Args: cobra.NoArgs,
		Example: `  pipelinesentinel eval
  pipelinesentinel eval --format markdown
  pipelinesentinel eval --reason --provider offline
  pipelinesentinel eval --dir ./testdata/eval --min-score 0.9`,
		RunE: runEval,
	}

	cmd.Flags().StringVar(&evalOpts.Corpus, "corpus", "labeled-cases.json",
		"corpus file name within the eval directory")
	cmd.Flags().StringVar(&evalOpts.Dir, "dir", "",
		"read the corpus from this directory instead of the bundled one")
	cmd.Flags().StringVarP(&evalOpts.Format, "format", "f", "text",
		"output format: text, markdown, or json")
	cmd.Flags().StringVarP(&evalOpts.Output, "output", "o", "",
		"write the output to a file instead of stdout")
	cmd.Flags().Float64Var(&evalOpts.MinScore, "min-score", 0,
		"exit non-zero if exact-match accuracy falls below this")

	return cmd
}

func runEval(cmd *cobra.Command, args []string) error {
	cfg, err := resolveConfig(cmd)
	if err != nil {
		return err
	}

	var fsys fs.FS
	switch {
	case evalOpts.Dir != "":
		fsys = os.DirFS(evalOpts.Dir)
	case embedded.Eval != nil:
		fsys = embedded.Eval
	default:
		return fmt.Errorf("this binary was built without the eval corpus; pass --dir")
	}

	var provider llm.Provider
	if cfg.Reason {
		provider, err = llm.New(cfg.LLMOptions())
		if err != nil {
			return err
		}
	}

	harness := &eval.Harness{
		FS:       fsys,
		Corpus:   evalOpts.Corpus,
		Config:   cfg,
		Provider: provider,
		Warn:     cmd.ErrOrStderr(),
	}

	result, err := harness.Run(cmd.Context())
	if err != nil {
		return err
	}

	if result.Disclaimer != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "pipelinesentinel: "+result.Disclaimer)
	}

	out := cmd.OutOrStdout()
	if evalOpts.Output != "" {
		file, err := os.Create(evalOpts.Output)
		if err != nil {
			return fmt.Errorf("creating %s: %w", evalOpts.Output, err)
		}
		defer func() { _ = file.Close() }()
		out = file
	}

	switch evalOpts.Format {
	case "text", "":
		if err := writeEvalText(cmd, result); err != nil {
			return err
		}
	case formatMarkdown, formatMarkdownS:
		if err := eval.WriteMarkdown(out, result); err != nil {
			return err
		}
	case formatJSON:
		if err := eval.WriteJSON(out, result); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (want text, %s, or %s)",
			evalOpts.Format, formatMarkdown, formatJSON)
	}

	// A regression gate belongs in the eval command itself: it is the only
	// place that knows what the corpus measured.
	if evalOpts.MinScore > 0 && result.Scores.Accuracy < evalOpts.MinScore {
		return fmt.Errorf("exact-match accuracy %.3f is below the required %.3f",
			result.Scores.Accuracy, evalOpts.MinScore)
	}
	return nil
}

func writeEvalText(cmd *cobra.Command, result eval.Result) error {
	out := cmd.OutOrStdout()
	if evalOpts.Output != "" {
		return eval.WriteMarkdown(out, result)
	}

	if result.Disclaimer != "" {
		fmt.Fprintf(out, "%s\n\n", result.Disclaimer)
	}

	s := result.Scores
	fmt.Fprintf(out, "corpus   %s (%d cases)\n", result.Corpus, result.Cases)
	fmt.Fprintf(out, "detector %s\n", result.Provider)
	if result.Model != "" && result.Model != "n/a" {
		fmt.Fprintf(out, "model    %s\n", result.Model)
	}
	fmt.Fprintf(out, "elapsed  %s\n\n", result.Duration.Round(1e6))

	fmt.Fprintf(out, "exact-match accuracy  %.1f%% (%d/%d)\n",
		s.Accuracy*100, s.ExactMatches, s.Cases)
	fmt.Fprintf(out, "macro F1              %.3f\n", s.MacroF1)
	fmt.Fprintf(out, "clean left silent     %.1f%% (%d/%d)\n",
		s.CleanAccuracy()*100, s.CleanCorrect, s.CleanCases)
	if s.LinesChecked > 0 {
		fmt.Fprintf(out, "cited the right line  %.1f%% (%d/%d)\n\n",
			s.CitationAccuracy()*100, s.LinesCorrect, s.LinesChecked)
	}

	fmt.Fprintf(out, "%-20s %9s %7s %7s %5s %4s %4s\n",
		"rule", "precision", "recall", "f1", "tp", "fp", "fn")
	for _, rule := range s.PerRule {
		fmt.Fprintf(out, "%-20s %9.3f %7.3f %7.3f %5d %4d %4d\n",
			rule.Rule, rule.Precision, rule.Recall, rule.F1, rule.TP, rule.FP, rule.FN)
	}

	if len(s.Failures) > 0 {
		fmt.Fprintf(out, "\n%d case(s) could not be evaluated:\n", len(s.Failures))
		for _, f := range s.Failures {
			fmt.Fprintf(out, "  %s\n", f)
		}
	}

	if r := result.Reasoning; r != nil && r.Candidates > 0 {
		fmt.Fprintf(out, "\nreasoning pass: %d escalated, %d confirmed, %d dismissed, %d uncertain\n",
			r.Candidates, r.Confirmed, r.Dismissed, r.Uncertain)
		if r.TotalCited > 0 {
			fmt.Fprintf(out, "citations: %d of %d verified (%.1f%%)\n",
				r.TotalCited-r.Fabricated, r.TotalCited, r.CitationAccuracy()*100)
		}
	}

	return nil
}
