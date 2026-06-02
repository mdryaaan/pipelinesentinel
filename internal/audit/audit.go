// Package audit wires the source, parser, rules, reasoning pass, and report
// together into one run.
package audit

import (
	"context"
	"io"
	"time"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/github"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/report"
	"github.com/mdryaaan/pipelinesentinel/internal/rules"
	"github.com/mdryaaan/pipelinesentinel/pkg/version"
)

// Runner performs one audit.
//
// Everything the audit depends on is injected: the source of workflows, the
// rule engine, and the optional reasoning provider. That is what lets the same
// code path serve `audit ./repo`, `audit owner/repo`, `audit --offline`, and
// the eval harness — so the numbers the eval reports describe the pipeline
// users actually run.
type Runner struct {
	Source   github.Source
	Config   config.Config
	Provider llm.Provider
	// Warn receives non-fatal problems. Nil discards them.
	Warn io.Writer
}

// Run audits every workflow the source provides.
//
// A file that fails to parse is recorded and skipped rather than aborting the
// run: one malformed workflow should not hide findings in the other nine. What
// it must never do is disappear, so it is reported in a section of its own.
func (r *Runner) Run(ctx context.Context) (report.Audit, error) {
	files, err := r.Source.Workflows(ctx)
	if err != nil {
		return report.Audit{}, err
	}

	engine := rules.NewEngine().Only(r.Config.Rules).Without(r.Config.Ignore)

	audit := report.Audit{
		Tool:        "pipelinesentinel",
		Version:     version.Version,
		Source:      r.Source.Name(),
		GeneratedAt: time.Now().UTC(),
	}

	var reviewer *llm.Reviewer
	var stats llm.Stats
	if r.Config.Reason && r.Provider != nil {
		reviewer = llm.NewReviewer(r.Provider)
		reviewer.Warn = r.Warn
		stats.ProviderName = r.Provider.Name()
		stats.ModelName = r.Provider.Model()
	}

	for _, file := range files {
		if r.Config.Ignored(file.Path) {
			continue
		}

		wf, err := parser.Parse(file.Path, file.Content)
		if err != nil {
			audit.Errors = append(audit.Errors, report.FileError{
				Path:   file.Path,
				Reason: err.Error(),
			})
			continue
		}

		found := engine.Run(wf)

		if reviewer != nil {
			var pass llm.Stats
			found, pass = reviewer.Review(ctx, wf, found)
			stats = merge(stats, pass)
		}

		found = filterSeverity(found, r.Config.Severity())

		audit.Files = append(audit.Files, report.FileResult{
			Path:     file.Path,
			URL:      file.URL,
			Lines:    wf.LineCount(),
			Findings: len(finding.Active(found)),
		})
		audit.Findings = append(audit.Findings, found...)
	}

	finding.Sort(audit.Findings)
	audit.Summary = report.Summarise(audit.Findings)

	if reviewer != nil {
		audit.Reasoning = report.SummariseReasoning(stats)
	}

	return audit, nil
}

// filterSeverity drops findings below the reporting threshold.
//
// Dismissed findings are kept regardless: they are part of the record of what
// the reasoning pass decided, and dropping them would make a dismissal
// indistinguishable from a finding that was never raised.
func filterSeverity(findings []finding.Finding, min finding.Severity) []finding.Finding {
	if min == finding.Info {
		return findings
	}

	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity.AtLeast(min) || f.Dismissed {
			out = append(out, f)
		}
	}
	return out
}

func merge(a, b llm.Stats) llm.Stats {
	a.Candidates += b.Candidates
	a.Reviewed += b.Reviewed
	a.Confirmed += b.Confirmed
	a.Dismissed += b.Dismissed
	a.Uncertain += b.Uncertain
	a.Failed += b.Failed
	a.TotalCited += b.TotalCited
	a.Fabricated += b.Fabricated
	return a
}
