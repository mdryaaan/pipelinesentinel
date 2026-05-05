package eval

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/rules"
)

// Harness runs the detector over a labelled corpus.
//
// It drives the same rule engine the audit command uses rather than a
// re-implementation, so a score here is a statement about the tool people run.
// An eval that measures a parallel code path measures nothing.
type Harness struct {
	FS     fs.FS
	Corpus string
	Config config.Config
	// Provider enables the reasoning pass. Nil evaluates the rules alone,
	// which is the baseline every model run should be compared against.
	Provider llm.Provider
	// Warn receives per-case problems. Nil discards them.
	Warn io.Writer
}

// Result is a scored run with the metadata needed to interpret it.
type Result struct {
	RanAt    time.Time `json:"ran_at"`
	Corpus   string    `json:"corpus"`
	Cases    int       `json:"cases"`
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
	// Disclaimer is non-empty when the "provider" was not a model. Anything
	// printing these numbers must print this too.
	Disclaimer string        `json:"disclaimer,omitempty"`
	Duration   time.Duration `json:"duration_ms"`
	Scores     Scores        `json:"scores"`
	Reasoning  *llm.Stats    `json:"reasoning,omitempty"`
}

// Run evaluates every case in the corpus.
func (h *Harness) Run(ctx context.Context) (Result, error) {
	corpus, err := LoadCorpus(h.FS, h.Corpus)
	if err != nil {
		return Result{}, err
	}

	engine := rules.NewEngine().Only(h.Config.Rules).Without(h.Config.Ignore)

	var reviewer *llm.Reviewer
	var stats llm.Stats
	if h.Provider != nil {
		reviewer = llm.NewReviewer(h.Provider)
		reviewer.Warn = h.Warn
		stats.ProviderName = h.Provider.Name()
		stats.ModelName = h.Provider.Model()
	}

	started := time.Now()
	predictions := make([]Prediction, 0, len(corpus.Cases))

	for _, tc := range corpus.Cases {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		pred := Prediction{CaseID: tc.ID, Lines: map[string]int{}}

		data, err := fs.ReadFile(h.FS, tc.Resolve(h.Corpus))
		if err != nil {
			pred.Err = fmt.Errorf("reading case workflow: %w", err)
			predictions = append(predictions, pred)
			continue
		}

		wf, err := parser.Parse(tc.File, data)
		if err != nil {
			pred.Err = fmt.Errorf("parsing case workflow: %w", err)
			predictions = append(predictions, pred)
			continue
		}

		found := engine.Run(wf)
		if reviewer != nil {
			var pass llm.Stats
			found, pass = reviewer.Review(ctx, wf, found)
			stats = mergeStats(stats, pass)
		}

		for _, f := range finding.Active(found) {
			id := string(f.RuleID)
			if _, seen := pred.Lines[id]; !seen {
				pred.Lines[id] = f.Line
			}
			if !containsRule(pred.Rules, id) {
				pred.Rules = append(pred.Rules, id)
			}
		}
		sort.Strings(pred.Rules)

		predictions = append(predictions, pred)
	}

	result := Result{
		RanAt:    time.Now().UTC(),
		Corpus:   h.Corpus,
		Cases:    len(corpus.Cases),
		Provider: "rules only (no reasoning pass)",
		Model:    "n/a",
		Duration: time.Since(started),
		Scores:   Score(corpus, predictions),
	}

	if reviewer != nil {
		result.Provider = stats.ProviderName
		result.Model = stats.ModelName
		result.Reasoning = &stats
		if stats.ProviderName == llm.ProviderOffline {
			result.Disclaimer = llm.OfflineDisclaimer
		}
	}

	return result, nil
}

func containsRule(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func mergeStats(a, b llm.Stats) llm.Stats {
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
