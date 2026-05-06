package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

func realCorpus() (string, string) {
	return filepath.Join("..", "..", "testdata", "eval"), "labeled-cases.json"
}

func TestCorpusIsWellFormed(t *testing.T) {
	dir, name := realCorpus()
	corpus, err := LoadCorpus(os.DirFS(dir), name)
	if err != nil {
		t.Fatalf("the shipped corpus does not load: %v", err)
	}

	if len(corpus.Cases) < 40 {
		t.Errorf("corpus has %d cases, want at least 40", len(corpus.Cases))
	}

	// Every rule needs positive cases, and the corpus needs clean cases, or
	// precision cannot be measured at all.
	perCategory := map[string]int{}
	for _, tc := range corpus.Cases {
		perCategory[tc.Category]++

		path := filepath.Join(dir, tc.File)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("case %s points at a missing file %s", tc.ID, tc.File)
		}
		if tc.Description == "" {
			t.Errorf("case %s has no description", tc.ID)
		}
	}

	if perCategory[NoFinding] < 5 {
		t.Errorf("only %d clean cases; precision is not measurable without safe look-alikes",
			perCategory[NoFinding])
	}
	for _, category := range corpus.Categories() {
		if category != NoFinding && perCategory[category] < 5 {
			t.Errorf("category %s has only %d cases", category, perCategory[category])
		}
	}
}

func TestCorpusValidationCatchesLabellingMistakes(t *testing.T) {
	tests := map[string]string{
		"no cases":            `{"version":1,"cases":[]}`,
		"missing id":          `{"cases":[{"file":"a.yml","category":"clean"}]}`,
		"duplicate id":        `{"cases":[{"id":"a","file":"a.yml","category":"clean"},{"id":"a","file":"b.yml","category":"clean"}]}`,
		"missing file":        `{"cases":[{"id":"a","category":"clean"}]}`,
		"unknown category":    `{"cases":[{"id":"a","file":"a.yml","category":"typo-rule","expected":["typo-rule"]}]}`,
		"unknown rule":        `{"cases":[{"id":"a","file":"a.yml","category":"secret-leak","expected":["secrets-leak"]}]}`,
		"clean but expecting": `{"cases":[{"id":"a","file":"a.yml","category":"clean","expected":["secret-leak"]}]}`,
		"labelled but empty":  `{"cases":[{"id":"a","file":"a.yml","category":"secret-leak","expected":[]}]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"cases.json": &fstest.MapFile{Data: []byte(body)}}
			if _, err := LoadCorpus(fsys, "cases.json"); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestHarnessScoresTheShippedCorpus(t *testing.T) {
	dir, name := realCorpus()
	h := &Harness{FS: os.DirFS(dir), Corpus: name, Config: config.Default()}

	result, err := h.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(result.Scores.Failures) != 0 {
		t.Errorf("cases failed to evaluate: %v", result.Scores.Failures)
	}
	if result.Scores.Cases != result.Cases {
		t.Errorf("scored %d cases, ran %d", result.Scores.Cases, result.Cases)
	}

	// The corpus is a regression suite: it was written alongside the rules, so
	// it is expected to pass. A drop here means a rule changed behaviour.
	if result.Scores.Accuracy < 1 {
		var missed []string
		for _, r := range result.Scores.Results {
			if !r.Correct {
				missed = append(missed, r.CaseID+" expected "+strings.Join(r.Expected, ",")+
					" got "+strings.Join(r.Predicted, ","))
			}
		}
		t.Errorf("accuracy dropped to %.3f:\n%s", result.Scores.Accuracy, strings.Join(missed, "\n"))
	}
	if result.Scores.CitationAccuracy() < 1 {
		t.Errorf("only %d of %d findings cited the labelled line",
			result.Scores.LinesCorrect, result.Scores.LinesChecked)
	}

	// Without a provider the run is rules-only and must say so rather than
	// implying a model was involved.
	if !strings.Contains(result.Provider, "rules only") {
		t.Errorf("provider = %q, want it to name the rules-only path", result.Provider)
	}
	if result.Reasoning != nil {
		t.Error("a reasoning summary appeared without a provider")
	}
}

func TestHarnessWithTheOfflineBaselineCarriesADisclaimer(t *testing.T) {
	dir, name := realCorpus()
	h := &Harness{
		FS: os.DirFS(dir), Corpus: name, Config: config.Default(),
		Provider: llm.NewOffline(),
	}

	result, err := h.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.Disclaimer == "" {
		t.Fatal("baseline numbers were produced without a disclaimer")
	}
	if result.Reasoning == nil {
		t.Fatal("no reasoning stats were recorded")
	}
	if result.Reasoning.Fabricated != 0 {
		t.Errorf("the baseline reported %d fabricated citations, which it cannot produce",
			result.Reasoning.Fabricated)
	}
}

func TestHarnessRecordsUnreadableCases(t *testing.T) {
	fsys := fstest.MapFS{
		"cases.json": &fstest.MapFile{Data: []byte(
			`{"version":1,"cases":[{"id":"a","file":"missing.yml","category":"clean","expected":[]}]}`)},
	}

	result, err := (&Harness{FS: fsys, Corpus: "cases.json", Config: config.Default()}).
		Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(result.Scores.Failures) != 1 {
		t.Fatalf("expected one recorded failure, got %v", result.Scores.Failures)
	}
	if !strings.Contains(result.Scores.Failures[0], "a:") {
		t.Errorf("the failure does not name the case: %v", result.Scores.Failures)
	}
}

func TestHarnessStopsOnACancelledContext(t *testing.T) {
	dir, name := realCorpus()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (&Harness{FS: os.DirFS(dir), Corpus: name, Config: config.Default()}).Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestScoreArithmetic(t *testing.T) {
	corpus := Corpus{Cases: []Case{
		{ID: "hit", File: "a.yml", Category: "secret-leak", Expected: []string{"secret-leak"}, ExpectedLine: 7},
		{ID: "miss", File: "b.yml", Category: "pwn-request", Expected: []string{"pwn-request"}},
		{ID: "extra", File: "c.yml", Category: "secret-leak", Expected: []string{"secret-leak"}},
		{ID: "quiet", File: "d.yml", Category: NoFinding},
		{ID: "noisy", File: "e.yml", Category: NoFinding},
	}}

	predictions := []Prediction{
		{CaseID: "hit", Rules: []string{"secret-leak"}, Lines: map[string]int{"secret-leak": 7}},
		{CaseID: "miss"},
		{CaseID: "extra", Rules: []string{"secret-leak", "unpinned-action"}},
		{CaseID: "quiet"},
		{CaseID: "noisy", Rules: []string{"unpinned-action"}},
	}

	s := Score(corpus, predictions)

	if s.ExactMatches != 2 || s.Cases != 5 {
		t.Errorf("exact matches = %d of %d, want 2 of 5", s.ExactMatches, s.Cases)
	}
	if s.CleanCases != 2 || s.CleanCorrect != 1 {
		t.Errorf("clean scoring = %d/%d, want 1/2", s.CleanCorrect, s.CleanCases)
	}
	if s.LinesChecked != 1 || s.LinesCorrect != 1 {
		t.Errorf("line scoring = %d/%d, want 1/1", s.LinesCorrect, s.LinesChecked)
	}

	byRule := map[string]RuleScore{}
	for _, r := range s.PerRule {
		byRule[r.Rule] = r
	}

	secret := byRule["secret-leak"]
	if secret.TP != 2 || secret.FP != 0 || secret.FN != 0 {
		t.Errorf("secret-leak = %+v, want 2 TP", secret)
	}
	pwn := byRule["pwn-request"]
	if pwn.TP != 0 || pwn.FN != 1 {
		t.Errorf("pwn-request = %+v, want a false negative", pwn)
	}
	unpinned := byRule["unpinned-action"]
	if unpinned.FP != 2 || unpinned.Precision != 0 {
		t.Errorf("unpinned-action = %+v, want 2 false positives", unpinned)
	}

	// A missed case must land in the clean column so the matrix shows it.
	if s.Confusion["pwn-request"][NoFinding] != 1 {
		t.Errorf("a miss did not land in the clean column: %v", s.Confusion["pwn-request"])
	}
	if s.Confusion[NoFinding]["unpinned-action"] != 1 {
		t.Errorf("a false positive did not land in the matrix: %v", s.Confusion[NoFinding])
	}

	if s.Accuracy != 0.4 {
		t.Errorf("accuracy = %v, want 0.4", s.Accuracy)
	}
}

func TestScoreHandlesEmptyDenominators(t *testing.T) {
	s := Score(Corpus{Cases: []Case{{ID: "a", File: "a.yml", Category: NoFinding}}},
		[]Prediction{{CaseID: "a"}})

	if s.CitationAccuracy() != 0 {
		t.Errorf("CitationAccuracy() = %v with nothing checked, want 0", s.CitationAccuracy())
	}
	if s.MacroF1 != 0 {
		t.Errorf("MacroF1 = %v with no rules scored, want 0", s.MacroF1)
	}
	if s.CleanAccuracy() != 1 {
		t.Errorf("CleanAccuracy() = %v, want 1", s.CleanAccuracy())
	}
}

func TestRenderers(t *testing.T) {
	dir, name := realCorpus()
	result, err := (&Harness{FS: os.DirFS(dir), Corpus: name, Config: config.Default()}).
		Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var jsonOut bytes.Buffer
	if err := WriteJSON(&jsonOut, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var back Result
	if err := json.Unmarshal(jsonOut.Bytes(), &back); err != nil {
		t.Fatalf("eval JSON does not round trip: %v", err)
	}
	if back.Scores.Cases != result.Scores.Cases {
		t.Error("case count did not survive the round trip")
	}

	var md bytes.Buffer
	if err := WriteMarkdown(&md, result); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	out := md.String()
	for _, want := range []string{
		"## Evaluation", "Exact-match accuracy", "Macro F1",
		"### Per-rule", "### Confusion matrix", "labelled \\ fired",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

func TestMarkdownLeadsWithTheBaselineDisclaimer(t *testing.T) {
	dir, name := realCorpus()
	result, err := (&Harness{
		FS: os.DirFS(dir), Corpus: name, Config: config.Default(), Provider: llm.NewOffline(),
	}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var md bytes.Buffer
	if err := WriteMarkdown(&md, result); err != nil {
		t.Fatal(err)
	}
	out := md.String()

	disclaimer := strings.Index(out, "not by an LLM")
	firstNumber := strings.Index(out, "Exact-match accuracy")
	if disclaimer < 0 {
		t.Fatal("the disclaimer is missing entirely")
	}
	if disclaimer > firstNumber {
		t.Error("the disclaimer appears after the numbers it qualifies")
	}
}

func TestSummaryIsOneLine(t *testing.T) {
	s := Scores{Cases: 45, ExactMatches: 45, Accuracy: 1, MacroF1: 1, CleanCases: 12, CleanCorrect: 12}
	got := s.Summary()
	if strings.Contains(got, "\n") {
		t.Errorf("Summary() spans multiple lines: %q", got)
	}
	if !strings.Contains(got, "45/45") {
		t.Errorf("Summary() = %q", got)
	}
}
