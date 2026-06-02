package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/github"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

func fixtureSource() github.Source {
	return github.NewFixtureSource(os.DirFS(filepath.Join("..", "..", "testdata", "fixtures")))
}

func TestRunAuditsEveryFixture(t *testing.T) {
	runner := &Runner{Source: fixtureSource(), Config: config.Default()}

	audit, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(audit.Files) != 5 {
		t.Fatalf("audited %d files, want 5", len(audit.Files))
	}
	if len(audit.Errors) != 0 {
		t.Errorf("unexpected parse errors: %+v", audit.Errors)
	}
	if audit.Clean() {
		t.Fatal("the vulnerable fixtures produced no findings")
	}
	if audit.Worst() != finding.Critical {
		t.Errorf("worst severity = %s, want critical", audit.Worst())
	}

	// The safe fixtures must contribute nothing, or every real repository will
	// drown in noise.
	for _, file := range audit.Files {
		if strings.Contains(file.Path, "safe-") && file.Findings != 0 {
			t.Errorf("%s produced %d findings, want 0", file.Path, file.Findings)
		}
	}

	// The reasoning pass is opt-in, so no section should appear.
	if audit.Reasoning != nil {
		t.Error("a reasoning summary appeared without --reason")
	}
}

func TestRunAppliesSeverityThreshold(t *testing.T) {
	cfg := config.Default()
	cfg.MinSeverity = string(finding.High)

	audit, err := (&Runner{Source: fixtureSource(), Config: cfg}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range audit.Active() {
		if !f.Severity.AtLeast(finding.High) {
			t.Errorf("%s survived a high threshold at severity %s", f.Location(), f.Severity)
		}
	}
}

func TestRunRespectsRuleSelectionAndIgnores(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []string{"unpinned-action"}

	only, err := (&Runner{Source: fixtureSource(), Config: cfg}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(only.Active()) == 0 {
		t.Fatal("rule selection produced no findings")
	}
	for _, f := range only.Active() {
		if f.RuleID != finding.RuleUnpinnedAction {
			t.Errorf("rule %s leaked past the selection", f.RuleID)
		}
	}

	cfg = config.Default()
	cfg.Ignore = []string{"unpinned-action"}
	without, err := (&Runner{Source: fixtureSource(), Config: cfg}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range without.Active() {
		if f.RuleID == finding.RuleUnpinnedAction {
			t.Error("an ignored rule still reported")
		}
	}
}

func TestRunSkipsIgnoredPaths(t *testing.T) {
	cfg := config.Default()
	cfg.IgnorePaths = []string{"vulnerable-*.yml"}

	audit, err := (&Runner{Source: fixtureSource(), Config: cfg}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.Files) != 2 {
		t.Fatalf("audited %d files, want only the 2 safe ones", len(audit.Files))
	}
	if !audit.Clean() {
		t.Errorf("expected a clean audit, got %d findings", len(audit.Active()))
	}
}

// One malformed workflow must not hide the findings in the others, and must
// not vanish either.
func TestRunRecordsUnparsableFilesAndKeepsGoing(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, github.WorkflowsDir)
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflows, "broken.yml"),
		[]byte("name: broken\n  on: [push]\n   bad indent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflows, "risky.yml"), []byte(
		"name: risky\non: [push]\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	audit, err := (&Runner{Source: github.NewLocalSource(dir), Config: config.Default()}).
		Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(audit.Errors) != 1 || !strings.Contains(audit.Errors[0].Path, "broken.yml") {
		t.Fatalf("the unparsable file was not recorded: %+v", audit.Errors)
	}
	if len(audit.Active()) == 0 {
		t.Error("findings from the parsable file were lost")
	}
}

func TestRunEscalatesAmbiguousFindings(t *testing.T) {
	cfg := config.Default()
	cfg.Reason = true
	cfg.Provider = llm.ProviderOffline

	var warnings bytes.Buffer
	runner := &Runner{
		Source:   fixtureSource(),
		Config:   cfg,
		Provider: llm.NewOffline(),
		Warn:     &warnings,
	}

	audit, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if audit.Reasoning == nil {
		t.Fatal("no reasoning summary was produced")
	}
	if audit.Reasoning.Disclaimer == "" {
		t.Error("the offline baseline was reported without its disclaimer")
	}
	if audit.Reasoning.Provider != llm.ProviderOffline {
		t.Errorf("provider = %q, want %q", audit.Reasoning.Provider, llm.ProviderOffline)
	}
	// Every fixture finding is deterministic and certain, so nothing should be
	// escalated — that is the design, not an accident.
	if audit.Reasoning.Candidates != audit.Reasoning.Reviewed+audit.Reasoning.Failed {
		t.Errorf("candidate accounting does not add up: %+v", audit.Reasoning)
	}
	if audit.Reasoning.Fabricated != 0 {
		t.Errorf("the baseline fabricated %d citations, which it cannot do by construction",
			audit.Reasoning.Fabricated)
	}
}

func TestRunSurfacesSourceErrors(t *testing.T) {
	runner := &Runner{
		Source: github.NewLocalSource(filepath.Join(t.TempDir(), "nowhere")),
		Config: config.Default(),
	}
	if _, err := runner.Run(context.Background()); err == nil {
		t.Fatal("expected an error from an unreadable source")
	}
}

func TestRunPopulatesTheSummary(t *testing.T) {
	audit, err := (&Runner{Source: fixtureSource(), Config: config.Default()}).
		Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if audit.Summary.Total != len(audit.Active()) {
		t.Errorf("summary total = %d, want %d", audit.Summary.Total, len(audit.Active()))
	}
	if audit.Summary.Worst != audit.Worst() {
		t.Errorf("summary worst = %s, want %s", audit.Summary.Worst, audit.Worst())
	}
	if len(audit.Summary.ByRule) == 0 {
		t.Error("the summary has no per-rule counts")
	}
}
