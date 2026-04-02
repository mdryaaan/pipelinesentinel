package rules

import (
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

func TestEngineRunsEveryRuleAndSortsBySeverity(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-1.yml")

	got := NewEngine().Run(wf)
	if len(got) < 5 {
		t.Fatalf("got %d findings %v, want at least 5", len(got), titles(got))
	}

	seen := map[finding.RuleID]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
		if err := f.Validate(); err != nil {
			t.Errorf("invalid finding %s: %v", f.Title, err)
		}
	}

	for _, want := range []finding.RuleID{
		finding.RulePwnRequest,
		finding.RuleScriptInjection,
		finding.RuleBroadPermission,
		finding.RuleSecretLeak,
		finding.RuleUnpinnedAction,
	} {
		if !seen[want] {
			t.Errorf("rule %s produced no finding on the vulnerable fixture", want)
		}
	}

	for i := 1; i < len(got); i++ {
		if got[i-1].Severity.Rank() < got[i].Severity.Rank() {
			t.Fatalf("findings are not sorted by severity: %s before %s",
				got[i-1].Severity, got[i].Severity)
		}
	}
}

func TestEngineFindsNothingInSafeWorkflows(t *testing.T) {
	for _, name := range []string{"safe-workflow-1.yml", "safe-workflow-2.yml"} {
		t.Run(name, func(t *testing.T) {
			wf := parseFixture(t, name)
			if got := NewEngine().Run(wf); len(got) != 0 {
				t.Fatalf("safe fixture produced %d findings: %v", len(got), titles(got))
			}
		})
	}
}

func TestEngineRunAllMergesAndSortsAcrossWorkflows(t *testing.T) {
	a := parseFixture(t, "vulnerable-workflow-1.yml")
	b := parseFixture(t, "vulnerable-workflow-2.yml")
	engine := NewEngine()

	merged := engine.RunAll([]*parser.Workflow{a, b})
	if want := len(engine.Run(a)) + len(engine.Run(b)); len(merged) != want {
		t.Fatalf("RunAll returned %d findings, want %d", len(merged), want)
	}

	files := map[string]bool{}
	for i, f := range merged {
		files[f.File] = true
		if i > 0 && merged[i-1].Severity.Rank() < f.Severity.Rank() {
			t.Fatalf("merged findings are not sorted by severity")
		}
	}
	if len(files) != 2 {
		t.Errorf("merged findings cover %d files, want 2", len(files))
	}
}

func TestEngineOnlyAndWithout(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-1.yml")
	all := NewEngine().Run(wf)

	only := NewEngine().Only([]string{"unpinned-action"}).Run(wf)
	if len(only) == 0 {
		t.Fatal("Only returned no findings")
	}
	for _, f := range only {
		if f.RuleID != finding.RuleUnpinnedAction {
			t.Errorf("Only leaked rule %s", f.RuleID)
		}
	}

	without := NewEngine().Without([]string{"unpinned-action"}).Run(wf)
	if len(without) != len(all)-len(only) {
		t.Errorf("Without dropped %d findings, want %d", len(all)-len(without), len(only))
	}

	// A rule name nobody recognises must not silently disable every check.
	typo := NewEngine().Only([]string{"unpined-action"}).Run(wf)
	if len(typo) != len(all) {
		t.Errorf("an unknown rule name narrowed the engine to %d findings", len(typo))
	}
}

func TestEngineDescribeCoversEveryRule(t *testing.T) {
	got := NewEngine().Describe()
	if len(got) != 5 {
		t.Fatalf("got %d catalogue entries, want 5", len(got))
	}
	for i, entry := range got {
		if entry.Description == "" {
			t.Errorf("rule %s has no description", entry.ID)
		}
		if i > 0 && got[i-1].ID > entry.ID {
			t.Errorf("catalogue is not sorted: %s before %s", got[i-1].ID, entry.ID)
		}
	}
}

func TestKnownRuleIDs(t *testing.T) {
	ids := KnownRuleIDs()
	if len(ids) != 5 {
		t.Fatalf("got %d rule ids %v, want 5", len(ids), ids)
	}
}
