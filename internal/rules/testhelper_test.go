package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

// parseString parses an inline workflow document for a test case.
func parseString(t *testing.T, yaml string) *parser.Workflow {
	t.Helper()
	wf, err := parser.Parse("test.yml", []byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return wf
}

// parseFixture loads one of the checked-in workflow fixtures.
func parseFixture(t *testing.T, name string) *parser.Workflow {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	wf, err := parser.Parse(name, data)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return wf
}

// assertCitesLineContaining checks that the finding points at a source line
// holding the given text. Every rule test asserts this: a finding that names
// the wrong line is worse than no finding, because it sends the reader to
// innocent code.
func assertCitesLineContaining(t *testing.T, wf *parser.Workflow, f finding.Finding, want string) {
	t.Helper()
	got := wf.LineAt(f.Line)
	if !strings.Contains(got, want) {
		t.Errorf("finding %s cites line %d = %q, which does not contain %q",
			f.RuleID, f.Line, got, want)
	}
}

// titles collects finding titles for readable failure output.
func titles(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}
