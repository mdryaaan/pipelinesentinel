package rules

import (
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

func TestScriptInjectionRule(t *testing.T) {
	tests := []struct {
		name       string
		workflow   string
		wantCount  int
		wantSev    finding.Severity
		wantConf   finding.Confidence
		wantCitesA string
	}{
		{
			name: "issue title inlined under an untrusted trigger",
			workflow: `name: t
on:
  issues:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`,
			wantCount:  1,
			wantSev:    finding.High,
			wantConf:   finding.Certain,
			wantCitesA: "github.event.issue.title",
		},
		{
			name: "pull_request_target raises it to critical",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`,
			wantCount:  1,
			wantSev:    finding.Critical,
			wantConf:   finding.Certain,
			wantCitesA: "github.event.pull_request.title",
		},
		{
			name: "push-only workflow is ambiguous, not certain",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
`,
			wantCount:  1,
			wantSev:    finding.Medium,
			wantConf:   finding.Ambiguous,
			wantCitesA: "head_commit.message",
		},
		{
			name: "value passed through env is the safe pattern",
			workflow: `name: t
on:
  issues:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
`,
			wantCount: 0,
		},
		{
			name: "trusted context is not untrusted input",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.repository }} ${{ github.run_id }}"
`,
			wantCount: 0,
		},
		{
			name: "secrets reference alone is not script injection",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "${{ secrets.TOKEN }}"
`,
			wantCount: 0,
		},
	}

	rule := NewScriptInjectionRule()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wf := parseString(t, tc.workflow)
			got := rule.Check(wf)

			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings %v, want %d", len(got), titles(got), tc.wantCount)
			}
			if tc.wantCount == 0 {
				return
			}
			if got[0].Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", got[0].Severity, tc.wantSev)
			}
			if got[0].Confidence != tc.wantConf {
				t.Errorf("confidence = %s, want %s", got[0].Confidence, tc.wantConf)
			}
			assertCitesLineContaining(t, wf, got[0], tc.wantCitesA)
		})
	}
}

// A multi-line block scalar is where line accounting usually goes wrong: the
// YAML node points at the `|` marker, not at the script.
func TestScriptInjectionRuleCitesLinesInsideBlockScalars(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-1.yml")

	got := NewScriptInjectionRule().Check(wf)
	if len(got) != 2 {
		t.Fatalf("got %d findings %v, want 2", len(got), titles(got))
	}
	assertCitesLineContaining(t, wf, got[0], "Thanks for the PR titled")
	assertCitesLineContaining(t, wf, got[1], "Branch:")
}

func TestScriptInjectionRuleSuggestsAnEnvVariable(t *testing.T) {
	wf := parseString(t, `name: t
on:
  issues:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`)

	got := NewScriptInjectionRule().Check(wf)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Fix, "ISSUE_TITLE") {
		t.Errorf("fix should name an env var derived from the context, got:\n%s", got[0].Fix)
	}
	if !strings.Contains(got[0].Fix, "env:") {
		t.Errorf("fix should show the env: block, got:\n%s", got[0].Fix)
	}
}

func TestSuggestEnvName(t *testing.T) {
	tests := map[string]string{
		"github.event.issue.title":           "ISSUE_TITLE",
		"github.event.pull_request.head.ref": "HEAD_REF",
		"github.event.comment.body":          "COMMENT_BODY",
		"github.head_ref":                    "GITHUB_HEAD_REF",
		"single":                             "UNTRUSTED_INPUT",
	}

	for input, want := range tests {
		if got := suggestEnvName(input); got != want {
			t.Errorf("suggestEnvName(%q) = %q, want %q", input, got, want)
		}
	}
}
