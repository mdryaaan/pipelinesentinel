package rules

import (
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

func TestPwnRequestRule(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantCount int
		wantSev   finding.Severity
		wantConf  finding.Confidence
		wantCites string
	}{
		{
			name: "checkout of the pull request head sha",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantCount: 1,
			wantSev:   finding.Critical,
			wantConf:  finding.Certain,
			wantCites: "head.sha",
		},
		{
			name: "checkout of the head ref",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			wantCount: 1,
			wantSev:   finding.Critical,
			wantConf:  finding.Certain,
			wantCites: "github.head_ref",
		},
		{
			name: "the trigger alone is reported but left ambiguous",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("hello")
`,
			wantCount: 1,
			wantSev:   finding.Medium,
			wantConf:  finding.Ambiguous,
			wantCites: "pull_request_target",
		},
		{
			name: "checkout without a ref takes the base branch and is safe",
			workflow: `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.Medium,
			wantConf:  finding.Ambiguous,
			wantCites: "pull_request_target",
		},
		{
			name: "the same checkout under pull_request is not a pwn request",
			workflow: `name: t
on:
  pull_request:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantCount: 0,
		},
		{
			name: "no pull_request_target trigger at all",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantCount: 0,
		},
	}

	rule := NewPwnRequestRule()

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
			assertCitesLineContaining(t, wf, got[0], tc.wantCites)
		})
	}
}

func TestPwnRequestRuleOnFixture(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-1.yml")

	got := NewPwnRequestRule().Check(wf)
	if len(got) != 1 {
		t.Fatalf("got %d findings %v, want 1", len(got), titles(got))
	}
	if got[0].Severity != finding.Critical {
		t.Errorf("severity = %s, want critical", got[0].Severity)
	}
	assertCitesLineContaining(t, wf, got[0], "github.event.pull_request.head.sha")
	if got[0].Step == "" {
		t.Error("finding should name the offending step")
	}
}

// The rule must not confuse a checkout in an unrelated action with the real
// one; only actions/checkout consumes a `ref:` this way.
func TestPwnRequestRuleIgnoresNonCheckoutSteps(t *testing.T) {
	wf := parseString(t, `name: t
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/deploy@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	got := NewPwnRequestRule().Check(wf)
	if len(got) != 1 || got[0].Confidence != finding.Ambiguous {
		t.Fatalf("expected only the ambiguous trigger finding, got %v", titles(got))
	}
}
