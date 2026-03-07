package rules

import (
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

func TestUnpinnedActionRule(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantCount int
		wantSev   finding.Severity
	}{
		{
			name: "tag reference is flagged",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantCount: 1,
			wantSev:   finding.Medium,
		},
		{
			name: "branch reference is flagged",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`,
			wantCount: 1,
			wantSev:   finding.Medium,
		},
		{
			name: "third-party action outranks a first-party one",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@latest
`,
			wantCount: 1,
			wantSev:   finding.High,
		},
		{
			name: "missing reference entirely is flagged",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action
`,
			wantCount: 1,
			wantSev:   finding.High,
		},
		{
			name: "full sha is accepted",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`,
			wantCount: 0,
		},
		{
			name: "abbreviated sha is not a pin",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd719
`,
			wantCount: 1,
			wantSev:   finding.Medium,
		},
		{
			name: "local action is out of scope",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
`,
			wantCount: 0,
		},
		{
			name: "docker action is out of scope",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.20
`,
			wantCount: 0,
		},
	}

	rule := NewUnpinnedActionRule()

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
			assertCitesLineContaining(t, wf, got[0], "uses:")
			if err := got[0].Validate(); err != nil {
				t.Errorf("invalid finding: %v", err)
			}
		})
	}
}

// A SHA-pinned action carrying a `# v4.2.2` comment is the recommended form.
// Matching the version out of the trailing comment instead of the ref itself
// would flag exactly the workflows that got it right.
func TestUnpinnedActionRuleIgnoresVersionComments(t *testing.T) {
	wf := parseFixture(t, "safe-workflow-1.yml")

	if got := NewUnpinnedActionRule().Check(wf); len(got) != 0 {
		t.Fatalf("SHA-pinned actions with version comments were flagged: %v", titles(got))
	}
}

func TestUnpinnedActionRuleReportsEveryStep(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-3.yml")

	got := NewUnpinnedActionRule().Check(wf)
	if len(got) != 2 {
		t.Fatalf("got %d findings %v, want 2", len(got), titles(got))
	}
	assertCitesLineContaining(t, wf, got[0], "actions/checkout@v4")
	assertCitesLineContaining(t, wf, got[1], "actions/setup-go@v5")
}
