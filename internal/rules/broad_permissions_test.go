package rules

import (
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

func TestBroadPermissionsRule(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantCount int
		wantSev   finding.Severity
		wantCites string
	}{
		{
			name: "write-all at workflow level",
			workflow: `name: t
on: [push]
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.High,
			wantCites: "write-all",
		},
		{
			name: "write-all at job level",
			workflow: `name: t
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.High,
			wantCites: "write-all",
		},
		{
			name: "no permissions block on a trusted trigger is only informational",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.Low,
			wantCites: "on:",
		},
		{
			name: "no permissions block on an untrusted trigger is serious",
			workflow: `name: t
on:
  issue_comment:
    types: [created]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.High,
			wantCites: "issue_comment",
		},
		{
			name: "read-only permissions are clean",
			workflow: `name: t
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 0,
		},
		{
			name: "contents write on a trusted trigger is accepted",
			workflow: `name: t
on: [push]
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make release
`,
			wantCount: 0,
		},
		{
			name: "contents write under an untrusted trigger is flagged",
			workflow: `name: t
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 1,
			wantSev:   finding.Medium,
			wantCites: "contents: write",
		},
		{
			name: "read-all is narrow enough",
			workflow: `name: t
on: [push]
permissions: read-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			wantCount: 0,
		},
	}

	rule := NewBroadPermissionsRule()

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
			assertCitesLineContaining(t, wf, got[0], tc.wantCites)
			if err := got[0].Validate(); err != nil {
				t.Errorf("invalid finding: %v", err)
			}
		})
	}
}

func TestBroadPermissionsRuleLeavesSafeFixturesAlone(t *testing.T) {
	for _, name := range []string{"safe-workflow-1.yml", "safe-workflow-2.yml"} {
		t.Run(name, func(t *testing.T) {
			wf := parseFixture(t, name)
			if got := NewBroadPermissionsRule().Check(wf); len(got) != 0 {
				t.Fatalf("safe fixture flagged: %v", titles(got))
			}
		})
	}
}

func TestBroadPermissionsRuleNamesTheJob(t *testing.T) {
	wf := parseString(t, `name: t
on: [push]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: make release
`)

	got := NewBroadPermissionsRule().Check(wf)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Job != "publish" {
		t.Errorf("job = %q, want %q", got[0].Job, "publish")
	}
}
