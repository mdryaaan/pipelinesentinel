package rules

import (
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

func TestSecretLeakRule(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantCount int
		wantSev   finding.Severity
		wantCites string
	}{
		{
			name: "echoing a secret",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.TOKEN }}"
`,
			wantCount: 1,
			wantSev:   finding.Critical,
			wantCites: "secrets.TOKEN",
		},
		{
			name: "printf is just as loud as echo",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: printf '%s' "${{ secrets.API_KEY }}"
`,
			wantCount: 1,
			wantSev:   finding.Critical,
			wantCites: "secrets.API_KEY",
		},
		{
			name: "secret as a long command-line flag",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}
`,
			wantCount: 1,
			wantSev:   finding.High,
			wantCites: "--token",
		},
		{
			name: "secret as a short command-line flag",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: docker login -u ci -p ${{ secrets.REGISTRY_PASSWORD }} ghcr.io
`,
			wantCount: 1,
			wantSev:   finding.High,
			wantCites: "docker login",
		},
		{
			name: "secret routed through env is the safe pattern",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: ./deploy.sh --token "$TOKEN"
`,
			wantCount: 0,
		},
		{
			name: "secret piped on stdin is not argv and not a log",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: cat secret.txt | docker login --password-stdin ghcr.io
`,
			wantCount: 0,
		},
		{
			name: "a commented-out line is not a leak",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # echo "${{ secrets.TOKEN }}"
          make build
`,
			wantCount: 0,
		},
		{
			name: "a non-secret expression is not a leak",
			workflow: `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
`,
			wantCount: 0,
		},
	}

	rule := NewSecretLeakRule()

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
		})
	}
}

// The leak is usually one line inside a longer script, so the finding has to
// point at that line and not at the `run:` key.
func TestSecretLeakRuleCitesTheOffendingLineOfAScript(t *testing.T) {
	wf := parseFixture(t, "vulnerable-workflow-3.yml")

	got := NewSecretLeakRule().Check(wf)
	if len(got) != 1 {
		t.Fatalf("got %d findings %v, want 1", len(got), titles(got))
	}
	assertCitesLineContaining(t, wf, got[0], "docker login")
}

func TestSecretLeakRuleSuggestsAnEnvVariable(t *testing.T) {
	wf := parseString(t, `name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}
`)

	got := NewSecretLeakRule().Check(wf)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Fix, "DEPLOY_TOKEN") {
		t.Errorf("fix should name the secret's env var, got:\n%s", got[0].Fix)
	}
}
