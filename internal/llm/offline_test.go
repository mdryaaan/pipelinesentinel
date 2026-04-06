package llm

import (
	"context"
	"strings"
	"testing"
)

func TestOfflineNeverPresentsItselfAsAModel(t *testing.T) {
	p := NewOffline()

	if !strings.Contains(p.Model(), "not a model") {
		t.Errorf("Model() = %q, which could be mistaken for a model name", p.Model())
	}

	got, err := p.Review(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if !strings.HasPrefix(got.Reasoning, OfflineDisclaimer) {
		t.Errorf("reasoning does not lead with the disclaimer:\n%s", got.Reasoning)
	}
}

func TestOfflineReview(t *testing.T) {
	tests := []struct {
		name        string
		req         Request
		wantVerdict string
		wantDismiss bool
	}{
		{
			name: "script injection under an untrusted trigger",
			req: Request{
				RuleID:   "script-injection",
				Triggers: []string{"issues"},
				Context:  "  11 |   - run: |\n  12 |       echo \"${{ github.event.issue.title }}\"\n",
			},
			wantVerdict: VerdictExploitable,
		},
		{
			name: "script injection with the value bound to env",
			req: Request{
				RuleID:   "script-injection",
				Triggers: []string{"issues"},
				Context:  "  10 |   - env:\n  11 |       TITLE: ${{ github.event.issue.title }}\n  12 |     run: echo \"$TITLE\"\n",
			},
			wantVerdict: VerdictNotExploitable,
			wantDismiss: true,
		},
		{
			name: "script injection reachable only with push access",
			req: Request{
				RuleID:   "script-injection",
				Triggers: []string{"push"},
				Context:  "  12 |   - run: echo \"${{ github.event.head_commit.message }}\"\n",
			},
			wantVerdict: VerdictNotExploitable,
			// Deliberately below the dismissal threshold: needing write access
			// makes a finding lower priority, not false.
			wantDismiss: false,
		},
		{
			name: "pwn request with an untrusted checkout",
			req: Request{
				RuleID:   "pwn-request",
				Triggers: []string{"pull_request_target"},
				Context:  "  14 |     with:\n  15 |       ref: ${{ github.event.pull_request.head.sha }}\n",
			},
			wantVerdict: VerdictExploitable,
		},
		{
			name: "pwn request trigger with nothing checked out",
			req: Request{
				RuleID:   "pwn-request",
				Triggers: []string{"pull_request_target"},
				Context:  "   3 |   pull_request_target:\n   4 |     types: [opened]\n",
			},
			wantVerdict: VerdictUncertain,
		},
		{
			name: "a rule the baseline has no heuristic for",
			req: Request{
				RuleID:  "some-future-rule",
				Context: "   1 | name: t\n",
			},
			wantVerdict: VerdictUncertain,
		},
	}

	p := NewOffline()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Review(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Review failed: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q\nreasoning: %s", got.Verdict, tc.wantVerdict, got.Reasoning)
			}
			if got.Dismisses() != tc.wantDismiss {
				t.Errorf("Dismisses() = %v (confidence %.2f), want %v",
					got.Dismisses(), got.Confidence, tc.wantDismiss)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("baseline produced an invalid review: %v", err)
			}
		})
	}
}

// The baseline reads its citations out of the excerpt, so it cannot fabricate
// one. This test pins that property, because its citation score is reported
// next to a model's and the two are not comparable achievements.
func TestOfflineCitationsAlwaysComeFromTheExcerpt(t *testing.T) {
	req := Request{
		RuleID:    "script-injection",
		Triggers:  []string{"issue_comment"},
		FirstLine: 40,
		LastLine:  42,
		Context:   "  40 |   - run: |\n  41 |       echo \"${{ github.event.comment.body }}\"\n  42 |       make build\n",
	}

	got, err := NewOffline().Review(context.Background(), req)
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if len(got.CitedLines) == 0 {
		t.Fatal("expected at least one citation")
	}

	valid, invalid := VerifyCitations(got.CitedLines, req.FirstLine, req.LastLine)
	if len(invalid) != 0 {
		t.Errorf("baseline fabricated citations %v", invalid)
	}
	if len(valid) != len(got.CitedLines) {
		t.Errorf("only %d of %d citations verified", len(valid), len(got.CitedLines))
	}
}

func TestParseNumberedReadsTheSnippetFormat(t *testing.T) {
	excerpt := "  10 | jobs:\n  11 |   triage:\n  12 |     runs-on: ubuntu-latest\n"

	got := parseNumbered(excerpt)
	if len(got) != 3 {
		t.Fatalf("parsed %d lines, want 3", len(got))
	}
	if got[0].Number != 10 || !strings.Contains(got[0].Text, "jobs:") {
		t.Errorf("first line = %+v", got[0])
	}
	if got[2].Number != 12 {
		t.Errorf("last line number = %d, want 12", got[2].Number)
	}
}

func TestEnvBindingHintMatchesTheSnippetFormat(t *testing.T) {
	if !envBindingHint("  10 | env:\n") {
		t.Error("expected the numbered env: line to match")
	}
	if envBindingHint("  10 | run: make build\n") {
		t.Error("a run line should not look like an env binding")
	}
}
