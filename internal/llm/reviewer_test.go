package llm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

// stubProvider returns a scripted review, so reviewer behaviour can be tested
// without a daemon and without the offline baseline's own heuristics.
type stubProvider struct {
	review Review
	err    error
	calls  int
	last   Request
}

func (s *stubProvider) Name() string  { return "stub" }
func (s *stubProvider) Model() string { return "stub-model" }
func (s *stubProvider) Review(_ context.Context, req Request) (Review, error) {
	s.calls++
	s.last = req
	return s.review, s.err
}

func loadWorkflow(t *testing.T, name string) *parser.Workflow {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	wf, err := parser.Parse(name, data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return wf
}

func ambiguous() finding.Finding {
	return finding.Finding{
		RuleID:     finding.RulePwnRequest,
		Severity:   finding.Medium,
		File:       "vulnerable-workflow-1.yml",
		Line:       15,
		Job:        "preview",
		Title:      "Workflow uses pull_request_target",
		Detail:     "Deterministic detail.",
		Confidence: finding.Ambiguous,
	}
}

// Only ambiguous findings are escalated. Sending certain ones would spend
// inference re-answering a question a rule already answered, and would give a
// model the chance to overturn it.
func TestReviewerOnlyEscalatesAmbiguousFindings(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")
	stub := &stubProvider{review: Review{
		Verdict: VerdictExploitable, Confidence: 0.9, Reasoning: "Reachable.", CitedLines: []int{15},
	}}

	certain := ambiguous()
	certain.Confidence = finding.Certain
	probable := ambiguous()
	probable.Confidence = finding.Probable
	reviewed := ambiguous()
	reviewed.LLMReviewed = true

	findings := []finding.Finding{ambiguous(), certain, probable, reviewed}

	got, stats := NewReviewer(stub).Review(context.Background(), wf, findings)

	if stub.calls != 1 {
		t.Fatalf("provider called %d times, want 1", stub.calls)
	}
	if stats.Candidates != 1 || stats.Reviewed != 1 || stats.Confirmed != 1 {
		t.Errorf("unexpected stats: %+v", stats)
	}
	if !got[0].LLMReviewed {
		t.Error("the ambiguous finding was not marked reviewed")
	}
	if got[1].LLMReviewed || got[2].LLMReviewed {
		t.Error("a non-ambiguous finding was escalated")
	}
}

func TestReviewerRecordsAConfirmation(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")
	stub := &stubProvider{review: Review{
		Verdict:    VerdictExploitable,
		Confidence: 0.88,
		Reasoning:  "Any GitHub user can open a pull request.",
		CitedLines: []int{15},
		Mitigation: "Use pull_request instead.",
	}}

	got, _ := NewReviewer(stub).Review(context.Background(), wf, []finding.Finding{ambiguous()})

	f := got[0]
	if f.Dismissed {
		t.Fatal("an exploitable verdict must not dismiss the finding")
	}
	if f.LLMVerdict != VerdictExploitable || f.LLMScore != 0.88 {
		t.Errorf("verdict/score not recorded: %+v", f)
	}
	if f.Confidence != finding.Probable {
		t.Errorf("a confirmed finding should leave ambiguity, got %s", f.Confidence)
	}
	if !strings.Contains(f.Detail, "Any GitHub user") {
		t.Error("the reasoning was not attached to the finding")
	}
	if !strings.Contains(f.Detail, "Use pull_request instead") {
		t.Error("the mitigation was not attached to the finding")
	}
	if !strings.Contains(f.Detail, "Deterministic detail") {
		t.Error("the rule's own detail was overwritten")
	}
}

func TestReviewerDismissesOnlyOnAConfidentNegative(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")

	tests := []struct {
		name        string
		review      Review
		wantDismiss bool
	}{
		{"confident negative", Review{Verdict: VerdictNotExploitable, Confidence: 0.9, Reasoning: "Bound to env."}, true},
		{"hesitant negative", Review{Verdict: VerdictNotExploitable, Confidence: 0.5, Reasoning: "Probably fine."}, false},
		{"uncertain", Review{Verdict: VerdictUncertain, Confidence: 0.95, Reasoning: "Cannot tell."}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubProvider{review: tc.review}
			got, stats := NewReviewer(stub).Review(context.Background(), wf, []finding.Finding{ambiguous()})

			if got[0].Dismissed != tc.wantDismiss {
				t.Errorf("Dismissed = %v, want %v", got[0].Dismissed, tc.wantDismiss)
			}
			if tc.wantDismiss {
				if stats.Dismissed != 1 {
					t.Errorf("stats.Dismissed = %d, want 1", stats.Dismissed)
				}
				if got[0].DismissedWhy == "" {
					t.Error("a dismissal must record why")
				}
			}
		})
	}
}

// A citation that points at a line the model was never shown reads as evidence
// while being invented, so it is stripped and counted.
func TestReviewerStripsFabricatedCitations(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")
	stub := &stubProvider{review: Review{
		Verdict:    VerdictExploitable,
		Confidence: 0.9,
		Reasoning:  "Reachable.",
		CitedLines: []int{15, 900},
	}}

	var warnings bytes.Buffer
	reviewer := NewReviewer(stub)
	reviewer.Warn = &warnings

	got, stats := reviewer.Review(context.Background(), wf, []finding.Finding{ambiguous()})

	if len(got[0].CitedLines) != 1 || got[0].CitedLines[0] != 15 {
		t.Errorf("cited lines = %v, want [15]", got[0].CitedLines)
	}
	if len(got[0].Hallucinated) != 1 || got[0].Hallucinated[0] != 900 {
		t.Errorf("hallucinated lines = %v, want [900]", got[0].Hallucinated)
	}
	if stats.Fabricated != 1 || stats.TotalCited != 2 {
		t.Errorf("unexpected citation stats: %+v", stats)
	}
	if got := stats.CitationAccuracy(); got != 0.5 {
		t.Errorf("CitationAccuracy() = %v, want 0.5", got)
	}
	if !strings.Contains(warnings.String(), "900") {
		t.Errorf("the dropped citation was not reported: %q", warnings.String())
	}
}

// A provider failure degrades the audit; it must not discard the deterministic
// findings that were already correct.
func TestReviewerSurvivesProviderFailure(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")
	stub := &stubProvider{err: errors.New("connection refused")}

	var warnings bytes.Buffer
	reviewer := NewReviewer(stub)
	reviewer.Warn = &warnings

	got, stats := reviewer.Review(context.Background(), wf, []finding.Finding{ambiguous()})

	if len(got) != 1 {
		t.Fatalf("got %d findings, want the original 1", len(got))
	}
	if got[0].LLMReviewed || got[0].Dismissed {
		t.Error("a failed review must leave the finding untouched")
	}
	if stats.Failed != 1 || stats.Reviewed != 0 {
		t.Errorf("unexpected stats: %+v", stats)
	}
	if !strings.Contains(warnings.String(), "connection refused") {
		t.Errorf("the failure was not reported: %q", warnings.String())
	}
}

// The model is asked whether an attacker can reach the pattern, which it cannot
// answer without the trigger and the permissions.
func TestReviewerSendsTriggersPermissionsAndABoundedExcerpt(t *testing.T) {
	wf := loadWorkflow(t, "vulnerable-workflow-1.yml")
	stub := &stubProvider{review: Review{Verdict: VerdictUncertain, Confidence: 0.4, Reasoning: "x"}}

	NewReviewer(stub).Review(context.Background(), wf, []finding.Finding{ambiguous()})

	req := stub.last
	if len(req.Triggers) == 0 || req.Triggers[0] != "pull_request_target" {
		t.Errorf("triggers = %v, want pull_request_target", req.Triggers)
	}
	if !strings.Contains(req.Permissions, "write-all") {
		t.Errorf("permissions = %q, want the declared write-all", req.Permissions)
	}
	if req.FirstLine < 1 || req.LastLine > wf.LineCount() {
		t.Errorf("excerpt range %d-%d escapes the file (%d lines)",
			req.FirstLine, req.LastLine, wf.LineCount())
	}
	if !strings.Contains(req.Context, "github.event.pull_request.head.sha") {
		t.Error("the excerpt does not include the cited line")
	}
	// The numbers must be in the text, or a citation cannot be checked.
	if !strings.Contains(req.Context, "  15 |") {
		t.Errorf("the excerpt is not numbered:\n%s", req.Context)
	}
}

func TestCitationAccuracyWithNoCitations(t *testing.T) {
	if got := (Stats{}).CitationAccuracy(); got != 0 {
		t.Errorf("CitationAccuracy() = %v, want 0", got)
	}
}
