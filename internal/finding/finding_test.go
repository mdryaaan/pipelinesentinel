package finding

import (
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	base := Finding{
		RuleID:   RuleScriptInjection,
		Severity: High,
		File:     "ci.yml",
		Line:     12,
		Title:    "Untrusted input in a run block",
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"unknown rule", func(f *Finding) { f.RuleID = "made-up" }},
		{"unknown severity", func(f *Finding) { f.Severity = "catastrophic" }},
		{"zero line", func(f *Finding) { f.Line = 0 }},
		{"negative line", func(f *Finding) { f.Line = -3 }},
		{"blank title", func(f *Finding) { f.Title = "   " }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.mutate(&f)
			err := f.Validate()
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error %v does not wrap ErrInvalid", err)
			}
		})
	}
}

func TestNeedsReasoning(t *testing.T) {
	tests := []struct {
		name string
		f    Finding
		want bool
	}{
		{"ambiguous and unreviewed", Finding{Confidence: Ambiguous}, true},
		{"ambiguous but already reviewed", Finding{Confidence: Ambiguous, LLMReviewed: true}, false},
		{"certain findings are never escalated", Finding{Confidence: Certain}, false},
		{"probable findings are never escalated", Finding{Confidence: Probable}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.NeedsReasoning(); got != tc.want {
				t.Errorf("NeedsReasoning() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSortOrdersBySeverityThenLocation(t *testing.T) {
	findings := []Finding{
		{Severity: Low, File: "a.yml", Line: 1, RuleID: RuleUnpinnedAction},
		{Severity: Critical, File: "b.yml", Line: 40, RuleID: RulePwnRequest},
		{Severity: Critical, File: "a.yml", Line: 9, RuleID: RuleScriptInjection},
		{Severity: Critical, File: "a.yml", Line: 2, RuleID: RuleSecretLeak},
		{Severity: Medium, File: "a.yml", Line: 3, RuleID: RuleBroadPermission},
	}

	Sort(findings)

	want := []string{"a.yml:2", "a.yml:9", "b.yml:40", "a.yml:3", "a.yml:1"}
	for i, w := range want {
		if got := findings[i].Location(); got != w {
			t.Errorf("position %d = %s, want %s", i, got, w)
		}
	}
}

func TestCountsIgnoreDismissedFindings(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, RuleID: RulePwnRequest},
		{Severity: Critical, RuleID: RulePwnRequest, Dismissed: true},
		{Severity: High, RuleID: RuleSecretLeak},
	}

	bySeverity := CountBySeverity(findings)
	if bySeverity[Critical] != 1 {
		t.Errorf("critical count = %d, want 1", bySeverity[Critical])
	}

	byRule := CountByRule(findings)
	if byRule[RulePwnRequest] != 1 {
		t.Errorf("pwn-request count = %d, want 1", byRule[RulePwnRequest])
	}

	if got := len(Active(findings)); got != 2 {
		t.Errorf("Active returned %d findings, want 2", got)
	}
}

func TestSeverityLadder(t *testing.T) {
	order := []Severity{Critical, High, Medium, Low, Info}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() <= order[i].Rank() {
			t.Fatalf("%s does not outrank %s", order[i-1], order[i])
		}
	}

	if !High.AtLeast(Medium) {
		t.Error("high should clear a medium threshold")
	}
	if Low.AtLeast(High) {
		t.Error("low should not clear a high threshold")
	}
	if !Critical.AtLeast(Critical) {
		t.Error("AtLeast should be inclusive")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, in := range []string{"critical", "CRITICAL", " High ", "medium", "low", "info"} {
		if _, err := ParseSeverity(in); err != nil {
			t.Errorf("ParseSeverity(%q) failed: %v", in, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}
