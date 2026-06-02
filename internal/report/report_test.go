package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

func sampleAudit() Audit {
	return Audit{
		Tool:        "pipelinesentinel",
		Version:     "v0.1.0",
		Source:      "mdryaaan/pipelinesentinel",
		GeneratedAt: time.Date(2026, 8, 16, 9, 30, 0, 0, time.UTC),
		Files: []FileResult{
			{Path: ".github/workflows/ci.yml", Lines: 40, Findings: 2},
			{Path: ".github/workflows/release.yml", Lines: 26, Findings: 0},
		},
		Findings: []finding.Finding{
			{
				RuleID:     finding.RulePwnRequest,
				Severity:   finding.Critical,
				File:       ".github/workflows/ci.yml",
				Line:       15,
				Job:        "preview",
				Title:      "pull_request_target checks out untrusted pull request code",
				Detail:     "The fork's code runs with the base repository's secrets.",
				Snippet:    "  15 |           ref: ${{ github.event.pull_request.head.sha }}",
				Confidence: finding.Certain,
				Fix:        "--- a/ci.yml\n+++ b/ci.yml\n-          ref: x\n",
			},
			{
				RuleID:     finding.RuleUnpinnedAction,
				Severity:   finding.Medium,
				File:       ".github/workflows/ci.yml",
				Line:       13,
				Title:      "Action \"actions/checkout@v4\" is not pinned to a commit SHA",
				Detail:     "A tag is a mutable pointer.",
				Confidence: finding.Certain,
			},
			{
				RuleID:       finding.RuleScriptInjection,
				Severity:     finding.High,
				File:         ".github/workflows/ci.yml",
				Line:         19,
				Title:        "Untrusted input in a run block",
				Detail:       "Interpolated before the shell parses it.",
				Confidence:   finding.Ambiguous,
				Dismissed:    true,
				DismissedWhy: "The value is bound to an env variable.",
			},
		},
	}
}

func TestAuditAggregates(t *testing.T) {
	audit := sampleAudit()

	if got := len(audit.Active()); got != 2 {
		t.Errorf("Active() returned %d findings, want 2 (the dismissed one must be excluded)", got)
	}
	if audit.Worst() != finding.Critical {
		t.Errorf("Worst() = %s, want critical", audit.Worst())
	}
	if audit.Clean() {
		t.Error("an audit with findings is not clean")
	}
	if counts := audit.Counts(); counts[finding.High] != 0 {
		t.Errorf("the dismissed high finding is still counted: %v", counts)
	}

	if !audit.FailsAt(finding.High) {
		t.Error("a critical finding should fail a high threshold")
	}

	clean := Audit{Files: []FileResult{{Path: "ci.yml"}}}
	if !clean.Clean() || clean.Worst() != finding.Info || clean.FailsAt(finding.Low) {
		t.Error("an empty audit should be clean, info, and non-failing")
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleAudit()); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var back Audit
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(back.Findings) != 3 {
		t.Errorf("round-tripped %d findings, want 3 (dismissed ones stay in the record)", len(back.Findings))
	}
	if back.Findings[0].Line != 15 {
		t.Errorf("line numbers did not survive the round trip: %+v", back.Findings[0])
	}
	// Expression syntax must stay readable rather than being HTML-escaped.
	if strings.Contains(buf.String(), `&`) {
		t.Error("output was HTML-escaped")
	}
}

func TestWriteSARIFIsIngestible(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleAudit()); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 active findings", len(results))
	}

	first := results[0].(map[string]any)
	if first["level"] != "error" {
		t.Errorf("a critical finding mapped to level %v, want error", first["level"])
	}

	loc := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	region := loc["region"].(map[string]any)
	if region["startLine"].(float64) != 15 {
		t.Errorf("startLine = %v, want 15", region["startLine"])
	}
}

func TestWriteMarkdownCoversTheAudit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleAudit()); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# Workflow security audit",
		"mdryaaan/pipelinesentinel",
		"pull_request_target checks out untrusted",
		".github/workflows/ci.yml:15",
		"```yaml",
		"```diff",
		"**How to fix:**",
		"## Files audited",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q", want)
		}
	}

	// A dismissed finding must not appear in the body.
	if strings.Contains(out, "Untrusted input in a run block") {
		t.Error("a dismissed finding was rendered")
	}

	// Severity order: critical before medium.
	if strings.Index(out, "### 🛑 Critical") > strings.Index(out, "### 🟠 Medium") {
		t.Error("findings are not ordered worst-first")
	}
}

func TestWriteMarkdownOnACleanAudit(t *testing.T) {
	var buf bytes.Buffer
	clean := Audit{Tool: "pipelinesentinel", Files: []FileResult{{Path: "ci.yml"}}}
	if err := WriteMarkdown(&buf, clean); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Errorf("a clean audit should say so:\n%s", buf.String())
	}
}

// A file that could not be parsed was not audited. Reporting the rest as clean
// without saying so would be the most dangerous way for this tool to be wrong.
func TestReportsNameFilesThatCouldNotBeAudited(t *testing.T) {
	audit := sampleAudit()
	audit.Errors = []FileError{{Path: ".github/workflows/broken.yml", Reason: "yaml: line 4: did not find expected key"}}

	var md, digest bytes.Buffer
	if err := WriteMarkdown(&md, audit); err != nil {
		t.Fatal(err)
	}
	if err := WriteDigest(&digest, audit); err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{"markdown": md.String(), "digest": digest.String()} {
		if !strings.Contains(out, "broken.yml") {
			t.Errorf("%s output does not mention the unparsed file", name)
		}
		if !strings.Contains(out, "did not find expected key") {
			t.Errorf("%s output does not say why the file was skipped", name)
		}
	}
}

func TestWritePRComment(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePRComment(&buf, sampleAudit()); err != nil {
		t.Fatalf("WritePRComment failed: %v", err)
	}
	out := buf.String()

	// The marker is what lets a CI job update its own comment instead of
	// posting a new one on every push.
	if !strings.HasPrefix(out, CommentMarker) {
		t.Errorf("comment does not start with the update marker:\n%s", out)
	}
	if !strings.Contains(out, "2 finding(s)") {
		t.Error("comment does not carry the finding count")
	}
	if !strings.Contains(out, "<details>") {
		t.Error("comment does not expand the most severe finding")
	}
}

func TestPRCommentCapsTheFindingList(t *testing.T) {
	audit := sampleAudit()
	audit.Findings = nil
	for i := 0; i < MaxCommentFindings+5; i++ {
		audit.Findings = append(audit.Findings, finding.Finding{
			RuleID: finding.RuleUnpinnedAction, Severity: finding.Medium,
			File: "ci.yml", Line: i + 1, Title: "Unpinned action",
		})
	}

	var buf bytes.Buffer
	if err := WritePRComment(&buf, audit); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if got := strings.Count(out, "| 🟠 Medium |"); got != MaxCommentFindings {
		t.Errorf("listed %d rows, want the cap of %d", got, MaxCommentFindings)
	}
	if !strings.Contains(out, "5 more finding(s) omitted") {
		t.Errorf("the omitted count is missing:\n%s", out)
	}
}

// A title containing a pipe would otherwise break the markdown table it sits in.
func TestTableCellsAreEscaped(t *testing.T) {
	audit := sampleAudit()
	audit.Findings = []finding.Finding{{
		RuleID: finding.RuleSecretLeak, Severity: finding.High, File: "ci.yml", Line: 3,
		Title: "Secret piped | to a command\nacross two lines",
	}}

	var buf bytes.Buffer
	if err := WritePRComment(&buf, audit); err != nil {
		t.Fatal(err)
	}
	row := ""
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "Secret piped") {
			row = line
		}
	}
	if row == "" {
		t.Fatal("the finding row is missing")
	}
	if !strings.Contains(row, `\|`) {
		t.Errorf("the pipe was not escaped: %q", row)
	}
	if !strings.Contains(row, "across two lines") {
		t.Errorf("the newline broke the row: %q", row)
	}
}

func TestWriteDigest(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDigest(&buf, sampleAudit()); err != nil {
		t.Fatalf("WriteDigest failed: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, ".github/workflows/ci.yml:15") {
		t.Error("digest does not carry a clickable location")
	}
	if !strings.Contains(out, "2 finding(s) in 2 file(s)") {
		t.Errorf("digest summary is wrong:\n%s", out)
	}
	if strings.Contains(out, "Untrusted input in a run block") {
		t.Error("a dismissed finding appeared in the digest")
	}
}

// Numbers produced without a model must never be printed without saying so.
func TestBaselineDisclaimerReachesEveryRenderer(t *testing.T) {
	audit := sampleAudit()
	audit.Reasoning = SummariseReasoning(llm.Stats{
		ProviderName: llm.ProviderOffline,
		ModelName:    "heuristic-baseline (not a model)",
		Candidates:   3, Reviewed: 3, Confirmed: 2, Dismissed: 1,
		TotalCited: 4, Fabricated: 0,
	})

	if audit.Reasoning.Disclaimer == "" {
		t.Fatal("the offline provider did not attach a disclaimer")
	}

	renderers := map[string]func(*bytes.Buffer) error{
		"markdown":   func(b *bytes.Buffer) error { return WriteMarkdown(b, audit) },
		"pr comment": func(b *bytes.Buffer) error { return WritePRComment(b, audit) },
		"digest":     func(b *bytes.Buffer) error { return WriteDigest(b, audit) },
	}

	for name, render := range renderers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := render(&buf); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), "not by an LLM") {
				t.Errorf("%s output presents baseline numbers without the disclaimer:\n%s",
					name, buf.String())
			}
		})
	}

	// A real provider carries no disclaimer, so the warning stays meaningful.
	real := SummariseReasoning(llm.Stats{ProviderName: llm.ProviderOllama, ModelName: "llama3"})
	if real.Disclaimer != "" {
		t.Errorf("a real provider was given a baseline disclaimer: %q", real.Disclaimer)
	}
}

func TestReasoningSectionReportsFabricatedCitations(t *testing.T) {
	audit := sampleAudit()
	audit.Reasoning = SummariseReasoning(llm.Stats{
		ProviderName: llm.ProviderOllama, ModelName: "llama3",
		Candidates: 2, Reviewed: 2, Confirmed: 1, Uncertain: 1,
		TotalCited: 5, Fabricated: 2,
	})

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, audit); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "3 of 5 citations") {
		t.Errorf("citation verification is not reported:\n%s", out)
	}
	if !strings.Contains(out, "2 fabricated citation(s) were dropped") {
		t.Errorf("dropped citations are not disclosed:\n%s", out)
	}
}

// The summary exists so a bash step or a policy gate does not have to
// re-derive counts from the finding list and re-apply the dismissal rules.
func TestSummariseMatchesTheActiveFindings(t *testing.T) {
	audit := sampleAudit()
	audit.Summary = Summarise(audit.Findings)

	if audit.Summary.Total != len(audit.Active()) {
		t.Errorf("summary total = %d, want %d", audit.Summary.Total, len(audit.Active()))
	}
	if audit.Summary.Worst != finding.Critical {
		t.Errorf("summary worst = %s, want critical", audit.Summary.Worst)
	}
	if audit.Summary.Dismissed != 1 {
		t.Errorf("summary dismissed = %d, want 1", audit.Summary.Dismissed)
	}
	if audit.Summary.BySeverity["high"] != 0 {
		t.Errorf("the dismissed high finding is counted: %v", audit.Summary.BySeverity)
	}
	if audit.Summary.ByRule["pwn-request"] != 1 {
		t.Errorf("by_rule = %v", audit.Summary.ByRule)
	}

	clean := Summarise(nil)
	if clean.Total != 0 || clean.Worst != finding.Info {
		t.Errorf("an empty summary should be clean and info, got %+v", clean)
	}
}
