package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the CLI with args and captures both streams.
//
// The command tree is rebuilt per call because cobra binds flags to package
// level variables; sharing one tree would let one test's --format leak into the
// next one's assertions.
func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	resetFlags()

	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)

	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func resetFlags() {
	opts.Offline = false
	opts.Reason = false
	opts.ConfigPath = ""
	opts.Provider = ""
	auditOpts.Format = "digest"
	auditOpts.Output = ""
	auditOpts.ListRules = false
	reportOpts.Format = "markdown"
	reportOpts.Output = ""
	reportOpts.JSONPath = ""
	evalOpts.Format = "text"
	evalOpts.Output = ""
	evalOpts.Dir = ""
	evalOpts.Corpus = "labeled-cases.json"
	evalOpts.MinScore = 0
	explainOpts.Rule = ""
	explainOpts.Line = 0
}

func TestMain(m *testing.M) {
	// The CLI reads its fixtures and corpus from the filesystems main injects,
	// so the tests supply the on-disk copies.
	SetEmbedded(
		os.DirFS(filepath.Join("..", "testdata", "fixtures")),
		os.DirFS(filepath.Join("..", "testdata", "eval")),
	)
	os.Exit(m.Run())
}

func TestAuditOffline(t *testing.T) {
	out, _, err := run(t, "audit", "--offline", "--fail-on", "critical")

	// The bundled fixtures include critical findings by design, so the gate
	// must trip — and it must trip with a threshold error, not a crash.
	if err == nil {
		t.Fatal("expected the failure threshold to trip")
	}
	var gate *thresholdError
	if !asThreshold(err, &gate) {
		t.Fatalf("error %v is not a threshold error", err)
	}

	for _, want := range []string{"pwn-request", "script-injection", "vulnerable-workflow-1.yml:15"} {
		if !strings.Contains(out, want) {
			t.Errorf("digest is missing %q:\n%s", want, out)
		}
	}
}

// Exit code 1 means "found something"; 2 means "the tool broke". A CI job
// cannot tell a vulnerable workflow from a bad token if those collapse.
func TestExitCodesDistinguishFindingsFromFailures(t *testing.T) {
	gate := &thresholdError{Count: 3}
	var target *thresholdError
	if !asThreshold(gate, &target) {
		t.Error("a threshold error should be recognised")
	}
	if asThreshold(os.ErrNotExist, &target) {
		t.Error("an unrelated error was mistaken for a threshold error")
	}
}

func TestAuditPassesOnACleanTarget(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "safe-workflow-1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflows, "ci.yml"), safe, 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err := run(t, "audit", dir)
	if err != nil {
		t.Fatalf("a clean repository should exit zero, got: %v", err)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("expected a clean digest, got:\n%s", out)
	}
}

func TestAuditFormats(t *testing.T) {
	tests := map[string]string{
		"json":       `"rule_id"`,
		"sarif":      `"$schema"`,
		"markdown":   "# Workflow security audit",
		"pr-comment": "<!-- pipelinesentinel:audit -->",
		"digest":     "finding(s) in",
	}

	for format, want := range tests {
		t.Run(format, func(t *testing.T) {
			out, _, _ := run(t, "audit", "--offline", "--format", format, "--fail-on", "critical")
			if !strings.Contains(out, want) {
				t.Errorf("%s output is missing %q:\n%s", format, want, out)
			}
		})
	}

	if _, _, err := run(t, "audit", "--offline", "--format", "yaml"); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestAuditJSONIsValid(t *testing.T) {
	out, _, _ := run(t, "audit", "--offline", "--format", "json", "--fail-on", "critical")

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("audit JSON does not parse: %v", err)
	}
	if parsed["tool"] != "pipelinesentinel" {
		t.Errorf("tool = %v", parsed["tool"])
	}
}

func TestAuditWritesToAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")

	if _, _, err := run(t, "audit", "--offline", "--format", "json",
		"--output", path, "--fail-on", "critical"); err == nil {
		t.Fatal("expected the threshold to trip")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the output file was not written: %v", err)
	}
	if !bytes.Contains(data, []byte(`"findings"`)) {
		t.Error("the output file does not contain the audit")
	}
}

func TestAuditRuleSelection(t *testing.T) {
	out, _, _ := run(t, "audit", "--offline", "--rule", "unpinned-action")

	if strings.Contains(out, "pwn-request") {
		t.Errorf("an unselected rule reported:\n%s", out)
	}
	if !strings.Contains(out, "unpinned-action") {
		t.Errorf("the selected rule did not report:\n%s", out)
	}
}

func TestAuditSeverityThreshold(t *testing.T) {
	out, _, _ := run(t, "audit", "--offline", "--min-severity", "critical", "--fail-on", "critical")

	if strings.Contains(out, "Medium") {
		t.Errorf("a medium finding survived a critical threshold:\n%s", out)
	}
}

func TestAuditRejectsBadFlagValues(t *testing.T) {
	if _, _, err := run(t, "audit", "--offline", "--min-severity", "severe"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
	if _, _, err := run(t, "audit", "--offline", "--provider", "gpt", "--reason"); err == nil {
		t.Error("expected an error for an unknown provider")
	}
	if _, _, err := run(t, "audit", "--offline", "--ignore", "unpined-action"); err == nil {
		t.Error("expected an error for an unknown rule")
	}
}

func TestAuditListRules(t *testing.T) {
	out, _, err := run(t, "audit", "--list-rules")
	if err != nil {
		t.Fatalf("--list-rules failed: %v", err)
	}
	for _, rule := range []string{
		"script-injection", "pwn-request", "secret-leak", "unpinned-action", "broad-permissions",
	} {
		if !strings.Contains(out, rule) {
			t.Errorf("rule %s is missing from the listing", rule)
		}
	}
	if !strings.Contains(out, "fix:") {
		t.Error("the listing does not include remediation guidance")
	}
}

// A target that is neither a path nor an owner/repo reference must say so
// rather than making a doomed API call.
func TestAuditRejectsAnUnusableTarget(t *testing.T) {
	_, _, err := run(t, "audit", "not-a-path-or-repo")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "owner/repo") {
		t.Errorf("error should explain the accepted forms, got: %v", err)
	}
}

func TestExplain(t *testing.T) {
	out, _, err := run(t, "explain", "--offline", "--rule-id", "pwn-request")
	if err != nil {
		t.Fatalf("explain failed: %v", err)
	}

	for _, want := range []string{
		"CRITICAL", "Why it matters", "The safe pattern", "Reference: https://",
		"finding(s) explained",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "unpinned-action") {
		t.Error("--rule-id did not narrow the output")
	}
}

func TestExplainWithNothingToSay(t *testing.T) {
	out, _, err := run(t, "explain", "--offline", "--rule-id", "pwn-request", "--line", "99999")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No findings to explain") {
		t.Errorf("expected an empty-result message, got:\n%s", out)
	}
}

func TestReportWritesBothFormats(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "report.md")
	js := filepath.Join(dir, "audit.json")

	if _, _, err := run(t, "report", "--offline", "-o", md, "--json", js,
		"--fail-on", "critical"); err == nil {
		t.Fatal("expected the threshold to trip")
	}

	markdown, err := os.ReadFile(md)
	if err != nil {
		t.Fatalf("markdown report missing: %v", err)
	}
	if !bytes.Contains(markdown, []byte("# Workflow security audit")) {
		t.Error("markdown report has no heading")
	}

	raw, err := os.ReadFile(js)
	if err != nil {
		t.Fatalf("json report missing: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("json report does not parse: %v", err)
	}
}

func TestEvalScoresTheBundledCorpus(t *testing.T) {
	out, _, err := run(t, "eval")
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}

	for _, want := range []string{
		"exact-match accuracy", "macro F1", "clean left silent", "cited the right line",
		"script-injection", "rules only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("eval output is missing %q:\n%s", want, out)
		}
	}
}

func TestEvalMinScoreGate(t *testing.T) {
	if _, _, err := run(t, "eval", "--min-score", "0.9"); err != nil {
		t.Errorf("the corpus should clear a 0.9 gate: %v", err)
	}
	if _, _, err := run(t, "eval", "--min-score", "1.01"); err == nil {
		t.Error("an unreachable gate should fail")
	}
}

func TestEvalJSONAndMarkdown(t *testing.T) {
	out, _, err := run(t, "eval", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("eval JSON does not parse: %v", err)
	}

	out, _, err = run(t, "eval", "--format", "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "### Confusion matrix") {
		t.Errorf("eval markdown has no confusion matrix:\n%s", out)
	}

	if _, _, err := run(t, "eval", "--format", "csv"); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

// Baseline numbers must announce themselves on stderr too, because that is
// where a CI log gets read.
func TestOfflineBaselineWarnsOnStderr(t *testing.T) {
	_, stderr, _ := run(t, "eval", "--reason", "--provider", "offline")
	if !strings.Contains(stderr, "not by an LLM") {
		t.Errorf("stderr did not carry the baseline disclaimer: %q", stderr)
	}

	_, stderr, _ = run(t, "audit", "--offline", "--reason", "--provider", "offline",
		"--fail-on", "critical")
	if !strings.Contains(stderr, "not by an LLM") {
		t.Errorf("audit stderr did not carry the baseline disclaimer: %q", stderr)
	}
}

func TestVersion(t *testing.T) {
	out, _, err := run(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pipelinesentinel") {
		t.Errorf("version output = %q", out)
	}

	out, _, err = run(t, "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]string
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("version JSON does not parse: %v", err)
	}
	for _, key := range []string{"version", "commit", "goVersion", "platform"} {
		if info[key] == "" {
			t.Errorf("version JSON has no %s", key)
		}
	}
}

func TestCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			out, _, err := run(t, "completion", shell)
			if err != nil {
				t.Fatalf("completion %s failed: %v", shell, err)
			}
			if len(out) < 100 {
				t.Errorf("completion script is suspiciously short (%d bytes)", len(out))
			}
		})
	}

	if _, _, err := run(t, "completion", "csh"); err == nil {
		t.Error("expected an error for an unsupported shell")
	}
}

func TestConfigFileIsRespected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".pipelinesentinel.yml")
	if err := os.WriteFile(cfgPath, []byte("ignore:\n  - unpinned-action\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, _ := run(t, "audit", "--offline", "--config", cfgPath, "--fail-on", "critical")
	if strings.Contains(out, "unpinned-action") {
		t.Errorf("the config file's ignore list was not applied:\n%s", out)
	}

	// A flag must still win over the file.
	out, _, _ = run(t, "audit", "--offline", "--config", cfgPath,
		"--rule", "unpinned-action", "--fail-on", "critical")
	if !strings.Contains(out, "unpinned-action") {
		t.Errorf("--rule did not override the config file:\n%s", out)
	}
}
