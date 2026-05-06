package rules

import (
	"fmt"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// untrustedRefs are checkout inputs that resolve to the PR author's code.
var untrustedRefs = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.merge_commit_sha",
	"github.head_ref",
}

// PwnRequestRule flags the pull_request_target + untrusted checkout pattern.
type PwnRequestRule struct{}

// NewPwnRequestRule builds the rule.
func NewPwnRequestRule() *PwnRequestRule { return &PwnRequestRule{} }

// ID returns the rule identifier.
func (r *PwnRequestRule) ID() finding.RuleID { return finding.RulePwnRequest }

// Description summarises the rule.
func (r *PwnRequestRule) Description() string {
	return "`pull_request_target` must never check out the pull request's own head."
}

// Check flags a checkout of PR-controlled code under pull_request_target.
//
// This is the "pwn request". `pull_request_target` runs in the context of the
// *base* repository: it has the repository's secrets and a write-capable token,
// and unlike `pull_request` it is not sandboxed. Checking out the PR head then
// running anything from it — a build, a test, an install script — executes a
// stranger's code with all of that available.
func (r *PwnRequestRule) Check(wf *parser.Workflow) []finding.Finding {
	if !wf.HasTrigger("pull_request_target") {
		return nil
	}

	triggerPos := wf.TriggerPos("pull_request_target")
	var out []finding.Finding

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			ref, ok := r.untrustedCheckout(step)
			if !ok {
				continue
			}

			line := step.With["ref"].Pos.Line
			if line < 1 {
				line = step.Pos.Line
			}
			source := wf.LineAt(line)

			out = append(out, finding.Finding{
				RuleID:   r.ID(),
				Severity: finding.Critical,
				File:     wf.File,
				Line:     line,
				Job:      job.ID.Value,
				Step:     stepLabel(step),
				Title:    "pull_request_target checks out untrusted pull request code",
				Detail: fmt.Sprintf(
					"This workflow is triggered by `pull_request_target` (line %d) and checks out "+
						"`%s`, which is code the pull request author controls. Unlike "+
						"`pull_request`, this trigger runs against the base repository with its "+
						"secrets and a write-capable GITHUB_TOKEN. Any build step, test, or "+
						"install script from the PR then runs with that access.",
					triggerPos.Line, ref),
				Snippet:    wf.Snippet(line, 3),
				Confidence: finding.Certain,
				Fix: utils.UnifiedDiff(wf.File, line, source, "") +
					"# Either use `pull_request` instead, or keep `pull_request_target` and do not\n" +
					"# check out the PR head. If you must inspect PR code, do it in a separate\n" +
					"# job with no secrets and `permissions: {}`.\n",
				References: []string{
					"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
				},
			})
		}
	}

	// The trigger alone, with no untrusted checkout, is still worth surfacing:
	// whether it is safe depends on what the workflow does with the PR, which
	// the rule cannot decide on its own.
	if len(out) == 0 {
		line := triggerPos.Line
		if line < 1 {
			line = 1
		}
		out = append(out, finding.Finding{
			RuleID:   r.ID(),
			Severity: finding.Medium,
			File:     wf.File,
			Line:     line,
			Title:    "Workflow uses pull_request_target",
			Detail: "`pull_request_target` runs with the base repository's secrets and a " +
				"write-capable token. No checkout of the PR head was detected, so this may well " +
				"be intentional and safe — but any path that ends up executing PR-controlled " +
				"code from this workflow is a full repository compromise.",
			Snippet:    wf.Snippet(line, 3),
			Confidence: finding.Ambiguous,
			References: []string{
				"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
			},
		})
	}

	return out
}

// untrustedCheckout reports whether the step checks out PR-controlled code.
func (r *PwnRequestRule) untrustedCheckout(step parser.Step) (string, bool) {
	if step.Uses.Empty() || !strings.Contains(step.Uses.Value, "actions/checkout") {
		return "", false
	}

	ref, ok := step.With["ref"]
	if !ok || ref.Empty() {
		return "", false
	}

	lower := strings.ToLower(ref.Value)
	for _, candidate := range untrustedRefs {
		if strings.Contains(lower, candidate) {
			return candidate, true
		}
	}

	// `refs/pull/<n>/head` and `refs/pull/<n>/merge` reach the same fork code by
	// a different spelling, and both are common enough in real workflows that
	// missing them would leave the rule easy to walk around by accident.
	if strings.Contains(lower, "refs/pull/") {
		return ref.Value, true
	}

	return "", false
}
