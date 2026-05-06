package rules

import (
	"fmt"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// untrustedTriggers fire on input from outside the repository's contributors.
var untrustedTriggers = map[string]bool{
	"pull_request_target": true,
	"issue_comment":       true,
	"issues":              true,
	"discussion":          true,
	"discussion_comment":  true,
	"workflow_run":        true,
	"fork":                true,
}

// sensitiveScopes are the write scopes worth flagging under an untrusted
// trigger.
//
// `pull-requests: write` and `issues: write` are deliberately absent. A labeler
// or a welcome-bot needs exactly those, and firing on every one of them would
// train people to ignore this rule — which costs more than the marginal risk of
// an attacker being able to add a label. The scopes listed here are the ones
// that let an attacker change what the repository ships.
var sensitiveScopes = map[string]bool{
	"contents":        true,
	"packages":        true,
	"actions":         true,
	"deployments":     true,
	"id-token":        true,
	"security-events": true,
	"attestations":    true,
}

// BroadPermissionsRule flags over-broad GITHUB_TOKEN grants.
type BroadPermissionsRule struct{}

// NewBroadPermissionsRule builds the rule.
func NewBroadPermissionsRule() *BroadPermissionsRule { return &BroadPermissionsRule{} }

// ID returns the rule identifier.
func (r *BroadPermissionsRule) ID() finding.RuleID { return finding.RuleBroadPermission }

// Description summarises the rule.
func (r *BroadPermissionsRule) Description() string {
	return "The GITHUB_TOKEN should be granted the narrowest scopes a workflow needs, never write-all."
}

// Check flags blanket grants, missing declarations, and write access under
// untrusted triggers.
func (r *BroadPermissionsRule) Check(wf *parser.Workflow) []finding.Finding {
	var out []finding.Finding

	untrusted := r.untrustedTrigger(wf)

	if wf.Permissions.Declared {
		out = append(out, r.checkBlock(wf, wf.Permissions, "workflow", "", untrusted)...)
	} else {
		// With no declaration the token inherits the repository default, which
		// on older repositories is read/write across every scope.
		line := 1
		if len(wf.Triggers) > 0 && wf.Triggers[0].Pos.Valid() {
			line = wf.Triggers[0].Pos.Line
		}

		severity := finding.Low
		detail := "This workflow declares no `permissions:` block, so the GITHUB_TOKEN inherits " +
			"the repository default. On repositories created before the default changed, that is " +
			"read and write across every scope."
		if untrusted != "" {
			severity = finding.High
			detail = fmt.Sprintf(
				"This workflow declares no `permissions:` block and is triggered by `%s`, which "+
					"is influenced by users outside the repository. The token inherits the "+
					"repository default, which may be read/write across every scope.", untrusted)
		}

		out = append(out, finding.Finding{
			RuleID:     r.ID(),
			Severity:   severity,
			File:       wf.File,
			Line:       line,
			Title:      "No explicit permissions block",
			Detail:     detail,
			Snippet:    wf.Snippet(line, 2),
			Confidence: finding.Certain,
			Fix: utils.UnifiedDiff(wf.File, line, wf.LineAt(line),
				wf.LineAt(line)+"\n\npermissions:\n  contents: read"),
			References: []string{
				"https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
			},
		})
	}

	for _, job := range wf.Jobs {
		if job.Permissions.Declared {
			out = append(out, r.checkBlock(wf, job.Permissions, "job", job.ID.Value, untrusted)...)
		}
	}

	return out
}

func (r *BroadPermissionsRule) untrustedTrigger(wf *parser.Workflow) string {
	for _, t := range wf.Triggers {
		if untrustedTriggers[strings.ToLower(t.Value)] {
			return t.Value
		}
	}
	return ""
}

func (r *BroadPermissionsRule) checkBlock(
	wf *parser.Workflow, perms parser.Permissions, scope, jobID, untrusted string,
) []finding.Finding {
	var out []finding.Finding
	line := perms.Pos.Line
	if line < 1 {
		line = 1
	}
	source := wf.LineAt(line)

	if !perms.Blanket.Empty() {
		value := strings.ToLower(perms.Blanket.Value)
		if value == "write-all" {
			out = append(out, finding.Finding{
				RuleID:   r.ID(),
				Severity: finding.High,
				File:     wf.File,
				Line:     perms.Blanket.Pos.Line,
				Job:      jobID,
				Title:    fmt.Sprintf("Blanket write-all permissions at %s level", scope),
				Detail: "`permissions: write-all` grants the GITHUB_TOKEN write access to every " +
					"scope, including contents, packages and actions. Any code that runs in this " +
					"workflow — including a compromised third-party action — inherits all of it.",
				Snippet:    wf.Snippet(perms.Blanket.Pos.Line, 1),
				Confidence: finding.Certain,
				Fix: utils.UnifiedDiff(wf.File, perms.Blanket.Pos.Line,
					wf.LineAt(perms.Blanket.Pos.Line),
					strings.Replace(wf.LineAt(perms.Blanket.Pos.Line),
						perms.Blanket.Value, "\n  contents: read", 1)),
				References: []string{
					"https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
				},
			})
		}
		return out
	}

	// Write scopes under an untrusted trigger are the combination that turns a
	// script-injection foothold into repository write access.
	if untrusted == "" {
		return out
	}

	for name, value := range perms.Scopes {
		if !strings.EqualFold(value.Value, "write") || !sensitiveScopes[strings.ToLower(name)] {
			continue
		}
		out = append(out, finding.Finding{
			RuleID:   r.ID(),
			Severity: finding.Medium,
			File:     wf.File,
			Line:     value.Pos.Line,
			Job:      jobID,
			Title:    fmt.Sprintf("Write access to %q under the untrusted trigger %q", name, untrusted),
			Detail: fmt.Sprintf(
				"This %s grants `%s: write` while the workflow is triggered by `%s`, which "+
					"outside users can influence. If any step can be coerced into running "+
					"attacker-controlled code, it inherits that write access.",
				scope, name, untrusted),
			Snippet:    wf.Snippet(value.Pos.Line, 1),
			Confidence: finding.Probable,
			Fix:        utils.UnifiedDiff(wf.File, value.Pos.Line, source, ""),
			References: []string{
				"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
			},
		})
	}

	return out
}
