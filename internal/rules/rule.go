// Package rules holds pipelinesentinel's deterministic workflow checks.
package rules

import (
	"regexp"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

// Rule is one deterministic check over a parsed workflow.
//
// Rules are pure: same workflow in, same findings out, no network and no model.
// Everything that can be decided without judgement is decided here, which keeps
// the LLM pass small, cheap, and reserved for cases that genuinely need context.
type Rule interface {
	// ID is the stable identifier reported in findings.
	ID() finding.RuleID
	// Description is a one-line summary for the rules reference.
	Description() string
	// Check returns every finding this rule detects in the workflow.
	Check(wf *parser.Workflow) []finding.Finding
}

// untrustedContexts are expression contexts an attacker can influence on a
// public repository. Interpolating any of these straight into a shell is the
// script-injection pattern.
var untrustedContexts = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.default_branch",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.pages",
	"github.event.commits",
	"github.event.head_commit.message",
	"github.event.head_commit.author.name",
	"github.event.head_commit.author.email",
	"github.head_ref",
}

// exprPattern matches a GitHub Actions expression, capturing its inner text.
var exprPattern = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

// secretPattern matches a secrets context reference.
var secretPattern = regexp.MustCompile(`secrets\.[A-Za-z_][A-Za-z0-9_]*`)

// expressions returns every `${{ ... }}` body found in s, trimmed.
func expressions(s string) []string {
	matches := exprPattern.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

// untrustedIn returns the untrusted contexts referenced by expr, if any.
func untrustedIn(expr string) []string {
	lower := strings.ToLower(expr)
	var hits []string
	for _, ctx := range untrustedContexts {
		if strings.Contains(lower, ctx) {
			hits = append(hits, ctx)
		}
	}
	return hits
}

// lineWithin finds the 0-based offset of the first line of body containing
// needle, so a finding inside a multi-line `run:` block cites the right line.
func lineWithin(body, needle string) int {
	for i, line := range strings.Split(body, "\n") {
		if strings.Contains(line, needle) {
			return i
		}
	}
	return 0
}

// stepLabel names a step for reports, falling back through the fields a
// workflow author might have set.
func stepLabel(step parser.Step) string {
	switch {
	case !step.Name.Empty():
		return step.Name.Value
	case !step.Uses.Empty():
		return step.Uses.Value
	default:
		return "run step"
	}
}
