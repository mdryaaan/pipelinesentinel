package llm

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// OfflineDisclaimer must accompany every result this provider produces.
//
// It is not decoration. This provider does not run a model — it applies a
// second, smaller set of hand-written heuristics to the excerpt. Reporting its
// output as "LLM accuracy" would be a fabricated measurement, so the disclaimer
// is carried in the reasoning text itself, printed to stderr by the commands
// that use it, kept as a field on the report structs, and repeated in the
// README next to the numbers.
const OfflineDisclaimer = "BASELINE (no model): produced by deterministic heuristics, " +
	"not by an LLM. Use --provider ollama or --provider claude for real model reasoning."

// Offline adjudicates findings without a model.
//
// It exists so that the whole pipeline — audit, escalation, reporting, eval —
// runs on a machine with no Ollama daemon and no API key, and so the eval
// harness has a labelled control to measure a real model against. A model that
// cannot beat a hundred lines of heuristics is not earning its inference cost,
// and without this baseline there is no way to know.
type Offline struct{}

// NewOffline builds the offline baseline provider.
func NewOffline() *Offline { return &Offline{} }

// Name identifies the provider.
func (o *Offline) Name() string { return ProviderOffline }

// Model reports that no model is involved. The string is deliberately not a
// plausible model name: it appears in report headers, and anyone reading one
// should be able to tell at a glance that these numbers are not a model's.
func (o *Offline) Model() string { return "heuristic-baseline (not a model)" }

var (
	envBindingPattern = regexp.MustCompile(`(?m)^\s*\d+\s*\|\s*env:\s*$`)
	numberedLine      = regexp.MustCompile(`(?m)^\s*(\d+)\s*\|\s?(.*)$`)
)

// untrustedTriggerNames mirrors the rules package: triggers an attacker without
// write access can fire.
var untrustedTriggerNames = map[string]bool{
	"pull_request_target": true,
	"pull_request":        true,
	"issue_comment":       true,
	"issues":              true,
	"discussion":          true,
	"discussion_comment":  true,
	"fork":                true,
	"workflow_run":        true,
}

// Review adjudicates one finding from the excerpt alone.
func (o *Offline) Review(_ context.Context, req Request) (Review, error) {
	lines := parseNumbered(req.Context)

	verdict, confidence, why, cited := o.decide(req, lines)

	return Review{
		Verdict:    verdict,
		Confidence: confidence,
		Reasoning:  OfflineDisclaimer + " " + why,
		CitedLines: cited,
		Mitigation: o.mitigation(req.RuleID),
	}, nil
}

// numberedSource is one line of the excerpt with the number it was shown under.
type numberedSource struct {
	Number int
	Text   string
}

func parseNumbered(excerpt string) []numberedSource {
	matches := numberedLine.FindAllStringSubmatch(excerpt, -1)
	out := make([]numberedSource, 0, len(matches))
	for _, m := range matches {
		n, err := strconv.Atoi(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		out = append(out, numberedSource{Number: n, Text: m[2]})
	}
	return out
}

// decide is the whole of the baseline's reasoning.
//
// Every citation it returns is a line number it read out of the excerpt, so by
// construction it cannot fabricate one. That is a property of the mechanism,
// not an achievement — worth stating plainly wherever its citation score is
// reported next to a model's.
func (o *Offline) decide(req Request, lines []numberedSource) (string, float64, string, []int) {
	untrusted, triggerName := o.hasUntrustedTrigger(req.Triggers)

	switch req.RuleID {
	case "script-injection":
		if boundLine, ok := o.boundToEnv(lines); ok {
			return VerdictNotExploitable, 0.75,
				fmt.Sprintf("The value is bound to an environment variable at line %d and the "+
					"script references it as a shell variable, so it never becomes command syntax.",
					boundLine), []int{boundLine}
		}
		if untrusted {
			cited := o.citeMatching(lines, "${{")
			return VerdictExploitable, 0.8,
				fmt.Sprintf("The workflow is triggered by %q, which any GitHub user can fire, and "+
					"the untrusted value is interpolated into the script text before the shell "+
					"parses it.", triggerName), cited
		}
		return VerdictNotExploitable, 0.55,
			"The only triggers are ones that require push access, so an attacker would already " +
				"need write permission on the repository. The pattern is still worth fixing, and " +
				"this confidence is deliberately below the threshold that would suppress it.",
			o.citeMatching(lines, "${{")

	case "pwn-request":
		if cited := o.citeMatching(lines, "head.sha", "head.ref", "github.head_ref"); len(cited) > 0 {
			return VerdictExploitable, 0.85,
				"The workflow checks out the pull request's own head while running with the base " +
					"repository's secrets and a write-capable token.", cited
		}
		return VerdictUncertain, 0.5,
			"The trigger is present but the excerpt does not show the pull request's code being " +
				"checked out or executed, so whether this is reachable depends on steps not shown.",
			o.citeMatching(lines, "pull_request_target")

	case "secret-leak":
		return VerdictExploitable, 0.7,
			"The secret reaches either the build log or the process table, both of which are " +
				"readable by more parties than the secret was issued to.",
			o.citeMatching(lines, "secrets.")

	case "unpinned-action":
		return VerdictExploitable, 0.6,
			"The reference is mutable, so exploitability depends on the action repository's own " +
				"security rather than on anything in this workflow.",
			o.citeMatching(lines, "uses:")

	case "broad-permissions":
		if untrusted {
			return VerdictExploitable, 0.7,
				fmt.Sprintf("Write scopes are granted while the workflow runs on %q, which an "+
					"outside user can fire.", triggerName),
				o.citeMatching(lines, "permissions", "write")
		}
		return VerdictUncertain, 0.5,
			"The grant is broader than necessary, but no untrusted trigger appears in the " +
				"excerpt, so whether it is reachable depends on the rest of the repository.",
			o.citeMatching(lines, "permissions")
	}

	return VerdictUncertain, 0.4,
		"No baseline heuristic covers this rule, so the finding is left as the analyser raised it.",
		nil
}

func (o *Offline) hasUntrustedTrigger(triggers []string) (bool, string) {
	for _, t := range triggers {
		if untrustedTriggerNames[strings.ToLower(strings.TrimSpace(t))] {
			return true, t
		}
	}
	return false, ""
}

// boundToEnv reports whether the excerpt shows an env: block, the safe pattern
// for getting untrusted input to a shell.
func (o *Offline) boundToEnv(lines []numberedSource) (int, bool) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line.Text)
		if trimmed == "env:" || strings.HasPrefix(trimmed, "env:") {
			return line.Number, true
		}
	}
	return 0, false
}

// citeMatching returns the numbers of excerpt lines containing any needle. It
// can only ever return numbers it read from the excerpt.
func (o *Offline) citeMatching(lines []numberedSource, needles ...string) []int {
	var out []int
	for _, line := range lines {
		for _, needle := range needles {
			if strings.Contains(line.Text, needle) {
				out = append(out, line.Number)
				break
			}
		}
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func (o *Offline) mitigation(ruleID string) string {
	switch ruleID {
	case "script-injection":
		return "Bind the value to an env: variable and reference it as $VAR in the script."
	case "pwn-request":
		return "Do not check out the pull request head under pull_request_target."
	case "secret-leak":
		return "Pass the secret through env: and never print it or place it in argv."
	case "unpinned-action":
		return "Pin the action to a full 40-character commit SHA."
	case "broad-permissions":
		return "Declare permissions explicitly and grant only the scopes the job uses."
	}
	return "Review the finding against the rule's documentation."
}

// envBindingHint keeps the compiled pattern reachable for tests that assert the
// excerpt format the baseline depends on.
func envBindingHint(excerpt string) bool { return envBindingPattern.MatchString(excerpt) }
