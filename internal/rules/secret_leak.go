package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// printCommands write their arguments somewhere a human or a log can read.
var printCommands = regexp.MustCompile(`(?i)^\s*(echo|printf|print|cat|tee|write-host|write-output)\b`)

// argFlag matches a secret handed to a program as a command-line flag value.
var argFlag = regexp.MustCompile(`(?i)(^|\s)(-{1,2}[a-z0-9][a-z0-9-]*)[= ]\s*["']?\$\{\{`)

// SecretLeakRule flags secrets that end up in logs or in the process table.
type SecretLeakRule struct{}

// NewSecretLeakRule builds the rule.
func NewSecretLeakRule() *SecretLeakRule { return &SecretLeakRule{} }

// ID returns the rule identifier.
func (r *SecretLeakRule) ID() finding.RuleID { return finding.RuleSecretLeak }

// Description summarises the rule.
func (r *SecretLeakRule) Description() string {
	return "Secrets must not be printed or passed as command-line arguments."
}

// Check flags printed secrets and secrets passed as argv.
//
// Actions masks a secret's exact value in logs, but the masking is a string
// match on the raw value: anything that transforms it — base64, a substring, a
// JSON re-encode — passes straight through. And argv is world-readable in the
// process table for the lifetime of the command, so `--token ${{ secrets.X }}`
// leaks to every other process on the runner.
func (r *SecretLeakRule) Check(wf *parser.Workflow) []finding.Finding {
	var out []finding.Finding

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run.Empty() {
				continue
			}

			for i, raw := range strings.Split(step.Run.Value, "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				secrets := secretPattern.FindAllString(line, -1)
				if len(secrets) == 0 {
					continue
				}

				kind, detail, severity := r.classify(line, secrets[0])
				if kind == "" {
					continue
				}

				at := parser.LineOffset(step.RunBodyPos, i)
				source := wf.LineAt(at)

				out = append(out, finding.Finding{
					RuleID:     r.ID(),
					Severity:   severity,
					File:       wf.File,
					Line:       at,
					Job:        job.ID.Value,
					Step:       stepLabel(step),
					Title:      fmt.Sprintf("Secret %s", kind),
					Detail:     detail,
					Snippet:    wf.Snippet(at, 2),
					Confidence: finding.Certain,
					Fix:        r.fixFor(wf, at, source, secrets[0]),
					References: []string{
						"https://docs.github.com/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions#accessing-your-secrets",
					},
				})
			}
		}
	}

	return out
}

// classify decides how the secret escapes, if it does at all.
func (r *SecretLeakRule) classify(line, secret string) (string, string, finding.Severity) {
	switch {
	case printCommands.MatchString(line):
		return "written to the build log",
			fmt.Sprintf("`%s` is passed to a printing command. Actions masks the exact secret "+
				"value in logs, but that masking is a literal string match — encode it, slice it, "+
				"or re-serialise it and the real value appears in plain text in a log anyone with "+
				"read access can download.", secret),
			finding.Critical

	case argFlag.MatchString(line):
		return "passed as a command-line argument",
			fmt.Sprintf("`%s` is passed as a command-line argument. Every process on the runner "+
				"can read the full argv of every other process, and many tools echo their own "+
				"invocation on error. Pass it through the environment or on stdin instead.", secret),
			finding.High
	}

	return "", "", finding.Info
}

func (r *SecretLeakRule) fixFor(wf *parser.Workflow, line int, source, secret string) string {
	name := "SECRET_VALUE"
	if m := regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`).FindStringSubmatch(secret); len(m) == 2 {
		name = strings.ToUpper(m[1])
	}

	fixed := strings.Replace(source, secret, "$"+name, 1)
	return utils.UnifiedDiff(wf.File, line, source, fixed) +
		fmt.Sprintf("\n# and add to the step:\n#   env:\n#     %s: %s\n", name, secret)
}
