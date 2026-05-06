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

// pureAssignment matches a line that only binds the secret to a shell variable.
//
// `TOKEN="${{ secrets.X }}"` on its own puts the value in the script text but
// not in any other process's argv, so it is not the leak this rule is about.
// The moment a command follows on the same line, it is.
var pureAssignment = regexp.MustCompile(`(?i)^\s*(export\s+)?[a-z_][a-z0-9_]*=\s*["']?\$\{\{[^}]*\}\}["']?\s*$`)

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

	case pureAssignment.MatchString(line):
		// Binding to a shell variable and using it later is the pattern this
		// rule is asking for, so it is not reported.
		return "", "", finding.Info

	default:
		// Anything else on a command line puts the expanded value in the
		// command's argv.
		return "passed on a command line",
			fmt.Sprintf("`%s` is expanded into a command line. Every process on the runner can "+
				"read the full argv of every other process, and many tools echo their own "+
				"invocation on error. Bind it to `env:` and read it from the environment, or "+
				"pass it on stdin.", secret),
			finding.High
	}

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
