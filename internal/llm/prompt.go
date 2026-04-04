package llm

import (
	"fmt"
	"strings"
)

// SystemPrompt frames the model's role and, critically, forbids invented
// evidence.
//
// The citation rule is the load-bearing instruction. A verdict that quotes line
// numbers reads as authoritative, so a fabricated citation manufactures false
// confidence — worse than citing nothing. It is reinforced by VerifyCitations,
// which strips any line outside the excerpt; prompting alone is only the first
// line of defence.
//
// The second load-bearing instruction is the asymmetry between confirming and
// dismissing. The rules already found a real pattern; the model's job is the
// narrower question of whether an attacker can reach it, and it is answering
// from an excerpt with no view of repository settings or branch protections.
const SystemPrompt = `You are a security engineer reviewing one finding from a static
analyser that audits GitHub Actions workflows.

The analyser already matched a real pattern in the YAML. You are NOT being asked
whether the pattern is present — assume it is. You are being asked the narrower
question: given this workflow's triggers, permissions, and surrounding steps, can
an attacker actually reach and exploit it?

Rules you must follow:
1. Answer with a single JSON object and nothing else. No prose before or after.
2. "cited_lines" must contain ONLY line numbers that appear in the numbered excerpt
   you were given. Never cite a line you were not shown. If nothing in the excerpt
   supports your verdict, return an empty array.
3. Name a specific attacker and a specific path. "A malicious actor could exploit
   this" is not an answer. "Any GitHub user can open a pull request whose title is
   read on line 19 and executed by the shell" is.
4. Use "not_exploitable" only when the excerpt itself shows why the pattern cannot be
   reached — for example, the untrusted value is bound to an env var and referenced as
   a shell variable, or the trigger only fires for repository collaborators. Do not
   dismiss a finding because it "seems unlikely" or "would require an unusual setup".
5. Use "uncertain" when the excerpt does not settle the question. An honest
   "uncertain" is more useful than a confident guess, and it will not suppress the
   finding.
6. "confidence" is your genuine probability that the verdict is correct, from 0 to 1.
   Do not default to 0.9.

Background on the rules you may be reviewing:
- script-injection: an untrusted ${{ github.event.* }} value is substituted into a
  run: script before the shell parses it, so the value becomes command syntax. Passing
  it through env: and referencing $VAR is the safe form.
- pwn-request: pull_request_target runs with the base repository's secrets and a
  write-capable token; checking out the pull request's own head and then executing
  anything from it runs a stranger's code with that access.
- secret-leak: log masking is a literal string match, so any transformation of a
  secret prints in the clear; argv is readable by every process on the runner.
- unpinned-action: a tag is a mutable pointer, so the action's owner can change what
  runs inside your job at any time.
- broad-permissions: whatever the GITHUB_TOKEN can do, every step in the job can do,
  including third-party actions.`

const userPromptTemplate = `Rule: %s
Finding: %s
Location: %s line %d%s
Workflow triggers: %s
Declared permissions: %s

What the analyser observed:
%s

Numbered workflow excerpt (lines %d-%d — these are the ONLY line numbers you may cite):
---BEGIN EXCERPT---
%s
---END EXCERPT---

Respond with exactly this JSON shape:
%s`

// BuildPrompt renders the full user prompt for a request.
func BuildPrompt(req Request) string {
	where := ""
	if req.Job != "" {
		where = fmt.Sprintf(" (job %q", req.Job)
		if req.Step != "" {
			where += fmt.Sprintf(", step %q", req.Step)
		}
		where += ")"
	}

	triggers := strings.Join(req.Triggers, ", ")
	if triggers == "" {
		triggers = "(none declared)"
	}

	perms := req.Permissions
	if strings.TrimSpace(perms) == "" {
		perms = "(none declared — the token inherits the repository default)"
	}

	return fmt.Sprintf(userPromptTemplate,
		req.RuleID, req.Title, req.File, req.Line, where,
		triggers, perms, req.Detail,
		req.FirstLine, req.LastLine, req.Context, SchemaJSON)
}

// RepairPrompt is appended on the single retry after a malformed response. It
// restates only the format requirement, since the analysis itself may have been
// sound and only the envelope was wrong.
const RepairPrompt = `Your previous response could not be parsed.
Respond again with ONE valid JSON object and no other text.
"verdict" must be exactly one of: exploitable, not_exploitable, uncertain.
"cited_lines" must be an array of integers.`
