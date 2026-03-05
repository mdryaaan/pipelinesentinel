package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// fullSHA matches a complete 40-character git object id. Nothing shorter counts:
// an abbreviated SHA is not collision-resistant enough to be a security control.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// UnpinnedActionRule flags action references that are not pinned to a commit.
type UnpinnedActionRule struct{}

// NewUnpinnedActionRule builds the rule.
func NewUnpinnedActionRule() *UnpinnedActionRule { return &UnpinnedActionRule{} }

// ID returns the rule identifier.
func (r *UnpinnedActionRule) ID() finding.RuleID { return finding.RuleUnpinnedAction }

// Description summarises the rule.
func (r *UnpinnedActionRule) Description() string {
	return "Third-party actions must be pinned to a full commit SHA, not a mutable tag or branch."
}

// Check flags every `uses:` that resolves to something mutable.
//
// A tag is a pointer, not a version: whoever controls the action repository can
// move `v4` to different code at any time, and that code runs with access to
// the workflow's secrets. A branch ref is worse still.
func (r *UnpinnedActionRule) Check(wf *parser.Workflow) []finding.Finding {
	var out []finding.Finding

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses.Empty() {
				continue
			}

			ref := step.Uses.Value

			// Local actions (./path) and container actions (docker://) are not
			// third-party supply chain in the same sense.
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
				continue
			}

			at := strings.LastIndex(ref, "@")
			if at < 0 {
				out = append(out, r.newFinding(wf, job, step, ref, "no version reference at all"))
				continue
			}

			version := ref[at+1:]
			if fullSHA.MatchString(version) {
				continue
			}

			out = append(out, r.newFinding(wf, job, step, ref,
				fmt.Sprintf("pinned to the mutable ref %q", version)))
		}
	}

	return out
}

func (r *UnpinnedActionRule) newFinding(
	wf *parser.Workflow, job parser.Job, step parser.Step, ref, why string,
) finding.Finding {
	line := step.Uses.Pos.Line
	source := wf.LineAt(line)

	name := ref
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		name = ref[:at]
	}

	// The action's own repository is trusted more or less depending on owner;
	// first-party actions moving a tag is still a supply-chain risk, but a far
	// less likely one, so it is reported at a lower severity.
	severity := finding.Medium
	if !strings.HasPrefix(name, "actions/") && !strings.HasPrefix(name, "github/") {
		severity = finding.High
	}

	fixed := strings.Replace(source, ref,
		fmt.Sprintf("%s@<40-char-commit-sha> # %s", name, refLabel(ref)), 1)

	return finding.Finding{
		RuleID:   r.ID(),
		Severity: severity,
		File:     wf.File,
		Line:     line,
		Job:      job.ID.Value,
		Step:     stepLabel(step),
		Title:    fmt.Sprintf("Action %q is not pinned to a commit SHA", ref),
		Detail: fmt.Sprintf(
			"`%s` is %s. A tag or branch is a mutable pointer: whoever controls the action "+
				"repository can change what it runs at any time, and that code executes with "+
				"access to this workflow's secrets and token.", ref, why),
		Snippet:    wf.Snippet(line, 1),
		Confidence: finding.Certain,
		Fix:        utils.UnifiedDiff(wf.File, line, source, fixed),
		References: []string{
			"https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
		},
	}
}

func refLabel(ref string) string {
	if at := strings.LastIndex(ref, "@"); at >= 0 && at+1 < len(ref) {
		return ref[at+1:]
	}
	return "pinned"
}
