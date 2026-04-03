package finding

import "fmt"

// Remediation is the human-facing guidance for a rule: what to do, why that
// works, and a worked example.
//
// Rules attach a concrete unified diff to each individual finding. This is the
// complementary half — the general advice, which is identical for every finding
// of a given rule and so is stored once rather than repeated per finding.
type Remediation struct {
	RuleID  RuleID `json:"rule_id"`
	Summary string `json:"summary"`
	Why     string `json:"why"`
	Example string `json:"example"`
	Docs    string `json:"docs"`
}

var remediations = map[RuleID]Remediation{
	RuleScriptInjection: {
		RuleID:  RuleScriptInjection,
		Summary: "Pass untrusted values to the shell through `env:`, then reference them as shell variables.",
		Why: "GitHub substitutes `${{ }}` expressions into the script text before any shell sees " +
			"it, so the value becomes part of the command. Binding it to an environment variable " +
			"hands the shell the value out of band, where it is data and never syntax.",
		Example: "- name: Greet\n" +
			"  env:\n" +
			"    PR_TITLE: ${{ github.event.pull_request.title }}\n" +
			"  run: echo \"Thanks for $PR_TITLE\"",
		Docs: "https://securitylab.github.com/resources/github-actions-untrusted-input/",
	},
	RulePwnRequest: {
		RuleID:  RulePwnRequest,
		Summary: "Do not check out the pull request head in a `pull_request_target` workflow.",
		Why: "`pull_request_target` runs against the base repository with its secrets and a " +
			"write-capable token. Checking out the fork's code and then building, testing, or " +
			"installing from it executes a stranger's code with all of that in reach.",
		Example: "# Split the work in two:\n" +
			"#   1. an untrusted job on `pull_request` that builds the PR with no secrets\n" +
			"#   2. a `workflow_run` job that consumes the artifact and holds the secrets\n" +
			"on:\n" +
			"  pull_request:\n" +
			"permissions:\n" +
			"  contents: read",
		Docs: "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
	},
	RuleSecretLeak: {
		RuleID:  RuleSecretLeak,
		Summary: "Move secrets into `env:` and never print them or pass them as arguments.",
		Why: "Log masking is a literal match on the secret's exact value, so any transformation " +
			"of it prints in the clear. Command-line arguments are readable by every process on " +
			"the runner for as long as the command runs.",
		Example: "- name: Publish\n" +
			"  env:\n" +
			"    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n" +
			"  run: ./deploy.sh   # reads $DEPLOY_TOKEN from the environment",
		Docs: "https://docs.github.com/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
	},
	RuleUnpinnedAction: {
		RuleID:  RuleUnpinnedAction,
		Summary: "Pin every action to a full 40-character commit SHA, with the version in a comment.",
		Why: "A tag is a mutable pointer. Whoever controls the action repository can move `v4` to " +
			"different code at any time, and that code runs inside your job with your secrets. A " +
			"commit SHA cannot be moved.",
		Example: "- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
		Docs:    "https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
	},
	RuleBroadPermission: {
		RuleID:  RuleBroadPermission,
		Summary: "Declare `permissions:` explicitly and grant only the scopes the job uses.",
		Why: "The GITHUB_TOKEN is available to every step, including third-party actions. Whatever " +
			"it can do, anything that runs in the job can do — so the blast radius of one " +
			"compromised dependency is exactly the set of scopes you granted.",
		Example: "permissions:\n" +
			"  contents: read\n" +
			"\n" +
			"jobs:\n" +
			"  release:\n" +
			"    permissions:\n" +
			"      contents: write   # only where it is actually needed",
		Docs: "https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication",
	},
}

// RemediationFor returns the guidance for a rule.
func RemediationFor(id RuleID) (Remediation, error) {
	r, ok := remediations[id]
	if !ok {
		return Remediation{}, fmt.Errorf("%w: no remediation for rule %q", ErrInvalid, id)
	}
	return r, nil
}

// AllRemediations returns guidance for every rule, in report order.
func AllRemediations() []Remediation {
	out := make([]Remediation, 0, len(remediations))
	for _, id := range AllRules() {
		if r, ok := remediations[id]; ok {
			out = append(out, r)
		}
	}
	return out
}
