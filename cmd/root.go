// Package cmd defines pipelinesentinel's command line interface.
package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/pkg/version"
)

// embedded holds the fixture and corpus filesystems compiled into the binary.
//
// They are injected from main rather than embedded here because `go:embed`
// cannot reach outside its own package directory, and keeping one copy of the
// fixtures at the repository root is what stops the offline demo from drifting
// away from the files the tests use.
var embedded struct {
	Fixtures fs.FS
	Eval     fs.FS
}

// SetEmbedded registers the compiled-in filesystems.
func SetEmbedded(fixtures, eval fs.FS) {
	embedded.Fixtures = fixtures
	embedded.Eval = eval
}

// global flags shared by every command.
var opts struct {
	ConfigPath  string
	Provider    string
	Model       string
	BaseURL     string
	Temperature float64
	Reason      bool
	MinSeverity string
	FailOn      string
	Rules       []string
	Ignore      []string
	Offline     bool
	Token       string
	Ref         string
	NoColor     bool
}

// NewRootCommand builds the command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "pipelinesentinel",
		Short: "Audit GitHub Actions workflows for supply-chain risks",
		Long: `pipelinesentinel audits GitHub Actions workflow files for the supply-chain
mistakes that turn CI into a way into a repository: unpinned actions, pwn
requests, over-broad token permissions, leaked secrets, and script injection.

Detection is deterministic. Rules read the YAML, keep the source position of
every value, and report exactly what they matched. A language model is consulted
only for the findings the rules themselves marked ambiguous — where whether a
pattern is exploitable depends on context a regex cannot judge — and it can
never invent a finding the rules did not raise.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Current().String(),
	}

	flags := root.PersistentFlags()
	flags.StringVar(&opts.ConfigPath, "config", "", "path to a config file (default: nearest "+config.FileName+")")
	flags.StringVar(&opts.Provider, "provider", "", "reasoning provider: ollama, claude, or offline")
	flags.StringVar(&opts.Model, "model", "", "model name for the provider")
	flags.StringVar(&opts.BaseURL, "base-url", "", "override the provider or GitHub API endpoint")
	flags.Float64Var(&opts.Temperature, "temperature", -1, "sampling temperature for the reasoning pass")
	flags.BoolVar(&opts.Reason, "reason", false, "escalate ambiguous findings to the reasoning provider")
	flags.StringVar(&opts.MinSeverity, "min-severity", "", "hide findings below this severity")
	flags.StringVar(&opts.FailOn, "fail-on", "", "exit non-zero when a finding reaches this severity")
	flags.StringSliceVar(&opts.Rules, "rule", nil, "run only these rules (repeatable)")
	flags.StringSliceVar(&opts.Ignore, "ignore", nil, "skip these rules (repeatable)")
	flags.BoolVar(&opts.Offline, "offline", false, "audit the bundled example workflows, with no network")
	flags.StringVar(&opts.Token, "token", "", "GitHub token (default: $GITHUB_TOKEN or $GH_TOKEN)")
	flags.StringVar(&opts.Ref, "ref", "", "branch, tag, or sha to audit (default: the default branch)")
	flags.BoolVar(&opts.NoColor, "no-color", false, "disable coloured output")

	root.AddCommand(
		newAuditCommand(),
		newExplainCommand(),
		newReportCommand(),
		newEvalCommand(),
		newVersionCommand(),
		newCompletionCommand(),
	)

	return root
}

// Execute runs the CLI and returns a process exit code.
//
// The code is meaningful, because this runs in CI: 0 means clean, 1 means
// findings at or above the failure threshold, and 2 means the tool itself could
// not complete. Collapsing the last two would make a broken token look
// identical to a vulnerable workflow.
func Execute() int {
	if err := NewRootCommand().Execute(); err != nil {
		var gate *thresholdError
		if asThreshold(err, &gate) {
			fmt.Fprintln(os.Stderr, gate.Error())
			return 1
		}
		fmt.Fprintf(os.Stderr, "pipelinesentinel: %v\n", err)
		return 2
	}
	return 0
}

// thresholdError signals that the audit found something at or above the failure
// threshold. It is a distinct type so Execute can map it to exit code 1.
type thresholdError struct {
	Worst     finding.Severity
	Threshold finding.Severity
	Count     int
}

func (e *thresholdError) Error() string {
	return fmt.Sprintf("%d finding(s) at or above %s (worst: %s)",
		e.Count, e.Threshold, e.Worst)
}

func asThreshold(err error, target **thresholdError) bool {
	for err != nil {
		if t, ok := err.(*thresholdError); ok {
			*target = t
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// removeAll returns values with every entry of drop taken out.
func removeAll(values, drop []string) []string {
	if len(values) == 0 || len(drop) == 0 {
		return values
	}

	skip := make(map[string]bool, len(drop))
	for _, d := range drop {
		skip[strings.ToLower(strings.TrimSpace(d))] = true
	}

	out := make([]string, 0, len(values))
	for _, v := range values {
		if !skip[strings.ToLower(strings.TrimSpace(v))] {
			out = append(out, v)
		}
	}
	return out
}

// resolveConfig layers flags over the config file over the defaults.
//
// Flags win because they are the most specific expression of intent: someone
// typing --min-severity critical wants that run to be quieter, not a lecture
// about what the repository config says.
func resolveConfig(cmd *cobra.Command) (config.Config, error) {
	var cfg config.Config
	var err error

	if opts.ConfigPath != "" {
		cfg, err = config.Load(opts.ConfigPath)
	} else {
		wd, wdErr := os.Getwd()
		if wdErr != nil {
			wd = "."
		}
		cfg, _, err = config.Discover(wd)
	}
	if err != nil {
		return cfg, err
	}

	flags := cmd.Flags()
	if flags.Changed("provider") {
		cfg.Provider = opts.Provider
	}
	if flags.Changed("model") {
		cfg.Model = opts.Model
	}
	if flags.Changed("base-url") {
		cfg.BaseURL = opts.BaseURL
	}
	if flags.Changed("temperature") {
		cfg.Temperature = opts.Temperature
	}
	if flags.Changed("reason") {
		cfg.Reason = opts.Reason
	}
	if flags.Changed("min-severity") {
		cfg.MinSeverity = opts.MinSeverity
	}
	if flags.Changed("fail-on") {
		cfg.FailOn = opts.FailOn
	}
	if flags.Changed("rule") {
		cfg.Rules = opts.Rules
		// Asking for a rule explicitly outranks a config file that had
		// suppressed it. Without this, `--rule unpinned-action` in a repository
		// whose config ignores that rule reports nothing at all, which reads as
		// "your workflows are clean" rather than "you cancelled yourself out".
		cfg.Ignore = removeAll(cfg.Ignore, opts.Rules)
	}
	if flags.Changed("ignore") {
		cfg.Ignore = opts.Ignore
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
