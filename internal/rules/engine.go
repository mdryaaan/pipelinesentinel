package rules

import (
	"sort"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

// Engine runs a set of rules over workflows.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine with the default rule set.
func NewEngine() *Engine {
	return &Engine{rules: DefaultRules()}
}

// NewEngineWith builds an engine from an explicit rule set, used by tests.
func NewEngineWith(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// DefaultRules returns every rule shipped with pipelinesentinel.
func DefaultRules() []Rule {
	return []Rule{
		NewScriptInjectionRule(),
		NewPwnRequestRule(),
		NewSecretLeakRule(),
		NewUnpinnedActionRule(),
		NewBroadPermissionsRule(),
	}
}

// Rules exposes the configured rules, for the reference table.
func (e *Engine) Rules() []Rule { return e.rules }

// Only narrows the engine to the named rules. An empty or entirely unknown
// list leaves the engine untouched, so a typo in `--rule` cannot silently
// audit nothing and report a clean bill of health.
func (e *Engine) Only(ids []string) *Engine {
	if len(ids) == 0 {
		return e
	}

	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[strings.ToLower(strings.TrimSpace(id))] = true
	}

	var kept []Rule
	for _, rule := range e.rules {
		if wanted[string(rule.ID())] {
			kept = append(kept, rule)
		}
	}
	if len(kept) == 0 {
		return e
	}
	return &Engine{rules: kept}
}

// Without drops the named rules, for suppressing a rule a repository has
// consciously decided not to enforce.
func (e *Engine) Without(ids []string) *Engine {
	if len(ids) == 0 {
		return e
	}

	skip := make(map[string]bool, len(ids))
	for _, id := range ids {
		skip[strings.ToLower(strings.TrimSpace(id))] = true
	}

	kept := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		if !skip[string(rule.ID())] {
			kept = append(kept, rule)
		}
	}
	return &Engine{rules: kept}
}

// KnownRuleIDs lists every rule ID the binary ships with.
func KnownRuleIDs() []string {
	ids := make([]string, 0, 5)
	for _, rule := range DefaultRules() {
		ids = append(ids, string(rule.ID()))
	}
	sort.Strings(ids)
	return ids
}

// Run checks one workflow and returns findings in report order.
func (e *Engine) Run(wf *parser.Workflow) []finding.Finding {
	var out []finding.Finding
	for _, rule := range e.rules {
		out = append(out, rule.Check(wf)...)
	}
	finding.Sort(out)
	return out
}

// RunAll checks several workflows.
func (e *Engine) RunAll(workflows []*parser.Workflow) []finding.Finding {
	var out []finding.Finding
	for _, wf := range workflows {
		out = append(out, e.Run(wf)...)
	}
	finding.Sort(out)
	return out
}

// Catalogue describes the rule set, for the docs and the CLI.
type Catalogue struct {
	ID          finding.RuleID `json:"id"`
	Description string         `json:"description"`
}

// Describe lists the configured rules, sorted by ID for stable output.
func (e *Engine) Describe() []Catalogue {
	out := make([]Catalogue, 0, len(e.rules))
	for _, rule := range e.rules {
		out = append(out, Catalogue{ID: rule.ID(), Description: rule.Description()})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
