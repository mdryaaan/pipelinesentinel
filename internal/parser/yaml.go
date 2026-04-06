package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is a parsed GitHub Actions workflow with source positions retained.
type Workflow struct {
	File     string   `json:"file"`
	Name     Scalar   `json:"name"`
	Triggers []Scalar `json:"triggers"`
	// Permissions at workflow level. Declared reports whether a permissions
	// block was present at all, which is itself a finding.
	Permissions Permissions `json:"permissions"`
	Jobs        []Job       `json:"jobs"`

	// Lines is the raw file split by line, 0-indexed, used to render snippets
	// and to verify that a cited line actually exists.
	Lines []string `json:"-"`
}

// Permissions models a `permissions:` block.
type Permissions struct {
	Declared bool `json:"declared"`
	Pos      Pos  `json:"pos"`
	// Blanket is set for the scalar forms: `permissions: write-all`.
	Blanket Scalar            `json:"blanket,omitempty"`
	Scopes  map[string]Scalar `json:"scopes,omitempty"`
}

// Job is one job in a workflow.
type Job struct {
	ID          Scalar      `json:"id"`
	Name        Scalar      `json:"name"`
	RunsOn      []Scalar    `json:"runs_on"`
	If          Scalar      `json:"if"`
	Permissions Permissions `json:"permissions"`
	Steps       []Step      `json:"steps"`
	Pos         Pos         `json:"pos"`
}

// Step is one step within a job.
type Step struct {
	Name Scalar `json:"name"`
	// Uses is the action reference, e.g. "actions/checkout@v4".
	Uses Scalar `json:"uses"`
	// Run is the shell body. Pos points at the `run:` key, and RunBodyPos at the
	// first line of the script itself.
	Run        Scalar            `json:"run"`
	RunBodyPos Pos               `json:"run_body_pos"`
	With       map[string]Scalar `json:"with,omitempty"`
	Env        map[string]Scalar `json:"env,omitempty"`
	If         Scalar            `json:"if"`
	Pos        Pos               `json:"pos"`
}

// Parse reads workflow YAML, preserving positions for every value.
func Parse(file string, data []byte) (*Workflow, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("parsing %s: document is empty", file)
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parsing %s: top level is not a mapping", file)
	}

	wf := &Workflow{
		File:  file,
		Lines: splitLines(string(data)),
	}

	if n, _ := mapValue(doc, "name"); n != nil {
		wf.Name = scalarOf(n)
	}

	// YAML 1.1 parses a bare `on` as the boolean true, so a workflow's trigger
	// key can arrive as "on" or as "true" depending on how it was quoted. Both
	// have to be looked up or every trigger-dependent rule silently finds nothing.
	triggerNode, _ := mapValue(doc, "on")
	if triggerNode == nil {
		triggerNode, _ = mapValue(doc, "true")
	}
	wf.Triggers = stringsOf(triggerNode)

	permNode, permKey := mapValue(doc, "permissions")
	wf.Permissions = parsePermissions(permNode, permKey)

	jobsNode, _ := mapValue(doc, "jobs")
	wf.Jobs = parseJobs(jobsNode)

	return wf, nil
}

func parsePermissions(node, key *yaml.Node) Permissions {
	if node == nil {
		return Permissions{Declared: false}
	}

	p := Permissions{Declared: true, Pos: posOf(key)}
	if !p.Pos.Valid() {
		p.Pos = posOf(node)
	}

	switch node.Kind {
	case yaml.ScalarNode:
		p.Blanket = scalarOf(node)
	case yaml.MappingNode:
		p.Scopes = make(map[string]Scalar)
		for i := 0; i+1 < len(node.Content); i += 2 {
			p.Scopes[node.Content[i].Value] = scalarOf(node.Content[i+1])
		}
	}

	return p
}

func parseJobs(node *yaml.Node) []Job {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	jobs := make([]Job, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, bodyNode := node.Content[i], node.Content[i+1]

		job := Job{ID: scalarOf(keyNode), Pos: posOf(keyNode)}

		if n, _ := mapValue(bodyNode, "name"); n != nil {
			job.Name = scalarOf(n)
		}
		if n, _ := mapValue(bodyNode, "runs-on"); n != nil {
			job.RunsOn = stringsOf(n)
		}
		if n, _ := mapValue(bodyNode, "if"); n != nil {
			job.If = scalarOf(n)
		}

		permNode, permKey := mapValue(bodyNode, "permissions")
		job.Permissions = parsePermissions(permNode, permKey)

		stepsNode, _ := mapValue(bodyNode, "steps")
		job.Steps = parseSteps(stepsNode)

		jobs = append(jobs, job)
	}

	return jobs
}

func parseSteps(node *yaml.Node) []Step {
	items := seqItems(node)
	if items == nil {
		return nil
	}

	steps := make([]Step, 0, len(items))
	for _, item := range items {
		if item.Kind != yaml.MappingNode {
			continue
		}

		step := Step{Pos: posOf(item)}

		if n, _ := mapValue(item, "name"); n != nil {
			step.Name = scalarOf(n)
		}
		if n, _ := mapValue(item, "uses"); n != nil {
			step.Uses = scalarOf(n)
		}
		if n, _ := mapValue(item, "if"); n != nil {
			step.If = scalarOf(n)
		}

		if n, key := mapValue(item, "run"); n != nil {
			step.Run = scalarOf(n)
			// A block scalar's node points at the `|` marker, so the body starts
			// on the following line; BlockBodyPos accounts for that.
			step.RunBodyPos = BlockBodyPos(n)
			if !step.RunBodyPos.Valid() {
				step.RunBodyPos = posOf(key)
			}
			step.Pos = posOf(key)
		}

		step.With = parseStringMap(item, "with")
		step.Env = parseStringMap(item, "env")

		steps = append(steps, step)
	}

	return steps
}

func parseStringMap(parent *yaml.Node, key string) map[string]Scalar {
	node, _ := mapValue(parent, key)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	out := make(map[string]Scalar, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		out[node.Content[i].Value] = scalarOf(node.Content[i+1])
	}
	return out
}

// splitLines normalises line endings and drops the empty element a trailing
// newline leaves behind, so LineCount matches what an editor shows.
func splitLines(data string) []string {
	normalised := strings.ReplaceAll(data, "\r\n", "\n")
	lines := strings.Split(normalised, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// LineAt returns the 1-indexed source line, or "" when out of range.
func (w *Workflow) LineAt(line int) string {
	if line < 1 || line > len(w.Lines) {
		return ""
	}
	return w.Lines[line-1]
}

// Snippet renders the lines around a citation, trimmed of trailing blanks.
func (w *Workflow) Snippet(line, context int) string {
	if line < 1 {
		return ""
	}
	start := line - context
	if start < 1 {
		start = 1
	}
	end := line + context
	if end > len(w.Lines) {
		end = len(w.Lines)
	}

	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%4d | %s\n", i, w.Lines[i-1])
	}
	return strings.TrimRight(b.String(), "\n")
}

// LineCount returns the number of source lines in the workflow.
func (w *Workflow) LineCount() int { return len(w.Lines) }

// Excerpt renders an inclusive numbered range of the file.
//
// The line numbers are part of the text on purpose: they are what a reasoning
// pass cites, and a citation that carries a number can be checked against the
// range it was given.
func (w *Workflow) Excerpt(first, last int) string {
	if first < 1 {
		first = 1
	}
	if last > len(w.Lines) {
		last = len(w.Lines)
	}
	if first > last {
		return ""
	}

	var b strings.Builder
	for i := first; i <= last; i++ {
		fmt.Fprintf(&b, "%4d | %s\n", i, w.Lines[i-1])
	}
	return b.String()
}

// HasTrigger reports whether the workflow fires on the named event.
func (w *Workflow) HasTrigger(name string) bool {
	for _, t := range w.Triggers {
		if strings.EqualFold(t.Value, name) {
			return true
		}
	}
	return false
}

// TriggerPos returns the position of a named trigger, for citation.
func (w *Workflow) TriggerPos(name string) Pos {
	for _, t := range w.Triggers {
		if strings.EqualFold(t.Value, name) {
			return t.Pos
		}
	}
	return Pos{}
}
