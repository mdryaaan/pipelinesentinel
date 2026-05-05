// Package eval measures the detector against a labelled corpus.
package eval

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

// NoFinding is the label for a case that should produce nothing.
//
// Clean cases carry most of the weight in this corpus. Recall alone is easy to
// game — a rule that fires on every workflow scores perfectly — so a labelled
// set without safe look-alikes cannot tell a useful detector from a broken one.
const NoFinding = "clean"

// Case is one labelled workflow.
type Case struct {
	ID          string `json:"id"`
	File        string `json:"file"`
	Description string `json:"description"`
	// Category is the rule the case exercises, or "clean".
	Category string `json:"category"`
	// Expected lists every rule that should fire, in any order. A clean case
	// has an empty list.
	Expected []string `json:"expected"`
	// ExpectedLine, when set, is the source line the primary finding must cite.
	// A finding that names the wrong line sends a reader to innocent code, so
	// it is scored separately rather than counted as a hit.
	ExpectedLine int `json:"expected_line,omitempty"`
	// Exploitable records whether a human considers the pattern reachable, used
	// to score the reasoning pass rather than the rules.
	Exploitable bool `json:"exploitable"`
}

// Corpus is the labelled set.
type Corpus struct {
	Version int    `json:"version"`
	Cases   []Case `json:"cases"`
}

// LoadCorpus reads and validates a labelled corpus from a filesystem.
func LoadCorpus(fsys fs.FS, name string) (Corpus, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Corpus{}, fmt.Errorf("reading eval corpus %s: %w", name, err)
	}

	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return Corpus{}, fmt.Errorf("parsing eval corpus %s: %w", name, err)
	}
	if err := corpus.Validate(); err != nil {
		return Corpus{}, fmt.Errorf("in %s: %w", name, err)
	}
	return corpus, nil
}

// Validate checks the corpus for the mistakes that would silently distort a
// score: a duplicate id, an unknown rule label, or a case with no file.
func (c Corpus) Validate() error {
	if len(c.Cases) == 0 {
		return fmt.Errorf("corpus contains no cases")
	}

	known := map[string]bool{}
	for _, id := range finding.AllRules() {
		known[string(id)] = true
	}

	seen := map[string]bool{}
	for i, tc := range c.Cases {
		if tc.ID == "" {
			return fmt.Errorf("case %d has no id", i)
		}
		if seen[tc.ID] {
			return fmt.Errorf("duplicate case id %q", tc.ID)
		}
		seen[tc.ID] = true

		if tc.File == "" {
			return fmt.Errorf("case %s has no file", tc.ID)
		}
		if tc.Category != NoFinding && !known[tc.Category] {
			return fmt.Errorf("case %s has unknown category %q", tc.ID, tc.Category)
		}
		for _, rule := range tc.Expected {
			if !known[rule] {
				return fmt.Errorf("case %s expects unknown rule %q", tc.ID, rule)
			}
		}
		if tc.Category == NoFinding && len(tc.Expected) > 0 {
			return fmt.Errorf("case %s is labelled clean but expects %v", tc.ID, tc.Expected)
		}
		if tc.Category != NoFinding && len(tc.Expected) == 0 {
			return fmt.Errorf("case %s has category %q but expects nothing", tc.ID, tc.Category)
		}
	}

	return nil
}

// Categories lists the categories present, clean last.
func (c Corpus) Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, tc := range c.Cases {
		if tc.Category != NoFinding && !seen[tc.Category] {
			seen[tc.Category] = true
			out = append(out, tc.Category)
		}
	}
	sort.Strings(out)

	for _, tc := range c.Cases {
		if tc.Category == NoFinding {
			out = append(out, NoFinding)
			break
		}
	}
	return out
}

// Resolve returns the case's workflow path relative to the corpus file.
func (tc Case) Resolve(corpusPath string) string {
	return path.Join(path.Dir(corpusPath), tc.File)
}
