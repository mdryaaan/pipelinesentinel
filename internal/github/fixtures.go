package github

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// FixtureSource serves example workflows from a filesystem, normally the one
// embedded in the binary at build time.
//
// It exists so the tool can be evaluated end to end with no token, no network,
// and no repository — which is how most people will first run it, and how the
// test suite runs it every time. Taking an fs.FS rather than embedding here
// keeps a single copy of the fixtures at the repository root: `go:embed` cannot
// reach outside its own package directory, and a second copy under
// internal/github would drift from the first the day someone edited one.
type FixtureSource struct {
	fsys fs.FS
	name string
}

// NewFixtureSource builds a source over a filesystem of workflow files.
func NewFixtureSource(fsys fs.FS) *FixtureSource {
	return &FixtureSource{fsys: fsys, name: "bundled fixtures (offline)"}
}

// Name describes the source.
func (s *FixtureSource) Name() string { return s.name }

// Workflows returns every workflow in the filesystem, sorted by name so two
// runs report findings in the same order.
func (s *FixtureSource) Workflows(_ context.Context) ([]WorkflowFile, error) {
	if s.fsys == nil {
		return nil, fmt.Errorf("no offline fixtures were compiled into this binary")
	}

	var out []WorkflowFile
	err := fs.WalkDir(s.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !IsWorkflowFile(p) {
			return nil
		}

		content, err := fs.ReadFile(s.fsys, p)
		if err != nil {
			return fmt.Errorf("reading fixture %s: %w", p, err)
		}
		out = append(out, WorkflowFile{
			Path:    path.Join(WorkflowsDir, path.Base(p)),
			Content: content,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading offline fixtures: %w", err)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no workflow files found in the offline fixture set")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
