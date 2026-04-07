package github

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LocalSource reads workflows from a directory on disk.
//
// This is the source that runs inside the GitHub Action: the repository is
// already checked out, so re-fetching the same files over the API would spend
// rate limit to learn nothing.
type LocalSource struct {
	root string
}

// NewLocalSource builds a source over a directory. The directory may be a
// repository root, a `.github/workflows` directory, or a single file.
func NewLocalSource(root string) *LocalSource { return &LocalSource{root: root} }

// Name describes the source.
func (s *LocalSource) Name() string { return s.root }

// Workflows walks the directory and returns every workflow file, sorted by path
// so two runs over the same tree report findings in the same order.
func (s *LocalSource) Workflows(_ context.Context) ([]WorkflowFile, error) {
	info, err := os.Stat(s.root)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.root, err)
	}

	if !info.IsDir() {
		content, err := os.ReadFile(s.root)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", s.root, err)
		}
		return []WorkflowFile{{Path: s.root, Content: content}}, nil
	}

	// A repository root is the common case, so narrow to the workflows
	// directory when one exists rather than auditing every YAML file in the
	// tree — a Kubernetes manifest is not a workflow.
	search := s.root
	if nested := filepath.Join(s.root, WorkflowsDir); dirExists(nested) {
		search = nested
	}

	var out []WorkflowFile
	err = filepath.WalkDir(search, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != search {
				return filepath.SkipDir
			}
			return nil
		}
		if !IsWorkflowFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		out = append(out, WorkflowFile{Path: path, Content: content})
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no workflow files found under %s", search)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
