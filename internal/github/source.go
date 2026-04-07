// Package github fetches workflow files to audit, from a repository, from a
// local checkout, or from the bundled fixtures.
package github

import (
	"context"
	"fmt"
	"strings"
)

// WorkflowFile is one workflow definition and its contents.
type WorkflowFile struct {
	// Path is how the file is reported: `.github/workflows/ci.yml` for a
	// repository, the real path for a local directory.
	Path string
	// Repo is "owner/name" when the file came from a repository, empty for a
	// local source.
	Repo    string
	Content []byte
	// URL links to the file on github.com when one is known.
	URL string
}

// Source produces the workflows to audit.
//
// The interface is what lets `audit --offline`, `audit ./path`, and
// `audit owner/repo` run through exactly the same pipeline. That matters
// beyond tidiness: the offline path is the one used in tests, in CI, and by
// anyone evaluating the tool without a token, so it must not be a second
// implementation that drifts from the real one.
type Source interface {
	// Name describes the source for report headers.
	Name() string
	// Workflows returns every workflow file to audit.
	Workflows(ctx context.Context) ([]WorkflowFile, error)
}

// WorkflowsDir is where GitHub Actions looks for workflow definitions.
const WorkflowsDir = ".github/workflows"

// IsWorkflowFile reports whether a path names a workflow definition.
func IsWorkflowFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// ParseRepo splits an "owner/name" reference, tolerating a github.com URL.
func ParseRepo(ref string) (owner, name string, err error) {
	trimmed := strings.TrimSpace(ref)
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimPrefix(trimmed, "github.com/")
	trimmed = strings.TrimSuffix(trimmed, ".git")
	trimmed = strings.Trim(trimmed, "/")

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%q is not an owner/repo reference", ref)
	}
	return parts[0], parts[1], nil
}
