package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRepo(t *testing.T) {
	tests := []struct {
		in          string
		owner, name string
		wantErr     bool
	}{
		{in: "mdryaaan/pipelinesentinel", owner: "mdryaaan", name: "pipelinesentinel"},
		{in: "https://github.com/mdryaaan/pipelinesentinel", owner: "mdryaaan", name: "pipelinesentinel"},
		{in: "github.com/mdryaaan/pipelinesentinel", owner: "mdryaaan", name: "pipelinesentinel"},
		{in: "https://github.com/mdryaaan/pipelinesentinel.git", owner: "mdryaaan", name: "pipelinesentinel"},
		{in: "  mdryaaan/pipelinesentinel  ", owner: "mdryaaan", name: "pipelinesentinel"},
		{in: "pipelinesentinel", wantErr: true},
		{in: "", wantErr: true},
		{in: "/", wantErr: true},
		{in: "owner/", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			owner, name, err := ParseRepo(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRepo(%q) failed: %v", tc.in, err)
			}
			if owner != tc.owner || name != tc.name {
				t.Errorf("got %s/%s, want %s/%s", owner, name, tc.owner, tc.name)
			}
		})
	}
}

func TestIsWorkflowFile(t *testing.T) {
	yes := []string{"ci.yml", "ci.yaml", ".github/workflows/RELEASE.YML", "a/b/c.yaml"}
	no := []string{"README.md", "Makefile", "ci.yml.bak", "config.json", "action.yml.tmpl"}

	for _, path := range yes {
		if !IsWorkflowFile(path) {
			t.Errorf("IsWorkflowFile(%q) = false, want true", path)
		}
	}
	for _, path := range no {
		if IsWorkflowFile(path) {
			t.Errorf("IsWorkflowFile(%q) = true, want false", path)
		}
	}
}

func TestLocalSourceWalksARepositoryRoot(t *testing.T) {
	root := t.TempDir()
	workflows := filepath.Join(root, WorkflowsDir)
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(filepath.Join(workflows, "ci.yml"), "name: CI\n")
	write(filepath.Join(workflows, "release.yaml"), "name: Release\n")
	write(filepath.Join(workflows, "notes.md"), "not a workflow\n")
	// A YAML file elsewhere in the tree is a manifest, not a workflow, and
	// auditing it would produce findings about a file Actions never runs.
	write(filepath.Join(root, "deployment.yml"), "apiVersion: apps/v1\n")

	got, err := NewLocalSource(root).Workflows(context.Background())
	if err != nil {
		t.Fatalf("Workflows failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d workflows, want 2: %+v", len(got), got)
	}
	if !strings.HasSuffix(got[0].Path, "ci.yml") {
		t.Errorf("workflows are not sorted by path: %s came first", got[0].Path)
	}
	if string(got[0].Content) != "name: CI\n" {
		t.Errorf("content = %q", got[0].Content)
	}
}

func TestLocalSourceAcceptsASingleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(path, []byte("name: CI\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := NewLocalSource(path).Workflows(context.Background())
	if err != nil {
		t.Fatalf("Workflows failed: %v", err)
	}
	if len(got) != 1 || got[0].Path != path {
		t.Fatalf("got %+v, want the single file", got)
	}
}

func TestLocalSourceErrors(t *testing.T) {
	if _, err := NewLocalSource(filepath.Join(t.TempDir(), "missing")).Workflows(context.Background()); err == nil {
		t.Error("expected an error for a missing path")
	}
	// An empty directory is a mistake worth reporting, not a clean audit.
	if _, err := NewLocalSource(t.TempDir()).Workflows(context.Background()); err == nil {
		t.Error("expected an error when no workflows were found")
	}
}

func TestFixtureSourceReadsAFilesystem(t *testing.T) {
	got, err := NewFixtureSource(os.DirFS(filepath.Join("..", "..", "testdata", "fixtures"))).
		Workflows(context.Background())
	if err != nil {
		t.Fatalf("Workflows failed: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d fixtures, want 5", len(got))
	}
	for _, wf := range got {
		if !strings.HasPrefix(wf.Path, WorkflowsDir) {
			t.Errorf("fixture path %q should be reported under %s", wf.Path, WorkflowsDir)
		}
		if len(wf.Content) == 0 {
			t.Errorf("fixture %s is empty", wf.Path)
		}
	}
}

func TestFixtureSourceWithoutAFilesystem(t *testing.T) {
	if _, err := NewFixtureSource(nil).Workflows(context.Background()); err == nil {
		t.Fatal("expected an error when no fixtures were compiled in")
	}
}
