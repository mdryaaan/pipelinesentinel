package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T, name string) *Workflow {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	wf, err := Parse(name, data)
	require.NoError(t, err)
	return wf
}

func TestParseBasicStructure(t *testing.T) {
	wf := loadFixture(t, "vulnerable-workflow-1.yml")

	assert.Equal(t, "PR Preview", wf.Name.Value)
	assert.True(t, wf.HasTrigger("pull_request_target"))
	assert.False(t, wf.HasTrigger("push"))

	require.Len(t, wf.Jobs, 1)
	job := wf.Jobs[0]
	assert.Equal(t, "preview", job.ID.Value)
	require.Len(t, job.Steps, 3)
	assert.Equal(t, "actions/checkout@v4", job.Steps[0].Uses.Value)
}

// The whole point of parsing through yaml.Node is accurate citations, so the
// positions are asserted against the literal fixture content rather than
// against each other.
func TestLineNumbersMatchFixtureContent(t *testing.T) {
	wf := loadFixture(t, "vulnerable-workflow-1.yml")

	tests := []struct {
		name     string
		pos      Pos
		contains string
	}{
		{"workflow name", wf.Name.Pos, "PR Preview"},
		{"trigger", wf.TriggerPos("pull_request_target"), "pull_request_target"},
		{"permissions", wf.Permissions.Pos, "permissions"},
		{"job id", wf.Jobs[0].ID.Pos, "preview:"},
		{"checkout uses", wf.Jobs[0].Steps[0].Uses.Pos, "actions/checkout@v4"},
		{"untrusted ref input", wf.Jobs[0].Steps[0].With["ref"].Pos, "head.sha"},
		{"deploy run key", wf.Jobs[0].Steps[2].Pos, "run:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.True(t, tt.pos.Valid(), "position should be recorded")
			line := wf.LineAt(tt.pos.Line)
			assert.Contains(t, line, tt.contains,
				"line %d should contain %q but was %q", tt.pos.Line, tt.contains, line)
		})
	}
}

func TestBlockScalarPositionPointsAtScriptNotKey(t *testing.T) {
	wf := loadFixture(t, "vulnerable-workflow-1.yml")
	step := wf.Jobs[0].Steps[1]

	require.True(t, step.RunBodyPos.Valid())
	body := wf.LineAt(step.RunBodyPos.Line)
	assert.Contains(t, body, "echo",
		"a `run: |` block should cite its first script line, not the word run")
}

func TestPermissionsForms(t *testing.T) {
	blanket := loadFixture(t, "vulnerable-workflow-1.yml")
	assert.True(t, blanket.Permissions.Declared)
	assert.Equal(t, "write-all", blanket.Permissions.Blanket.Value)

	scoped := loadFixture(t, "safe-workflow-1.yml")
	assert.True(t, scoped.Permissions.Declared)
	assert.Equal(t, "read", scoped.Permissions.Scopes["contents"].Value)

	missing := loadFixture(t, "vulnerable-workflow-2.yml")
	assert.False(t, missing.Permissions.Declared,
		"a workflow with no permissions block must be detectable as such")
}

func TestJobLevelPermissions(t *testing.T) {
	wf := loadFixture(t, "safe-workflow-2.yml")
	require.Len(t, wf.Jobs, 1)

	perms := wf.Jobs[0].Permissions
	assert.True(t, perms.Declared)
	assert.Equal(t, "read", perms.Scopes["pull-requests"].Value)
}

func TestParseHandlesMappingTriggers(t *testing.T) {
	wf := loadFixture(t, "vulnerable-workflow-2.yml")
	assert.True(t, wf.HasTrigger("issues"))
	assert.True(t, wf.HasTrigger("issue_comment"))
}

// YAML 1.1 turns a bare `on` into the boolean true; if the parser only looked
// up "on", every trigger-dependent rule would silently find nothing.
func TestParseHandlesYAMLBooleanOnKey(t *testing.T) {
	data := []byte("name: T\non: pull_request_target\njobs:\n  a:\n    steps:\n      - run: echo hi\n")
	wf, err := Parse("t.yml", data)
	require.NoError(t, err)
	assert.True(t, wf.HasTrigger("pull_request_target"))
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"not yaml", "\tthis: [is: not: valid"},
		{"empty", ""},
		{"top level sequence", "- a\n- b\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("x.yml", []byte(tt.data))
			assert.Error(t, err)
		})
	}
}

func TestSnippetRendersNumberedContext(t *testing.T) {
	wf := loadFixture(t, "safe-workflow-1.yml")
	got := wf.Snippet(1, 1)

	assert.Contains(t, got, "   1 | name: CI")
	assert.NotEmpty(t, got)
	assert.Empty(t, wf.Snippet(0, 2))
}

func TestLineAtOutOfRange(t *testing.T) {
	wf := loadFixture(t, "safe-workflow-1.yml")
	assert.Empty(t, wf.LineAt(0))
	assert.Empty(t, wf.LineAt(99999))
}

func TestExcerptIsNumberedAndClamped(t *testing.T) {
	data := []byte("name: t\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n")
	wf, err := Parse("t.yml", data)
	require.NoError(t, err)

	assert.Equal(t, "   2 | on: [push]\n   3 | jobs:\n", wf.Excerpt(2, 3))
	assert.Equal(t, 5, wf.LineCount())

	// Out-of-range requests clamp rather than panic: a finding near the top or
	// the bottom of a file is exactly where an off-by-one would bite.
	assert.Contains(t, wf.Excerpt(-5, 2), "   1 | name: t")
	assert.Contains(t, wf.Excerpt(4, 900), "runs-on")
	assert.Empty(t, wf.Excerpt(9, 2), "an inverted range should be empty")
}
