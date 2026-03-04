package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLineOffset(t *testing.T) {
	tests := []struct {
		name  string
		start Pos
		delta int
		want  int
	}{
		{"first line of block", Pos{Line: 10}, 0, 10},
		{"third line of block", Pos{Line: 10}, 2, 12},
		{"negative clamps to start", Pos{Line: 10}, -3, 10},
		{"invalid start", Pos{}, 4, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, LineOffset(tt.start, tt.delta))
		})
	}
}

func TestPosValid(t *testing.T) {
	assert.True(t, Pos{Line: 1}.Valid())
	assert.False(t, Pos{}.Valid())
	assert.False(t, Pos{Line: 0, Column: 5}.Valid())
}

func TestScalarHelpers(t *testing.T) {
	assert.Equal(t, "v", Scalar{Value: "v"}.String())
	assert.True(t, Scalar{Value: "  "}.Empty())
	assert.False(t, Scalar{Value: "x"}.Empty())
}

func TestBlockBodyPosSkipsTheMarkerLine(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantLine int
		wantText string
	}{
		{
			name:     "literal block starts on the next line",
			yaml:     "steps:\n  - run: |\n      echo one\n      echo two\n",
			wantLine: 3,
			wantText: "echo one",
		},
		{
			name:     "folded block starts on the next line",
			yaml:     "steps:\n  - run: >\n      echo folded\n",
			wantLine: 3,
			wantText: "echo folded",
		},
		{
			name:     "plain scalar stays on its own line",
			yaml:     "steps:\n  - run: echo inline\n",
			wantLine: 2,
			wantText: "echo inline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := Parse("t.yml", []byte("name: t\non: push\njobs:\n  a:\n    "+tt.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			step := wf.Jobs[0].Steps[0]
			line := wf.LineAt(step.RunBodyPos.Line)
			assert.Contains(t, line, tt.wantText,
				"body position landed on line %d (%q)", step.RunBodyPos.Line, line)
		})
	}
}
