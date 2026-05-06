// Package parser turns GitHub Actions workflow YAML into a model that keeps
// every value's source position.
package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Pos is a 1-indexed source position, matching how editors and GitHub number
// lines. A zero Line means the position is unknown.
type Pos struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Valid reports whether the position points at real source.
func (p Pos) Valid() bool { return p.Line > 0 }

// Scalar is a string value that remembers where it came from.
//
// Findings are only as useful as their citations, so every value a rule can
// flag carries its own position rather than the position of its parent block.
// Unmarshalling straight into plain structs discards this, which is why the
// whole model is built from yaml.Node instead.
type Scalar struct {
	Value string `json:"value"`
	Pos   Pos    `json:"pos"`
	// Body is where the value's text begins. For a block scalar that is the
	// line after the `|` or `>` marker; for everything else it equals Pos.
	// Findings inside a multi-line value are offset from here.
	Body Pos `json:"body"`
}

// String returns the underlying value.
func (s Scalar) String() string { return s.Value }

// Empty reports whether the scalar holds no text.
func (s Scalar) Empty() bool { return strings.TrimSpace(s.Value) == "" }

// posOf reads a node's position.
func posOf(node *yaml.Node) Pos {
	if node == nil {
		return Pos{}
	}
	return Pos{Line: node.Line, Column: node.Column}
}

// scalarOf converts a scalar node, preserving its position.
func scalarOf(node *yaml.Node) Scalar {
	if node == nil {
		return Scalar{}
	}
	return Scalar{Value: node.Value, Pos: posOf(node), Body: BlockBodyPos(node)}
}

// mapValue returns the value node for key in a mapping node, plus the key's own
// node. Mapping contents alternate key, value, key, value.
//
// The key node is returned as well because a finding about a *field* should cite
// the key's line, not the value's — for a multi-line block scalar those differ,
// and citing the value lands the reader in the middle of a shell script.
func mapValue(node *yaml.Node, key string) (value *yaml.Node, keyNode *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if strings.EqualFold(k.Value, key) {
			return node.Content[i+1], k
		}
	}
	return nil, nil
}

// mapKeys lists a mapping's keys in document order.
func mapKeys(node *yaml.Node) []Scalar {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]Scalar, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		out = append(out, scalarOf(node.Content[i]))
	}
	return out
}

// seqItems returns a sequence node's children, or nil for anything else.
func seqItems(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

// stringsOf normalises a field that YAML allows as either a bare scalar or a
// sequence — `on: push` and `on: [push, pull_request]` are both legal.
func stringsOf(node *yaml.Node) []Scalar {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return []Scalar{scalarOf(node)}
	case yaml.SequenceNode:
		out := make([]Scalar, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				out = append(out, scalarOf(item))
			}
		}
		return out
	case yaml.MappingNode:
		// `on: { push: {...}, pull_request: {...} }` — the trigger names are keys.
		return mapKeys(node)
	default:
		return nil
	}
}

// BlockBodyPos returns where a scalar's *content* starts.
//
// For a literal or folded block (`run: |`), yaml.Node reports the line of the
// `|` marker, so the content actually begins on the next line. Citing the node
// position directly lands the reader on the word "run" instead of the offending
// command — which is the whole difference between a useful citation and a
// useless one.
func BlockBodyPos(node *yaml.Node) Pos {
	p := posOf(node)
	if !p.Valid() || node == nil {
		return p
	}
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle {
		p.Line++
		// Content is indented relative to the key, and the exact column is not
		// recoverable from the node, so it is cleared rather than left wrong.
		p.Column = 0
	}
	return p
}

// LineOffset converts a position inside a block scalar to an absolute file line.
//
// A `run: |` block reports one position for the whole script, so an offset
// within the script has to be added back to reach the real file line. Getting
// this wrong is the difference between citing the offending command and citing
// the word "run", which is why it lives in one function with its own tests.
func LineOffset(blockStart Pos, lineWithinBlock int) int {
	if !blockStart.Valid() {
		return 0
	}
	if lineWithinBlock < 0 {
		lineWithinBlock = 0
	}
	return blockStart.Line + lineWithinBlock
}
