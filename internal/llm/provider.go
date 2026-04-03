// Package llm wraps the reasoning model behind a narrow interface so the rest
// of pipelinesentinel never depends on a specific vendor.
package llm

import (
	"context"
	"fmt"
)

// Provider adjudicates one ambiguous finding.
//
// The interface is deliberately one method. Everything pipelinesentinel asks a
// model to do is "read this finding and the workflow around it, then tell me
// whether it is really exploitable" — the rules already decided *what* the
// pattern is. Keeping the surface this narrow is what makes the offline
// provider a genuine drop-in and what keeps a new vendor from touching the
// audit pipeline.
type Provider interface {
	// Name identifies the provider in reports and eval output.
	Name() string
	// Model identifies the specific model in use.
	Model() string
	// Review returns a validated verdict for one candidate finding.
	Review(ctx context.Context, req Request) (Review, error)
}

// Request is everything a provider needs to adjudicate one finding.
//
// It carries the surrounding workflow rather than only the offending line: the
// whole question the model is being asked — "can an attacker actually reach
// this?" — depends on the trigger, the job's permissions, and what the
// neighbouring steps do.
type Request struct {
	RuleID      string
	Title       string
	Detail      string
	File        string
	Line        int
	Job         string
	Step        string
	Triggers    []string
	Permissions string
	// Context is the numbered workflow excerpt. Line numbers are part of the
	// text so the model can cite them and so a citation can be checked.
	Context string
	// FirstLine and LastLine bound Context, and bound valid citations.
	FirstLine int
	LastLine  int
}

// Options configures provider construction.
type Options struct {
	Provider string
	Model    string
	BaseURL  string
	APIKey   string
	// Temperature is pinned low by callers: adjudication wants repeatability,
	// not creativity.
	Temperature float64
}

// Known provider identifiers.
const (
	ProviderOllama  = "ollama"
	ProviderClaude  = "claude"
	ProviderOffline = "offline"
)

// New builds a provider from options.
func New(opts Options) (Provider, error) {
	switch opts.Provider {
	case ProviderOllama, "":
		return NewOllama(opts), nil
	case ProviderClaude:
		return NewClaude(opts)
	case ProviderOffline:
		return NewOffline(), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (want one of: %s, %s, %s)",
			opts.Provider, ProviderOllama, ProviderClaude, ProviderOffline)
	}
}

// errorsIs keeps the errors dependency in one place so provider files read
// consistently.
func isMalformed(err error) bool { return err != nil && errorsIs(err, ErrMalformed) }
