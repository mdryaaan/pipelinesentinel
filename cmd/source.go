package cmd

import (
	"fmt"
	"os"

	"github.com/mdryaaan/pipelinesentinel/internal/config"
	"github.com/mdryaaan/pipelinesentinel/internal/github"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

// resolveSource turns a positional argument into something to audit.
//
// The precedence is deliberate: --offline always wins, then an existing path on
// disk, then an owner/repo reference. Checking the filesystem before the API
// means `pipelinesentinel audit .` never makes a network call, which is what
// people expect and what makes the tool usable inside a locked-down runner.
func resolveSource(target string) (github.Source, error) {
	if opts.Offline {
		if embedded.Fixtures == nil {
			return nil, fmt.Errorf("this binary was built without the offline fixtures")
		}
		return github.NewFixtureSource(embedded.Fixtures), nil
	}

	if target == "" {
		target = "."
	}

	if _, err := os.Stat(target); err == nil {
		return github.NewLocalSource(target), nil
	}

	owner, repo, err := github.ParseRepo(target)
	if err != nil {
		return nil, fmt.Errorf("%w — pass a directory, an owner/repo reference, or --offline", err)
	}

	client, err := github.NewClient(github.ClientOptions{Token: opts.Token, BaseURL: opts.BaseURL})
	if err != nil {
		return nil, err
	}
	return github.NewRepoSource(client, owner, repo, opts.Ref), nil
}

// resolveProvider builds the reasoning provider, or nil when reasoning is off.
//
// Nil rather than a no-op provider, so the report can distinguish "no reasoning
// pass ran" from "a pass ran and changed nothing".
func resolveProvider(cfg config.Config) (llm.Provider, error) {
	if !cfg.Reason {
		return nil, nil
	}
	return llm.New(cfg.LLMOptions())
}
