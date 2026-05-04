// Package config resolves settings from defaults, a config file, the
// environment, and flags.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

// FileName is the config file pipelinesentinel looks for in a repository.
const FileName = ".pipelinesentinel.yml"

// Config is the resolved settings for a run.
type Config struct {
	// Provider selects the reasoning backend.
	Provider string `yaml:"provider"`
	// Model overrides the provider's default model.
	Model string `yaml:"model"`
	// BaseURL points at a self-hosted Ollama or a GitHub Enterprise instance.
	BaseURL string `yaml:"base_url"`
	// Temperature is pinned low: adjudication wants repeatability.
	Temperature float64 `yaml:"temperature"`
	// Reason enables the LLM escalation pass.
	Reason bool `yaml:"reason"`
	// MinSeverity is the threshold below which findings are not reported.
	MinSeverity string `yaml:"min_severity"`
	// FailOn is the threshold at which the process exits non-zero.
	FailOn string `yaml:"fail_on"`
	// Rules narrows the run to specific rules; empty means all of them.
	Rules []string `yaml:"rules"`
	// Ignore suppresses specific rules.
	Ignore []string `yaml:"ignore"`
	// IgnorePaths suppresses whole files by glob.
	IgnorePaths []string `yaml:"ignore_paths"`
}

// Default returns the settings used when nothing overrides them.
//
// Reasoning is off by default. The rules are the product; the model is an
// assist, and a tool that silently tries to reach a daemon on every run — then
// prints a connection error to someone who only wanted a lint — is a tool
// people stop running.
func Default() Config {
	return Config{
		Provider:    llm.ProviderOllama,
		Temperature: 0.1,
		Reason:      false,
		MinSeverity: string(finding.Info),
		FailOn:      string(finding.High),
	}
}

// Load reads a config file, returning defaults when none exists.
//
// A missing file is not an error: the tool must work in a repository that has
// never heard of it. A malformed file is an error, because silently ignoring
// settings someone wrote down is worse than stopping.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading %s: %w", path, err)
	}

	// Unknown keys are rejected: a typo in `min_severity` would otherwise leave
	// the threshold at its default while the user believed they had raised it.
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Default(), fmt.Errorf("parsing %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Default(), fmt.Errorf("in %s: %w", path, err)
	}
	return cfg, nil
}

// Discover looks for a config file in dir and its parents, so running the tool
// from a subdirectory finds the repository's settings.
func Discover(dir string) (Config, string, error) {
	current, err := filepath.Abs(dir)
	if err != nil {
		return Default(), "", fmt.Errorf("resolving %s: %w", dir, err)
	}

	for {
		candidate := filepath.Join(current, FileName)
		if _, err := os.Stat(candidate); err == nil {
			cfg, err := Load(candidate)
			return cfg, candidate, err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return Default(), "", nil
		}
		current = parent
	}
}

// Validate checks the resolved settings.
func (c Config) Validate() error {
	switch c.Provider {
	case llm.ProviderOllama, llm.ProviderClaude, llm.ProviderOffline:
	default:
		return fmt.Errorf("unknown provider %q (want one of: %s, %s, %s)",
			c.Provider, llm.ProviderOllama, llm.ProviderClaude, llm.ProviderOffline)
	}

	if _, err := finding.ParseSeverity(c.MinSeverity); err != nil {
		return fmt.Errorf("min_severity: %w", err)
	}
	if _, err := finding.ParseSeverity(c.FailOn); err != nil {
		return fmt.Errorf("fail_on: %w", err)
	}

	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("temperature %v is outside the usable range [0,2]", c.Temperature)
	}

	known := map[string]bool{}
	for _, id := range finding.AllRules() {
		known[string(id)] = true
	}
	for _, list := range [][]string{c.Rules, c.Ignore} {
		for _, id := range list {
			if !known[strings.ToLower(strings.TrimSpace(id))] {
				return fmt.Errorf("unknown rule %q (run `pipelinesentinel audit --list-rules`)", id)
			}
		}
	}

	return nil
}

// Severity returns the parsed reporting threshold.
func (c Config) Severity() finding.Severity {
	s, err := finding.ParseSeverity(c.MinSeverity)
	if err != nil {
		return finding.Info
	}
	return s
}

// FailThreshold returns the parsed failure threshold.
func (c Config) FailThreshold() finding.Severity {
	s, err := finding.ParseSeverity(c.FailOn)
	if err != nil {
		return finding.High
	}
	return s
}

// LLMOptions renders the provider options this config implies.
func (c Config) LLMOptions() llm.Options {
	return llm.Options{
		Provider:    c.Provider,
		Model:       c.Model,
		BaseURL:     c.BaseURL,
		Temperature: c.Temperature,
	}
}

// Ignored reports whether a file path is excluded by ignore_paths.
func (c Config) Ignored(path string) bool {
	for _, pattern := range c.IgnorePaths {
		if matched, err := filepath.Match(pattern, path); err == nil && matched {
			return true
		}
		// A bare filename in ignore_paths should match wherever the file lives,
		// since workflow paths carry a `.github/workflows/` prefix nobody wants
		// to retype.
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err == nil && matched {
			return true
		}
	}
	return false
}
