package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/llm"
)

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The tool has to work in a repository that has never heard of it.
func TestLoadWithoutAFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yml"))
	if err != nil {
		t.Fatalf("a missing config should not be an error: %v", err)
	}
	if cfg.Provider != llm.ProviderOllama {
		t.Errorf("provider = %q, want the ollama default", cfg.Provider)
	}
	if cfg.Reason {
		t.Error("the reasoning pass should be opt-in")
	}
	if cfg.FailThreshold() != finding.High {
		t.Errorf("fail threshold = %s, want high", cfg.FailThreshold())
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	path := writeConfig(t, t.TempDir(), `
provider: claude
model: claude-sonnet-4-6
reason: true
min_severity: medium
fail_on: critical
ignore:
  - unpinned-action
ignore_paths:
  - "generated-*.yml"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Provider != llm.ProviderClaude || cfg.Model != "claude-sonnet-4-6" {
		t.Errorf("provider/model not applied: %+v", cfg)
	}
	if !cfg.Reason {
		t.Error("reason was not applied")
	}
	if cfg.Severity() != finding.Medium || cfg.FailThreshold() != finding.Critical {
		t.Errorf("thresholds not applied: %+v", cfg)
	}
	// Unset keys keep their defaults rather than becoming zero values.
	if cfg.Temperature != Default().Temperature {
		t.Errorf("temperature = %v, want the default %v", cfg.Temperature, Default().Temperature)
	}
}

// A typo in a key would otherwise leave the setting at its default while the
// user believed they had changed it.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "min_severty: high\n")

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a misspelled key")
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := map[string]string{
		"unknown provider":   "provider: gpt\n",
		"unknown severity":   "min_severity: severe\n",
		"unknown fail_on":    "fail_on: catastrophic\n",
		"unknown rule":       "ignore:\n  - unpined-action\n",
		"absurd temperature": "temperature: 9\n",
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), body)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), FileName) {
				t.Errorf("error should name the file: %v", err)
			}
		})
	}
}

// Running from a subdirectory should still find the repository's settings.
func TestDiscoverWalksUpToTheRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "min_severity: high\n")

	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg, path, err := Discover(nested)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if path == "" {
		t.Fatal("Discover found no config file")
	}
	if cfg.Severity() != finding.High {
		t.Errorf("severity = %s, want high", cfg.Severity())
	}
}

func TestDiscoverWithoutAConfigFile(t *testing.T) {
	cfg, path, err := Discover(t.TempDir())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if path != "" {
		t.Errorf("found an unexpected config at %s", path)
	}
	if cfg.Provider != Default().Provider {
		t.Error("expected defaults")
	}
}

func TestIgnoredMatchesBareFilenames(t *testing.T) {
	cfg := Config{IgnorePaths: []string{"generated-*.yml", ".github/workflows/vendor.yml"}}

	tests := map[string]bool{
		".github/workflows/generated-docs.yml": true,
		".github/workflows/vendor.yml":         true,
		".github/workflows/ci.yml":             false,
		"generated-docs.yml":                   true,
	}

	for path, want := range tests {
		if got := cfg.Ignored(path); got != want {
			t.Errorf("Ignored(%q) = %v, want %v", path, got, want)
		}
	}

	if (Config{}).Ignored("anything.yml") {
		t.Error("an empty ignore list should ignore nothing")
	}
}

func TestLLMOptionsCarryTheConfig(t *testing.T) {
	cfg := Config{Provider: llm.ProviderOllama, Model: "llama3", BaseURL: "http://host:11434", Temperature: 0.2}

	opts := cfg.LLMOptions()
	if opts.Provider != cfg.Provider || opts.Model != cfg.Model ||
		opts.BaseURL != cfg.BaseURL || opts.Temperature != cfg.Temperature {
		t.Errorf("LLMOptions() = %+v, want it to mirror the config", opts)
	}
}

// A threshold that somehow escaped validation must not open the gate.
func TestThresholdFallbacks(t *testing.T) {
	broken := Config{MinSeverity: "nonsense", FailOn: "nonsense"}
	if broken.Severity() != finding.Info {
		t.Errorf("Severity() = %s, want the permissive info default", broken.Severity())
	}
	if broken.FailThreshold() != finding.High {
		t.Errorf("FailThreshold() = %s, want the safe high default", broken.FailThreshold())
	}
}
