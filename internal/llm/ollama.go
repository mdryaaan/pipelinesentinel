package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultOllamaURL is where Ollama listens out of the box.
const DefaultOllamaURL = "http://localhost:11434"

// DefaultOllamaModel is a small instruct model that fits on a laptop.
const DefaultOllamaModel = "llama3"

// Ollama talks to a local Ollama daemon.
//
// This is pipelinesentinel's default provider on purpose. Workflow YAML is not
// as sensitive as a build log, but it does describe a repository's deploy paths,
// its internal hostnames, and the names of every secret it holds — a fairly
// precise map of what to attack. Auditing it locally means that map never leaves
// the machine, and it also means anyone can run the full pipeline without an
// account or a bill.
type Ollama struct {
	baseURL     string
	model       string
	temperature float64
	client      *http.Client
}

// NewOllama builds an Ollama provider, filling in defaults.
func NewOllama(opts Options) *Ollama {
	base := opts.BaseURL
	if base == "" {
		base = DefaultOllamaURL
	}
	model := opts.Model
	if model == "" {
		model = DefaultOllamaModel
	}

	return &Ollama{
		baseURL:     base,
		model:       model,
		temperature: opts.Temperature,
		client:      &http.Client{Timeout: 180 * time.Second},
	}
}

// Name identifies the provider.
func (o *Ollama) Name() string { return ProviderOllama }

// Model identifies the model in use.
func (o *Ollama) Model() string { return o.model }

type ollamaRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	System  string         `json:"system"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format"`
	Options ollamaSettings `json:"options"`
}

type ollamaSettings struct {
	Temperature float64 `json:"temperature"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Review sends the finding to Ollama and parses the structured verdict.
func (o *Ollama) Review(ctx context.Context, req Request) (Review, error) {
	prompt := BuildPrompt(req)

	review, err := o.once(ctx, prompt)
	if err == nil {
		return review, nil
	}

	// One retry, and only for a formatting failure. A refused connection will
	// not be fixed by asking the model more firmly.
	if !isMalformed(err) {
		return Review{}, err
	}

	review, retryErr := o.once(ctx, prompt+"\n\n"+RepairPrompt)
	if retryErr != nil {
		return Review{}, fmt.Errorf("ollama returned unparseable output twice: %w", retryErr)
	}
	return review, nil
}

func (o *Ollama) once(ctx context.Context, prompt string) (Review, error) {
	payload, err := json.Marshal(ollamaRequest{
		Model:  o.model,
		Prompt: prompt,
		System: SystemPrompt,
		Stream: false,
		// Ollama's JSON mode constrains decoding to valid JSON, which removes
		// most of the malformed-response problem at the source.
		Format:  "json",
		Options: ollamaSettings{Temperature: o.temperature},
	})
	if err != nil {
		return Review{}, fmt.Errorf("encoding ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return Review{}, fmt.Errorf("building ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return Review{}, fmt.Errorf(
			"calling ollama at %s (is `ollama serve` running?): %w", o.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Review{}, fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	var out ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Review{}, fmt.Errorf("decoding ollama response: %w", err)
	}

	return ParseReview(out.Response)
}
