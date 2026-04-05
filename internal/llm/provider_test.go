package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sampleRequest() Request {
	return Request{
		RuleID:    "script-injection",
		Title:     "Untrusted github.event.issue.title interpolated into a run block",
		Detail:    "The value becomes command syntax.",
		File:      "triage.yml",
		Line:      12,
		Job:       "triage",
		Step:      "Label from the issue title",
		Triggers:  []string{"issues"},
		Context:   "  10 | steps:\n  11 |   - run: |\n  12 |       echo \"${{ github.event.issue.title }}\"\n",
		FirstLine: 10,
		LastLine:  12,
	}
}

func TestNewSelectsProviders(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-key")

	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{"ollama", ProviderOllama, ProviderOllama},
		{"empty defaults to ollama", "", ProviderOllama},
		{"claude", ProviderClaude, ProviderClaude},
		{"offline", ProviderOffline, ProviderOffline},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(Options{Provider: tc.provider})
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			if p.Name() != tc.want {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.want)
			}
			if p.Model() == "" {
				t.Error("Model() is empty")
			}
		})
	}

	if _, err := New(Options{Provider: "gpt"}); err == nil {
		t.Error("expected an error for an unknown provider")
	}
}

// Claude without a key must fail construction with advice, not fail later with
// an opaque HTTP 401 halfway through an audit.
func TestNewClaudeWithoutAKeyExplainsTheAlternative(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")

	_, err := New(Options{Provider: ProviderClaude})
	if err == nil {
		t.Fatal("expected an error without an API key")
	}
	if !strings.Contains(err.Error(), "ollama") {
		t.Errorf("error should point at the local alternative, got: %v", err)
	}
}

func TestOllamaReviewParsesAResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		if req.Format != "json" {
			t.Errorf("format = %q, want json", req.Format)
		}
		if !strings.Contains(req.Prompt, "github.event.issue.title") {
			t.Error("prompt does not carry the excerpt")
		}
		_ = json.NewEncoder(w).Encode(ollamaResponse{
			Response: `{"verdict":"exploitable","confidence":0.85,"reasoning":"Any GitHub user can open an issue.","cited_lines":[12],"mitigation":"Use env."}`,
			Done:     true,
		})
	}))
	defer srv.Close()

	p := NewOllama(Options{BaseURL: srv.URL})
	got, err := p.Review(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if got.Verdict != VerdictExploitable {
		t.Errorf("verdict = %q, want %q", got.Verdict, VerdictExploitable)
	}
}

// One repair retry, and only for a formatting failure.
func TestOllamaRetriesOnceOnMalformedOutput(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req ollamaRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		if calls == 1 {
			_ = json.NewEncoder(w).Encode(ollamaResponse{Response: "I think it is fine."})
			return
		}
		if !strings.Contains(req.Prompt, "could not be parsed") {
			t.Error("the retry did not carry the repair instruction")
		}
		_ = json.NewEncoder(w).Encode(ollamaResponse{
			Response: `{"verdict":"uncertain","confidence":0.4,"reasoning":"Not enough context.","cited_lines":[]}`,
		})
	}))
	defer srv.Close()

	got, err := NewOllama(Options{BaseURL: srv.URL}).Review(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d calls, want exactly 2", calls)
	}
	if got.Verdict != VerdictUncertain {
		t.Errorf("verdict = %q, want %q", got.Verdict, VerdictUncertain)
	}
}

func TestOllamaGivesUpAfterTwoMalformedResponses(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(ollamaResponse{Response: "still not json"})
	}))
	defer srv.Close()

	if _, err := NewOllama(Options{BaseURL: srv.URL}).Review(context.Background(), sampleRequest()); err == nil {
		t.Fatal("expected an error after two malformed responses")
	}
	if calls != 2 {
		t.Errorf("made %d calls, want exactly 2", calls)
	}
}

// A refused connection is not fixed by asking the model more firmly, so it must
// not be retried.
func TestOllamaDoesNotRetryTransportFailures(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := NewOllama(Options{BaseURL: srv.URL}).Review(context.Background(), sampleRequest()); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("made %d calls, want exactly 1", calls)
	}
}

func TestOllamaErrorNamesTheDaemon(t *testing.T) {
	_, err := NewOllama(Options{BaseURL: "http://127.0.0.1:1"}).Review(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if !strings.Contains(err.Error(), "ollama serve") {
		t.Errorf("error should tell the user what to start, got: %v", err)
	}
}

func TestClaudeReviewParsesAResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key = %q, want test-key", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"verdict\":\"not_exploitable\",\"confidence\":0.8,\"reasoning\":\"Bound to env.\",\"cited_lines\":[11]}"}]}`))
	}))
	defer srv.Close()

	p, err := NewClaude(Options{BaseURL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("NewClaude failed: %v", err)
	}
	got, err := p.Review(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if got.Verdict != VerdictNotExploitable {
		t.Errorf("verdict = %q, want %q", got.Verdict, VerdictNotExploitable)
	}
}

func TestClaudeSurfacesAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))
	}))
	defer srv.Close()

	p, _ := NewClaude(Options{BaseURL: srv.URL, APIKey: "test-key"})
	_, err := p.Review(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "slow down") {
		t.Errorf("error should carry the API message, got: %v", err)
	}
}
