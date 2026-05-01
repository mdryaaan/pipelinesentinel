package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient points a client at a stub API server.
func newTestClient(t *testing.T, handler http.HandlerFunc, token string) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := NewClient(ClientOptions{Token: token, BaseURL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return client, srv
}

func TestNewClientReadsEitherTokenVariable(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	c, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Authenticated() {
		t.Error("client should be unauthenticated with no token in the environment")
	}

	t.Setenv("GH_TOKEN", "from-gh-cli")
	c, err = NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Authenticated() {
		t.Error("GH_TOKEN should authenticate the client")
	}

	// An explicit token wins over the environment.
	t.Setenv("GH_TOKEN", "from-gh-cli")
	c, err = NewClient(ClientOptions{Token: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	if c.token != "explicit" {
		t.Errorf("token = %q, want the explicit one", c.token)
	}
}

func TestRepoSourceFetchesWorkflows(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/.github/workflows"):
			fmt.Fprint(w, `[
			  {"type":"file","name":"ci.yml","path":".github/workflows/ci.yml","encoding":"base64","content":"bmFtZTogQ0kK","html_url":"https://github.com/o/r/blob/main/.github/workflows/ci.yml"},
			  {"type":"file","name":"notes.md","path":".github/workflows/notes.md"},
			  {"type":"dir","name":"partials","path":".github/workflows/partials"}
			]`)
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}, "t")

	got, err := NewRepoSource(client, "o", "r", "").Workflows(context.Background())
	if err != nil {
		t.Fatalf("Workflows failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d workflows, want 1", len(got))
	}
	if string(got[0].Content) != "name: CI\n" {
		t.Errorf("content = %q, want the decoded body", got[0].Content)
	}
	if got[0].Repo != "o/r" {
		t.Errorf("repo = %q, want o/r", got[0].Repo)
	}
	if got[0].URL == "" {
		t.Error("the workflow should carry a link back to github.com")
	}
}

// When the listing withholds a body, the client must pay a second round trip
// rather than audit an empty file and call it clean.
func TestRepoSourceFetchesWithheldContent(t *testing.T) {
	var contentCalls int

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.HasSuffix(r.URL.Path, "/contents/.github/workflows") {
			fmt.Fprint(w, `[{"type":"file","name":"ci.yml","path":".github/workflows/ci.yml"}]`)
			return
		}
		contentCalls++
		fmt.Fprint(w, `{"type":"file","name":"ci.yml","path":".github/workflows/ci.yml","encoding":"base64","content":"bmFtZTogQ0kK"}`)
	}, "t")

	got, err := NewRepoSource(client, "o", "r", "main").Workflows(context.Background())
	if err != nil {
		t.Fatalf("Workflows failed: %v", err)
	}
	if contentCalls != 1 {
		t.Errorf("made %d content calls, want 1", contentCalls)
	}
	if string(got[0].Content) != "name: CI\n" {
		t.Errorf("content = %q", got[0].Content)
	}
}

func TestRepoSourceErrors(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		token      string
		headers    map[string]string
		wantSubstr string
	}{
		{
			name:       "missing repository without a token mentions private repos",
			status:     http.StatusNotFound,
			body:       `{"message":"Not Found"}`,
			wantSubstr: "GITHUB_TOKEN",
		},
		{
			name:       "rejected token",
			status:     http.StatusUnauthorized,
			body:       `{"message":"Bad credentials"}`,
			token:      "bad",
			wantSubstr: "token was rejected",
		},
		{
			name:   "exhausted rate limit explains the cap",
			status: http.StatusForbidden,
			body:   `{"message":"API rate limit exceeded"}`,
			headers: map[string]string{
				"X-RateLimit-Limit":     "60",
				"X-RateLimit-Remaining": "0",
				"X-RateLimit-Reset":     fmt.Sprint(time.Now().Add(90 * time.Second).Unix()),
			},
			wantSubstr: "60/hour",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}, tc.token)

			_, err := NewRepoSource(client, "o", "r", "").Workflows(context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not mention %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestNotFoundIsIdentifiable(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}, "t")

	_, err := NewRepoSource(client, "o", "r", "").Workflows(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error %v does not wrap ErrNotFound", err)
	}
}

func TestRateLimitErrorMessage(t *testing.T) {
	err := &RateLimitError{Reset: time.Now().Add(2 * time.Minute), Authenticated: false}

	msg := err.Error()
	if !strings.Contains(msg, "resets in") {
		t.Errorf("message should say how long to wait: %q", msg)
	}
	if !strings.Contains(msg, "5000/hour") {
		t.Errorf("an unauthenticated caller should be told a token helps: %q", msg)
	}
	if !err.Retryable() {
		t.Error("a rate limit is worth retrying")
	}
	if err.RetryAfter() <= 0 {
		t.Error("RetryAfter should be positive before the reset time")
	}

	authed := &RateLimitError{Reset: time.Now().Add(time.Minute), Authenticated: true, Secondary: true}
	if strings.Contains(authed.Error(), "5000/hour") {
		t.Error("an authenticated caller does not need the token advice")
	}
	if !strings.Contains(authed.Error(), "secondary") {
		t.Error("a secondary limit should be named as such")
	}

	// A reset time in the past means the wait is over, not negative.
	past := &RateLimitError{Reset: time.Now().Add(-time.Minute)}
	if past.RetryAfter() != 0 {
		t.Errorf("RetryAfter() = %v, want 0 for a past reset", past.RetryAfter())
	}
}

func TestRateStateSummary(t *testing.T) {
	if got := (RateState{}).Summary(); !strings.Contains(got, "unknown") {
		t.Errorf("Summary() = %q, want it to admit the state is unknown", got)
	}

	state := RateState{Limit: 5000, Remaining: 4980, Reset: time.Now()}
	if !state.Known() || state.Exhausted() {
		t.Error("a healthy state should be known and not exhausted")
	}
	if got := state.Summary(); !strings.Contains(got, "4980/5000") {
		t.Errorf("Summary() = %q", got)
	}

	if !(RateState{Limit: 60, Remaining: 0}).Exhausted() {
		t.Error("zero remaining is exhausted")
	}
}

func TestPingReportsCredentialProblems(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Bad credentials"}`)
	}, "bad")

	if err := client.ping(context.Background()); err == nil {
		t.Fatal("expected an error from ping")
	}
}
