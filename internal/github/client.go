package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	gh "github.com/google/go-github/v66/github"
)

// Client wraps the GitHub REST API for the handful of calls this tool makes.
type Client struct {
	api   *gh.Client
	token string
	// Rate carries the limit state observed on the last call.
	Rate RateState
}

// ClientOptions configures a client.
type ClientOptions struct {
	// Token authenticates the client. Empty means unauthenticated, which is
	// allowed but rate limited to 60 requests an hour.
	Token string
	// BaseURL points at a GitHub Enterprise instance or a test server.
	BaseURL string
	// HTTPClient overrides the transport, used by tests.
	HTTPClient *http.Client
}

// NewClient builds a client, falling back to GITHUB_TOKEN then GH_TOKEN.
//
// Both names are checked because GITHUB_TOKEN is what Actions injects and
// GH_TOKEN is what the gh CLI exports; a user who has authenticated with gh
// should not have to learn a third variable.
func NewClient(opts ClientOptions) (*Client, error) {
	token := opts.Token
	if token == "" {
		token = firstNonEmpty(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN"))
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	api := gh.NewClient(httpClient)
	if token != "" {
		api = api.WithAuthToken(token)
	}

	if opts.BaseURL != "" {
		var err error
		api, err = api.WithEnterpriseURLs(opts.BaseURL, opts.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("configuring GitHub base URL %q: %w", opts.BaseURL, err)
		}
	}

	return &Client{api: api, token: token}, nil
}

// Authenticated reports whether a token was supplied.
func (c *Client) Authenticated() bool { return c.token != "" }

// ErrNotFound marks a repository or path that does not exist, or that the
// token cannot see. The two are indistinguishable over the API by design.
var ErrNotFound = errors.New("not found")

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// wrap turns a go-github error into something a user can act on.
func (c *Client) wrap(op string, resp *gh.Response, err error) error {
	if err == nil {
		return nil
	}

	if resp != nil {
		c.Rate = rateFrom(resp)

		switch resp.StatusCode {
		case http.StatusNotFound:
			hint := ""
			if !c.Authenticated() {
				hint = " (no token was supplied, so private repositories look identical to " +
					"missing ones — set GITHUB_TOKEN)"
			}
			return fmt.Errorf("%s: %w%s", op, ErrNotFound, hint)
		case http.StatusUnauthorized:
			return fmt.Errorf("%s: the token was rejected — check GITHUB_TOKEN", op)
		case http.StatusForbidden:
			if c.Rate.Remaining == 0 {
				return &RateLimitError{Reset: c.Rate.Reset, Authenticated: c.Authenticated()}
			}
			return fmt.Errorf("%s: forbidden — the token may lack the `repo` scope", op)
		}
	}

	var rateErr *gh.RateLimitError
	if errors.As(err, &rateErr) {
		return &RateLimitError{Reset: rateErr.Rate.Reset.Time, Authenticated: c.Authenticated()}
	}

	var abuseErr *gh.AbuseRateLimitError
	if errors.As(err, &abuseErr) {
		reset := time.Now().Add(time.Minute)
		if abuseErr.RetryAfter != nil {
			reset = time.Now().Add(*abuseErr.RetryAfter)
		}
		return &RateLimitError{Reset: reset, Secondary: true, Authenticated: c.Authenticated()}
	}

	return fmt.Errorf("%s: %w", op, err)
}

// ping is used by tests and by `audit --check-auth` to confirm credentials
// before a long run spends time only to fail at the end.
func (c *Client) ping(ctx context.Context) error {
	_, resp, err := c.api.RateLimit.Get(ctx)
	return c.wrap("checking GitHub credentials", resp, err)
}
