package github

import (
	"fmt"
	"time"

	gh "github.com/google/go-github/v66/github"
)

// RateState is what the API last told us about the rate limit.
type RateState struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Reset     time.Time `json:"reset"`
}

// Known returns whether any rate information has been observed yet.
func (r RateState) Known() bool { return r.Limit > 0 }

// Exhausted reports whether the budget is spent.
func (r RateState) Exhausted() bool { return r.Known() && r.Remaining <= 0 }

// Summary renders the state for a report footer.
func (r RateState) Summary() string {
	if !r.Known() {
		return "rate limit: unknown"
	}
	return fmt.Sprintf("rate limit: %d/%d remaining, resets %s",
		r.Remaining, r.Limit, r.Reset.Format(time.RFC3339))
}

// RateLimitError is returned when the API refuses further calls.
//
// It is a distinct type because the right response differs from every other
// failure: waiting works, and the message should say how long and — for an
// unauthenticated caller stuck at 60 requests an hour — that a token raises the
// ceiling by more than eighty times.
type RateLimitError struct {
	Reset         time.Time
	Secondary     bool
	Authenticated bool
}

// Error describes the limit and what to do about it.
func (e *RateLimitError) Error() string {
	kind := "rate limit"
	if e.Secondary {
		kind = "secondary rate limit"
	}

	wait := time.Until(e.Reset).Round(time.Second)
	if wait < 0 {
		wait = 0
	}

	msg := fmt.Sprintf("GitHub %s reached; resets in %s", kind, wait)
	if !e.Authenticated {
		msg += " (unauthenticated requests are capped at 60/hour — set GITHUB_TOKEN for 5000/hour)"
	}
	return msg
}

// Retryable tells utils.Do that waiting is worthwhile.
func (e *RateLimitError) Retryable() bool { return true }

// RetryAfter is how long a caller should wait before trying again.
func (e *RateLimitError) RetryAfter() time.Duration {
	wait := time.Until(e.Reset)
	if wait < 0 {
		return 0
	}
	return wait
}

// rateFrom reads the limit headers off a response.
func rateFrom(resp *gh.Response) RateState {
	if resp == nil {
		return RateState{}
	}
	return RateState{
		Limit:     resp.Rate.Limit,
		Remaining: resp.Rate.Remaining,
		Reset:     resp.Rate.Reset.Time,
	}
}
