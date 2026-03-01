// Package utils holds small helpers shared across pipelinesentinel's packages.
package utils

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig controls the exponential backoff used for network calls.
type RetryConfig struct {
	Attempts int
	BaseWait time.Duration
	MaxWait  time.Duration
}

// DefaultRetry is a sensible policy for the GitHub API: enough attempts to ride
// out a secondary rate limit without hanging a CI job for minutes.
func DefaultRetry() RetryConfig {
	return RetryConfig{Attempts: 4, BaseWait: 500 * time.Millisecond, MaxWait: 8 * time.Second}
}

// Retryable lets a caller signal that an error is worth retrying. Errors that
// do not implement it are treated as permanent, so a 404 is not retried four
// times before failing.
type Retryable interface {
	Retryable() bool
}

// IsRetryable reports whether err, or anything it wraps, asks to be retried.
func IsRetryable(err error) bool {
	for err != nil {
		if r, ok := err.(Retryable); ok { //nolint:errorlint // unwrapped manually below
			return r.Retryable()
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Do runs fn until it succeeds, the context is cancelled, or attempts are
// exhausted. Backoff is exponential with jitter, so a fleet of runners retrying
// together does not synchronise into a thundering herd.
func Do(ctx context.Context, cfg RetryConfig, fn func(attempt int) error) error {
	if cfg.Attempts < 1 {
		cfg.Attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("retry cancelled: %w", err)
		}

		lastErr = fn(attempt)
		if lastErr == nil {
			return nil
		}
		if attempt == cfg.Attempts || !IsRetryable(lastErr) {
			break
		}

		wait := time.Duration(float64(cfg.BaseWait) * math.Pow(2, float64(attempt-1)))
		if wait > cfg.MaxWait {
			wait = cfg.MaxWait
		}
		jitter := time.Duration(rand.Int63n(int64(wait/2) + 1)) //nolint:gosec // jitter, not crypto

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(wait/2 + jitter):
		}
	}

	return fmt.Errorf("gave up after %d attempts: %w", cfg.Attempts, lastErr)
}
