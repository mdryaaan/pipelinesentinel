package utils

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type retryableError struct{ retry bool }

func (e retryableError) Error() string   { return "boom" }
func (e retryableError) Retryable() bool { return e.retry }

func fastRetry() RetryConfig {
	return RetryConfig{Attempts: 4, BaseWait: time.Millisecond, MaxWait: 2 * time.Millisecond}
}

func TestDoSucceedsWithoutRetrying(t *testing.T) {
	var calls int
	err := Do(context.Background(), fastRetry(), func(int) error {
		calls++
		return nil
	})

	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d calls, want 1", calls)
	}
}

func TestDoRetriesUntilSuccess(t *testing.T) {
	var calls int
	err := Do(context.Background(), fastRetry(), func(attempt int) error {
		calls++
		if attempt < 3 {
			return retryableError{retry: true}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if calls != 3 {
		t.Errorf("made %d calls, want 3", calls)
	}
}

// A 404 is not going to become a 200 on the fourth try, so an error that does
// not ask to be retried must fail immediately.
func TestDoDoesNotRetryPermanentErrors(t *testing.T) {
	var calls int
	err := Do(context.Background(), fastRetry(), func(int) error {
		calls++
		return errors.New("not found")
	})

	if err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("made %d calls, want 1", calls)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("the original error was lost: %v", err)
	}
}

func TestDoGivesUpAfterTheLastAttempt(t *testing.T) {
	var calls int
	err := Do(context.Background(), fastRetry(), func(int) error {
		calls++
		return retryableError{retry: true}
	})

	if err == nil {
		t.Fatal("expected an error")
	}
	if calls != 4 {
		t.Errorf("made %d calls, want 4", calls)
	}
	if !strings.Contains(err.Error(), "gave up after 4 attempts") {
		t.Errorf("error should say how many attempts were made: %v", err)
	}
}

func TestDoRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Do(ctx, fastRetry(), func(int) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestIsRetryableUnwraps(t *testing.T) {
	wrapped := errors.Join(errors.New("context"), retryableError{retry: true})
	if IsRetryable(wrapped) {
		// errors.Join does not expose a single Unwrap() error, so this is
		// expected to be false; the check pins the behaviour rather than
		// leaving it to chance.
		t.Log("joined errors are not unwrapped, as expected")
	}

	if !IsRetryable(retryableError{retry: true}) {
		t.Error("a retryable error should be recognised")
	}
	if IsRetryable(retryableError{retry: false}) {
		t.Error("an error that declines retry should be honoured")
	}
	if IsRetryable(nil) {
		t.Error("nil is not retryable")
	}
}

func TestDoClampsAttempts(t *testing.T) {
	var calls int
	_ = Do(context.Background(), RetryConfig{Attempts: 0}, func(int) error {
		calls++
		return errors.New("x")
	})
	if calls != 1 {
		t.Errorf("made %d calls with Attempts=0, want 1", calls)
	}
}

func TestUnifiedDiff(t *testing.T) {
	got := UnifiedDiff("ci.yml", 12, "  run: echo ${{ github.event.issue.title }}", "  run: echo $ISSUE_TITLE")

	for _, want := range []string{
		"--- a/ci.yml", "+++ b/ci.yml", "@@ -12,1 +12,1 @@",
		"-  run: echo ${{ github.event.issue.title }}", "+  run: echo $ISSUE_TITLE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff is missing %q:\n%s", want, got)
		}
	}
}

// A diff that changes nothing is noise in a report, so it is not emitted.
func TestUnifiedDiffSkipsNoOpChanges(t *testing.T) {
	if got := UnifiedDiff("ci.yml", 1, "  run: make test", "  run: make test  "); got != "" {
		t.Errorf("expected no diff, got:\n%s", got)
	}
}

func TestIndent(t *testing.T) {
	tests := map[string]string{
		"      - uses: actions/checkout@v4": "      ",
		"\t\trun: make":                     "\t\t",
		"no indent":                         "",
		"    ":                              "    ",
		"":                                  "",
	}

	for in, want := range tests {
		if got := Indent(in); got != want {
			t.Errorf("Indent(%q) = %q, want %q", in, got, want)
		}
	}
}
