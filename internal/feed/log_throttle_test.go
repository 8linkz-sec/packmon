package feed

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNewRepeatedErrorLoggerUsesDefaultWindow(t *testing.T) {
	t.Parallel()

	logger := NewRepeatedErrorLogger(0)
	if logger.window != DefaultRepeatedErrorLogWindow {
		t.Fatalf("window = %s, want %s", logger.window, DefaultRepeatedErrorLogWindow)
	}
}

func TestRepeatedErrorLoggerSuppressesRepeatedErrors(t *testing.T) {
	t.Parallel()

	throttle := NewRepeatedErrorLogger(time.Hour)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	throttle.Error(logger, "dequeue failed", errors.New("queue down"), slog.String("source", "socket"))
	throttle.Error(logger, "dequeue failed", errors.New("queue down"), slog.String("source", "socket"))

	output := logs.String()
	if got := strings.Count(output, `"level":"ERROR"`); got != 1 {
		t.Fatalf("ERROR logs = %d, want 1; logs=%s", got, output)
	}
	if got := strings.Count(output, `"level":"DEBUG"`); got != 1 {
		t.Fatalf("DEBUG logs = %d, want 1; logs=%s", got, output)
	}
	for _, want := range []string{`"error":"queue down"`, `"source":"socket"`, `"suppressed":true`} {
		if !strings.Contains(output, want) {
			t.Fatalf("logs missing %s: %s", want, output)
		}
	}
	if strings.Contains(output, `"suppressed_count"`) {
		t.Fatalf("suppressed_count should not be emitted until the next unsuppressed log: %s", output)
	}
}

func TestRepeatedErrorLoggerSummarizesSuppressedErrorsAfterWindow(t *testing.T) {
	t.Parallel()

	const window = time.Hour
	throttle := NewRepeatedErrorLogger(window)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	throttle.Warn(logger, "reset failed", errors.New("db down"))
	throttle.Warn(logger, "reset failed", errors.New("db down"))
	throttle.Warn(logger, "reset failed", errors.New("db down"))
	throttle.mu.Lock()
	throttle.lastError = time.Now().Add(-2 * window)
	throttle.mu.Unlock()
	throttle.Warn(logger, "reset failed", errors.New("db down"))

	output := logs.String()
	if got := strings.Count(output, `"level":"WARN"`); got != 2 {
		t.Fatalf("WARN logs = %d, want 2; logs=%s", got, output)
	}
	if got := strings.Count(output, `"level":"DEBUG"`); got != 2 {
		t.Fatalf("DEBUG logs = %d, want 2; logs=%s", got, output)
	}
	if !strings.Contains(output, `"suppressed_count":2`) {
		t.Fatalf("logs missing suppressed summary count: %s", output)
	}
}
