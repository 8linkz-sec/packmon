package feed

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const DefaultRepeatedErrorLogWindow = time.Minute

// RepeatedErrorLogger emits the first occurrence of a repeated worker error at
// error level, then suppresses later occurrences in the same window to debug.
type RepeatedErrorLogger struct {
	mu         sync.Mutex
	window     time.Duration
	lastError  time.Time
	suppressed int
}

func NewRepeatedErrorLogger(window time.Duration) *RepeatedErrorLogger {
	if window <= 0 {
		window = DefaultRepeatedErrorLogWindow
	}
	return &RepeatedErrorLogger{window: window}
}

func (l *RepeatedErrorLogger) Error(logger *slog.Logger, msg string, err error, attrs ...slog.Attr) {
	l.log(logger, slog.LevelError, msg, err, attrs...)
}

func (l *RepeatedErrorLogger) Warn(logger *slog.Logger, msg string, err error, attrs ...slog.Attr) {
	l.log(logger, slog.LevelWarn, msg, err, attrs...)
}

func (l *RepeatedErrorLogger) log(logger *slog.Logger, level slog.Level, msg string, err error, attrs ...slog.Attr) {
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now()

	l.mu.Lock()
	if l.lastError.IsZero() || now.Sub(l.lastError) >= l.window {
		suppressed := l.suppressed
		l.lastError = now
		l.suppressed = 0
		l.mu.Unlock()

		logger.LogAttrs(context.Background(), level, msg, repeatedErrorAttrs(err, suppressed, false, attrs...)...)
		return
	}
	l.suppressed++
	l.mu.Unlock()

	logger.LogAttrs(context.Background(), slog.LevelDebug, msg, repeatedErrorAttrs(err, 0, true, attrs...)...)
}

func repeatedErrorAttrs(err error, suppressedCount int, suppressed bool, attrs ...slog.Attr) []slog.Attr {
	out := make([]slog.Attr, 0, len(attrs)+3)
	out = append(out, attrs...)
	if err != nil {
		out = append(out, slog.String("error", err.Error()))
	}
	if suppressedCount > 0 {
		out = append(out, slog.Int("suppressed_count", suppressedCount))
	}
	if suppressed {
		out = append(out, slog.Bool("suppressed", true))
	}
	return out
}
