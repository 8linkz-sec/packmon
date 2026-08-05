package sqlite

import (
	"net/http"
	"testing"
	"time"
)

func TestParseSyncRetryAfter(t *testing.T) {
	t.Parallel()

	futureAt := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	pastAt := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		header     string
		want       time.Duration
		wantFuture time.Time
	}{
		{
			name:   "positive delta seconds",
			header: "15",
			want:   15 * time.Second,
		},
		{
			name:   "zero delta seconds",
			header: "0",
			want:   0,
		},
		{
			name:   "negative delta seconds",
			header: "-5",
			want:   0,
		},
		{
			name:       "future http date",
			header:     futureAt.Format(http.TimeFormat),
			wantFuture: futureAt,
		},
		{
			name:   "past http date",
			header: pastAt.Format(http.TimeFormat),
			want:   0,
		},
		{
			name:   "invalid header",
			header: "not-a-retry-after",
			want:   0,
		},
		{
			name:   "empty header",
			header: "",
			want:   0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			before := time.Now()
			got := parseSyncRetryAfter(tt.header)
			after := time.Now()

			if !tt.wantFuture.IsZero() {
				minDelay := tt.wantFuture.Sub(after)
				maxDelay := tt.wantFuture.Sub(before)
				if got < minDelay || got > maxDelay {
					t.Fatalf("parseSyncRetryAfter(%q) = %v, want between %v and %v", tt.header, got, minDelay, maxDelay)
				}
				return
			}

			if got != tt.want {
				t.Fatalf("parseSyncRetryAfter(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}
