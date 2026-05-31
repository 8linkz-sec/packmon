package db

import (
	"testing"
	"time"
)

func TestAPIKeyIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	exact := now
	future := now.Add(time.Second)

	for _, tt := range []struct {
		name string
		key  APIKey
		want bool
	}{
		{name: "no expiry", key: APIKey{}, want: false},
		{name: "past expiry", key: APIKey{ExpiresAt: &past}, want: true},
		{name: "exactly now", key: APIKey{ExpiresAt: &exact}, want: true},
		{name: "future expiry", key: APIKey{ExpiresAt: &future}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.key.IsExpired(now); got != tt.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
