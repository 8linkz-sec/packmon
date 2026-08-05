package auth

import (
	"testing"
	"time"
)

func TestAPIKeyCredentialIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	future := now.Add(time.Second)

	tests := []struct {
		name       string
		expiresAt  *time.Time
		wantExpire bool
	}{
		{name: "no expiration"},
		{name: "past expiration", expiresAt: &past, wantExpire: true},
		{name: "exact expiration", expiresAt: &now, wantExpire: true},
		{name: "future expiration", expiresAt: &future},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := APIKeyCredential{ExpiresAt: tt.expiresAt}
			if got := credential.IsExpired(now); got != tt.wantExpire {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.wantExpire)
			}
		})
	}
}
