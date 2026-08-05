package auth

import "time"

// APIKeyCredential is the minimal authenticated API-key view needed outside
// the persistence layer.
type APIKeyCredential struct {
	ID        int
	Name      string
	ExpiresAt *time.Time
}

// IsExpired reports whether the API key has an expiry timestamp at or before now.
func (k APIKeyCredential) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && !k.ExpiresAt.After(now)
}
