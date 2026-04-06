package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
)

const (
	// CSRFFieldName is the HTML form field name for the CSRF token.
	CSRFFieldName = "_csrf"

	// csrfTokenBytes is the number of random bytes used for CSRF tokens.
	// 32 bytes = 256 bits of entropy, hex-encoded to 64 characters.
	csrfTokenBytes = 32
)

// CSRFToken returns the CSRF token for the given session. If no token
// exists yet, one is generated and stored in the session. The token is
// stable for the lifetime of the session so that forms rendered at
// different times within the same session all use the same token.
func CSRFToken(sess *Session) (string, error) {
	if sess == nil {
		return "", fmt.Errorf("auth: csrf: nil session")
	}
	if sess.csrfToken != "" {
		return sess.csrfToken, nil
	}

	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: csrf: generate token: %w", err)
	}
	sess.csrfToken = hex.EncodeToString(b)
	return sess.csrfToken, nil
}

// ValidateCSRF checks that the form value of _csrf matches the token
// stored in the session. Returns true only on an exact, non-empty match.
func ValidateCSRF(r *http.Request, sess *Session) bool {
	if sess == nil || sess.csrfToken == "" {
		return false
	}
	formToken := r.FormValue(CSRFFieldName)
	if formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(formToken), []byte(sess.csrfToken)) == 1
}
