package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
)

const (
	// CSRFFieldName is the HTML form field name for the CSRF token.
	CSRFFieldName = "_csrf"

	// csrfTokenBytes is the number of random bytes used for CSRF tokens.
	// 32 bytes = 256 bits of entropy, hex-encoded to 64 characters.
	csrfTokenBytes = 32
)

var sessionCSRFInitMu sync.Mutex

// CSRFToken returns the CSRF token for the given session. If no token
// exists yet, one is generated and stored in the session. The token is
// stable for the lifetime of the session so that forms rendered at
// different times within the same session all use the same token.
func CSRFToken(sess *Session) (string, error) {
	if sess == nil {
		return "", fmt.Errorf("auth: csrf: nil session")
	}
	state := sess.csrfState()
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.token != "" {
		return state.token, nil
	}

	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: csrf: generate token: %w", err)
	}
	state.token = hex.EncodeToString(b)
	return state.token, nil
}

// ValidateCSRF checks that the form value of _csrf matches the token
// stored in the session. Returns true only on an exact, non-empty match.
func ValidateCSRF(r *http.Request, sess *Session) bool {
	if sess == nil {
		return false
	}
	state := sess.csrfState()
	state.mu.Lock()
	token := state.token
	state.mu.Unlock()

	if token == "" {
		return false
	}
	formToken := r.FormValue(CSRFFieldName)
	if formToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(formToken), []byte(token)) == 1
}

func (s *Session) csrfState() *sessionCSRFState {
	sessionCSRFInitMu.Lock()
	defer sessionCSRFInitMu.Unlock()

	if s.csrf == nil {
		s.csrf = &sessionCSRFState{}
	}
	return s.csrf
}
