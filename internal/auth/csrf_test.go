package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCSRFTokenGeneratesNonEmptyToken(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "test-session"}
	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("CSRFToken returned empty token")
	}
	// Token should be 64 hex characters (32 bytes).
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64", len(token))
	}
}

func TestCSRFTokenStoresTokenInSession(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "test-session"}

	token1, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken(1) returned error: %v", err)
	}

	// Calling CSRFToken again returns the same stored token.
	token2, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken(2) returned error: %v", err)
	}

	if token1 != token2 {
		t.Fatalf("CSRFToken returned different tokens: %q vs %q", token1, token2)
	}
}

func TestCSRFTokenDiffersBetweenSessions(t *testing.T) {
	t.Parallel()

	sess1 := &Session{ID: "session-1"}
	sess2 := &Session{ID: "session-2"}

	token1, err := CSRFToken(sess1)
	if err != nil {
		t.Fatalf("CSRFToken(sess1) returned error: %v", err)
	}

	token2, err := CSRFToken(sess2)
	if err != nil {
		t.Fatalf("CSRFToken(sess2) returned error: %v", err)
	}

	if token1 == token2 {
		t.Fatal("two different sessions generated the same CSRF token")
	}
}

func TestCSRFTokenConcurrentAccessIsRaceFree(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "test-session"}

	var wg sync.WaitGroup
	tokens := make(chan string, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := CSRFToken(sess)
			if err != nil {
				t.Errorf("CSRFToken returned error: %v", err)
				return
			}

			form := url.Values{}
			form.Set(CSRFFieldName, token)
			req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if !ValidateCSRF(req, sess) {
				t.Errorf("ValidateCSRF returned false for generated token")
			}
			tokens <- token
		}()
	}
	wg.Wait()
	close(tokens)

	var first string
	for token := range tokens {
		if first == "" {
			first = token
			continue
		}
		if token != first {
			t.Fatalf("CSRFToken returned different concurrent tokens: %q vs %q", first, token)
		}
	}
}

func TestCSRFTokenWithNilSessionReturnsError(t *testing.T) {
	t.Parallel()

	_, err := CSRFToken(nil)
	if err == nil {
		t.Fatal("CSRFToken(nil) did not return error")
	}
}

func TestValidateCSRFSucceedsWithCorrectToken(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}

	// Build a request with the CSRF token in form data.
	form := url.Values{}
	form.Set(CSRFFieldName, token)
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !ValidateCSRF(req, sess) {
		t.Fatal("ValidateCSRF returned false for correct token")
	}
}

func TestValidateCSRFFailsWithWrongToken(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	// Generate the real token so the session has one stored.
	_, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}

	// Submit a different token.
	form := url.Values{}
	form.Set(CSRFFieldName, "wrong-token-value")
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if ValidateCSRF(req, sess) {
		t.Fatal("ValidateCSRF returned true for wrong token")
	}
}

func TestValidateCSRFFailsWithEmptyToken(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	// Generate the real token.
	_, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}

	// Submit empty token.
	form := url.Values{}
	form.Set(CSRFFieldName, "")
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if ValidateCSRF(req, sess) {
		t.Fatal("ValidateCSRF returned true for empty token")
	}
}

func TestValidateCSRFFailsWithMissingFormField(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	_, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}

	// Request without any form data.
	req := httptest.NewRequest(http.MethodPost, "/admin/action", nil)

	if ValidateCSRF(req, sess) {
		t.Fatal("ValidateCSRF returned true when form field is missing")
	}
}

func TestValidateCSRFFailsWithNilSession(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set(CSRFFieldName, "some-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if ValidateCSRF(req, nil) {
		t.Fatal("ValidateCSRF returned true for nil session")
	}
}

func TestValidateCSRFFailsWithSessionWithoutToken(t *testing.T) {
	t.Parallel()

	// Session exists but CSRFToken() was never called, so csrfToken is "".
	sess := &Session{ID: "test-session"}

	form := url.Values{}
	form.Set(CSRFFieldName, "some-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if ValidateCSRF(req, sess) {
		t.Fatal("ValidateCSRF returned true for session without stored CSRF token")
	}
}
