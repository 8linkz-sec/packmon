package auth

import (
	"bytes"
	"encoding/hex"
	"mime/multipart"
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
	decoded, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded token length = %d bytes, want 32", len(decoded))
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

func TestValidateCSRFRejectsEqualLengthAndCrossSessionTokens(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "session-1"}
	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken(session-1) returned error: %v", err)
	}
	other := &Session{ID: "session-2"}
	otherToken, err := CSRFToken(other)
	if err != nil {
		t.Fatalf("CSRFToken(session-2) returned error: %v", err)
	}

	equalLengthMismatch := token[:len(token)-1] + "0"
	if equalLengthMismatch == token {
		equalLengthMismatch = token[:len(token)-1] + "1"
	}
	for label, submitted := range map[string]string{
		"equal-length mismatch": equalLengthMismatch,
		"cross-session token":   otherToken,
	} {
		form := url.Values{CSRFFieldName: {submitted}}
		req := httptest.NewRequest(http.MethodPost, "/admin/action", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if ValidateCSRF(req, sess) {
			t.Fatalf("ValidateCSRF accepted %s", label)
		}
	}
}

func TestValidateCSRFRequestSourcePrecedence(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "source-precedence"}
	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}
	wrong := token[:len(token)-1] + "0"
	if wrong == token {
		wrong = token[:len(token)-1] + "1"
	}

	tests := []struct {
		name        string
		encoding    string
		queryValues []string
		bodyValues  []string
		want        bool
	}{
		{name: "query only", queryValues: []string{token}, want: true},
		{name: "multipart body only", encoding: "multipart", bodyValues: []string{token}, want: true},
		{name: "urlencoded body precedes query", encoding: "urlencoded", queryValues: []string{wrong}, bodyValues: []string{token}, want: true},
		{name: "urlencoded invalid body masks query", encoding: "urlencoded", queryValues: []string{token}, bodyValues: []string{wrong}},
		{name: "urlencoded first duplicate wins", encoding: "urlencoded", bodyValues: []string{token, wrong}, want: true},
		{name: "urlencoded later duplicate does not win", encoding: "urlencoded", bodyValues: []string{wrong, token}},
		{name: "multipart query precedes body", encoding: "multipart", queryValues: []string{token}, bodyValues: []string{wrong}, want: true},
		{name: "multipart body does not mask query", encoding: "multipart", queryValues: []string{wrong}, bodyValues: []string{token}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{}
			for _, value := range tt.queryValues {
				query.Add(CSRFFieldName, value)
			}
			target := "/admin/action"
			if encoded := query.Encode(); encoded != "" {
				target += "?" + encoded
			}

			var req *http.Request
			switch tt.encoding {
			case "":
				req = httptest.NewRequest(http.MethodPost, target, nil)
			case "urlencoded":
				body := url.Values{}
				for _, value := range tt.bodyValues {
					body.Add(CSRFFieldName, value)
				}
				req = httptest.NewRequest(http.MethodPost, target, strings.NewReader(body.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			case "multipart":
				var body bytes.Buffer
				writer := multipart.NewWriter(&body)
				for _, value := range tt.bodyValues {
					if err := writer.WriteField(CSRFFieldName, value); err != nil {
						t.Fatalf("WriteField() error = %v", err)
					}
				}
				if err := writer.Close(); err != nil {
					t.Fatalf("multipart writer Close() error = %v", err)
				}
				req = httptest.NewRequest(http.MethodPost, target, &body)
				req.Header.Set("Content-Type", writer.FormDataContentType())
			default:
				t.Fatalf("unknown test encoding %q", tt.encoding)
			}

			if got := ValidateCSRF(req, sess); got != tt.want {
				t.Fatalf("ValidateCSRF() = %t, want %t", got, tt.want)
			}
		})
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
