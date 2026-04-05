package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockPinger implements the Pinger interface for testing.
type mockPinger struct {
	err   error
	delay time.Duration
}

func (m *mockPinger) Ping(ctx context.Context) error {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.err
}

func TestLiveHandler_ReturnsOK(t *testing.T) {
	c := NewChecker(&mockPinger{})
	handler := c.LiveHandler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("LiveHandler status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("LiveHandler Content-Type = %q, want %q", ct, "application/json; charset=utf-8")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("LiveHandler body decode error: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("LiveHandler status field = %q, want %q", body["status"], "ok")
	}
}

func TestReadyHandler_DatabaseReachable(t *testing.T) {
	c := NewChecker(&mockPinger{})
	handler := c.ReadyHandler()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ReadyHandler status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("ReadyHandler body decode error: %v", err)
	}
	if body["status"] != "ready" {
		t.Fatalf("ReadyHandler status field = %q, want %q", body["status"], "ready")
	}
}

func TestReadyHandler_DatabaseUnreachable(t *testing.T) {
	c := NewChecker(&mockPinger{err: errors.New("connection refused")})
	handler := c.ReadyHandler()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ReadyHandler status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("ReadyHandler body decode error: %v", err)
	}
	if body["status"] != "unavailable" {
		t.Fatalf("ReadyHandler status field = %q, want %q", body["status"], "unavailable")
	}
	if body["reason"] != "database unreachable" {
		t.Fatalf("ReadyHandler reason = %q, want %q", body["reason"], "database unreachable")
	}
}

func TestReadyHandler_DatabaseTimeout(t *testing.T) {
	// The ReadyHandler uses a 3-second internal timeout. We simulate a
	// pinger that takes much longer than that. To keep the test fast we
	// also cancel the parent context after a short deadline.
	c := NewChecker(&mockPinger{delay: 10 * time.Second})
	handler := c.ReadyHandler()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ReadyHandler (timeout) status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("ReadyHandler body decode error: %v", err)
	}
	if body["status"] != "unavailable" {
		t.Fatalf("ReadyHandler status field = %q, want %q", body["status"], "unavailable")
	}
}
