package auth

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSessionFlashIsReadOnce(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	sess, _ := createSession(t, sm)

	sm.SetFlash(sess.ID, "newkey", "plaintext-key")
	if got := sm.GetFlash(sess.ID, "newkey"); got != "plaintext-key" {
		t.Fatalf("GetFlash(first) = %q, want plaintext-key", got)
	}
	if got := sm.GetFlash(sess.ID, "newkey"); got != "" {
		t.Fatalf("GetFlash(second) = %q, want empty after one-time read", got)
	}
}

func TestSessionFlashCanBePeekedWithoutConsuming(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	sess, _ := createSession(t, sm)

	sm.SetFlash(sess.ID, "newkey", "plaintext-key")
	if got := sm.PeekFlash(sess.ID, "newkey"); got != "plaintext-key" {
		t.Fatalf("PeekFlash() = %q, want plaintext-key", got)
	}
	if got := sm.GetFlash(sess.ID, "newkey"); got != "plaintext-key" {
		t.Fatalf("GetFlash(after peek) = %q, want plaintext-key", got)
	}
}

func TestSessionFlashMissingSessionAndKeyAreNoops(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	sm.SetFlash("missing-session", "key", "value")
	if got := sm.GetFlash("missing-session", "key"); got != "" {
		t.Fatalf("GetFlash(missing session) = %q, want empty", got)
	}
	if got := sm.PeekFlash("missing-session", "key"); got != "" {
		t.Fatalf("PeekFlash(missing session) = %q, want empty", got)
	}

	sess, _ := createSession(t, sm)
	if got := sm.GetFlash(sess.ID, "missing-key"); got != "" {
		t.Fatalf("GetFlash(missing key) = %q, want empty", got)
	}
	if got := sm.PeekFlash(sess.ID, "missing-key"); got != "" {
		t.Fatalf("PeekFlash(missing key) = %q, want empty", got)
	}
}

func TestSessionManagerCoordinatesConcurrentLookupDeleteAndFlashOperations(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	sess, _ := createSession(t, sm)
	start := make(chan struct{})
	ready := make(chan struct{}, 3)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		for range 200 {
			_ = sm.Get(requestWithSession(sess.ID))
		}
	}()
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		for range 200 {
			sm.SetFlash(sess.ID, "notice", "value")
			_ = sm.PeekFlash(sess.ID, "notice")
			_ = sm.GetFlash(sess.ID, "notice")
		}
	}()
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		sm.Delete(httptest.NewRecorder(), requestWithSession(sess.ID))
	}()

	for range 3 {
		<-ready
	}
	close(start)
	wg.Wait()

	if got := sm.Get(requestWithSession(sess.ID)); got != nil {
		t.Fatalf("Get() after coordinated delete = %+v, want nil", got)
	}
	if got := sm.GetFlash(sess.ID, "notice"); got != "" {
		t.Fatalf("GetFlash() after coordinated delete = %q, want empty", got)
	}
}
