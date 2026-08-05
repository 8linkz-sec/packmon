package auth

import (
	"context"
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
