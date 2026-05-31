package auth

import (
	"context"
	"testing"
	"time"
)

func TestSessionFlashIsReadOnce(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(context.Background(), time.Hour, false)
	sess, _ := createSession(t, sm)

	sm.SetFlash(sess.ID, "newkey", "plaintext-key")
	if got := sm.GetFlash(sess.ID, "newkey"); got != "plaintext-key" {
		t.Fatalf("GetFlash(first) = %q, want plaintext-key", got)
	}
	if got := sm.GetFlash(sess.ID, "newkey"); got != "" {
		t.Fatalf("GetFlash(second) = %q, want empty after one-time read", got)
	}
}

func TestSessionFlashMissingSessionAndKeyAreNoops(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(context.Background(), time.Hour, false)
	sm.SetFlash("missing-session", "key", "value")
	if got := sm.GetFlash("missing-session", "key"); got != "" {
		t.Fatalf("GetFlash(missing session) = %q, want empty", got)
	}

	sess, _ := createSession(t, sm)
	if got := sm.GetFlash(sess.ID, "missing-key"); got != "" {
		t.Fatalf("GetFlash(missing key) = %q, want empty", got)
	}
}
