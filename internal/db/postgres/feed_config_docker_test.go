//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestFeedConfigWithAuditRejectsStaleSaveRevision(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "original-secret",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(original) error = %v", err)
	}
	loaded, err := store.GetFeedConfig(ctx, "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig(original) error = %v", err)
	}
	if loaded == nil || loaded.UpdatedAt.IsZero() {
		t.Fatalf("GetFeedConfig(original) = %+v, want revision", loaded)
	}

	time.Sleep(10 * time.Millisecond)
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{
		FeedName: "socket",
		Enabled:  false,
		Mode:     "external",
		APIKey:   "newer-secret",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(concurrent) error = %v", err)
	}

	loaded.Enabled = true
	loaded.Mode = "self"
	loaded.APIKey = "stale-secret"
	err = store.UpsertFeedConfigWithAudit(ctx,
		loaded,
		&db.AdminAuditEntry{Action: "feed_config_save", Details: json.RawMessage(`{"feed":"socket"}`), IP: "127.0.0.1"},
	)
	if !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertFeedConfigWithAudit(stale) error = %v, want ErrConflict", err)
	}

	current, err := store.GetFeedConfig(ctx, "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig(after stale) error = %v", err)
	}
	if current == nil || current.Enabled || current.Mode != "external" || current.APIKey != "newer-secret" {
		t.Fatalf("GetFeedConfig(after stale) = %+v, want newer config preserved", current)
	}
	audit, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after stale save = %+v, want none", audit)
	}
}

func TestDeleteFeedConfigWithAuditRejectsStaleRevision(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "original-secret",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(original) error = %v", err)
	}
	loaded, err := store.GetFeedConfig(ctx, "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig(original) error = %v", err)
	}
	if loaded == nil || loaded.UpdatedAt.IsZero() {
		t.Fatalf("GetFeedConfig(original) = %+v, want revision", loaded)
	}

	time.Sleep(10 * time.Millisecond)
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{
		FeedName: "socket",
		Enabled:  false,
		Mode:     "external",
		APIKey:   "newer-secret",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(concurrent) error = %v", err)
	}

	err = store.DeleteFeedConfigWithAudit(ctx,
		"socket",
		&loaded.UpdatedAt,
		&db.AdminAuditEntry{Action: "feed_config_reset", Details: json.RawMessage(`{"feed":"socket"}`), IP: "127.0.0.1"},
	)
	if !errors.Is(err, db.ErrConflict) {
		t.Fatalf("DeleteFeedConfigWithAudit(stale) error = %v, want ErrConflict", err)
	}

	current, err := store.GetFeedConfig(ctx, "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig(after stale delete) error = %v", err)
	}
	if current == nil || current.Enabled || current.Mode != "external" || current.APIKey != "newer-secret" {
		t.Fatalf("GetFeedConfig(after stale delete) = %+v, want newer config preserved", current)
	}
	audit, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after stale delete = %+v, want none", audit)
	}
}
