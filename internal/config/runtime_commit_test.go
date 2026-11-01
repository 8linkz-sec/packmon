package config

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestCommitAndPublishPublishesPolicyAndRetentionAfterCommit(t *testing.T) {
	t.Parallel()

	runtime := NewRuntimeSettings("CRITICAL", 60, 60)
	values := SystemSettingsValues{
		BlockThreshold:      "HIGH",
		RateLimitPerMinute:  120,
		RateLimitBurst:      30,
		ScanLogRetention:    0,
		AdminAuditRetention: 48 * time.Hour,
	}
	committed := false
	err := runtime.CommitAndPublish(context.Background(), values, func() error {
		if runtime.BlockThreshold() != "CRITICAL" {
			t.Error("values were published before the commit ran")
		}
		committed = true
		return nil
	})
	if err != nil || !committed {
		t.Fatalf("CommitAndPublish() = %v, committed=%v; want nil, true", err, committed)
	}
	perMinute, burst := runtime.RateLimit()
	retention := runtime.Retention()
	if runtime.BlockThreshold() != "HIGH" || perMinute != 120 || burst != 30 || retention.ScanLog != 0 || retention.AdminAuditLog != 48*time.Hour {
		t.Fatalf("runtime = %s %d/%d %+v, want all published values", runtime.BlockThreshold(), perMinute, burst, retention)
	}
}

func TestCommitAndPublishDoesNotPublishFailedCommit(t *testing.T) {
	t.Parallel()

	runtime := NewRuntimeSettings("CRITICAL", 60, 60)
	wantErr := errors.New("commit failed")
	err := runtime.CommitAndPublish(context.Background(), SystemSettingsValues{BlockThreshold: "LOW", RateLimitPerMinute: 1, RateLimitBurst: 1}, func() error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("CommitAndPublish() error = %v, want %v", err, wantErr)
	}
	if perMinute, burst := runtime.RateLimit(); runtime.BlockThreshold() != "CRITICAL" || perMinute != 60 || burst != 60 {
		t.Fatalf("runtime after failed commit = %s %d/%d, want unchanged", runtime.BlockThreshold(), perMinute, burst)
	}

	// The slot is released after a failed commit.
	if err := runtime.CommitAndPublish(context.Background(), SystemSettingsValues{BlockThreshold: "LOW"}, func() error { return nil }); err != nil {
		t.Fatalf("CommitAndPublish(after failure) error = %v", err)
	}
}

func TestCommitAndPublishWaiterGivesUpWithoutCommittingWhenContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runtime := NewRuntimeSettings("CRITICAL", 60, 60)
		release := make(chan struct{})
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- runtime.CommitAndPublish(context.Background(), SystemSettingsValues{BlockThreshold: "HIGH"}, func() error {
				<-release
				return nil
			})
		}()
		synctest.Wait()

		ctx, cancel := context.WithCancel(context.Background())
		secondDone := make(chan error, 1)
		secondCommitted := false
		go func() {
			secondDone <- runtime.CommitAndPublish(ctx, SystemSettingsValues{BlockThreshold: "LOW"}, func() error {
				secondCommitted = true
				return nil
			})
		}()
		synctest.Wait()
		cancel()
		if err := <-secondDone; !errors.Is(err, context.Canceled) || secondCommitted {
			t.Fatalf("waiting CommitAndPublish() = %v, committed=%v; want context.Canceled without commit", err, secondCommitted)
		}

		close(release)
		if err := <-firstDone; err != nil {
			t.Fatalf("first CommitAndPublish() error = %v", err)
		}
		if got := runtime.BlockThreshold(); got != "HIGH" {
			t.Fatalf("BlockThreshold() = %q, want the first save's HIGH", got)
		}
	})
}
