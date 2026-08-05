package config

import (
	"testing"
	"time"
)

func TestNewRuntimeSettingsFromConfigUsesDefaultsForNilConfig(t *testing.T) {
	t.Parallel()

	runtime := NewRuntimeSettingsFromConfig(nil)
	if runtime == nil {
		t.Fatal("NewRuntimeSettingsFromConfig(nil) = nil, want defaults")
	}
	if got := runtime.BlockThreshold(); got != "CRITICAL" {
		t.Fatalf("BlockThreshold() = %q, want CRITICAL default", got)
	}
	perMinute, burst := runtime.RateLimit()
	if perMinute != 60 || burst != 60 {
		t.Fatalf("RateLimit() = %d/%d, want 60/60 defaults", perMinute, burst)
	}
	retention := runtime.Retention()
	if retention.ScanLog != 0 || retention.AdminAuditLog != 0 {
		t.Fatalf("Retention() = %+v, want zero retention from nil config", retention)
	}
}

func TestNewRuntimeSettingsFromConfigSeedsFromConfigValues(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	cfg.Server.BlockThreshold = "HIGH"
	cfg.Server.RateLimitPerMinute = 120
	cfg.Server.RateLimitBurst = 30
	cfg.Retention.ScanLog = 48 * time.Hour
	cfg.Retention.AdminAuditLog = 72 * time.Hour

	runtime := NewRuntimeSettingsFromConfig(cfg)
	if got := runtime.BlockThreshold(); got != "HIGH" {
		t.Fatalf("BlockThreshold() = %q, want HIGH from config", got)
	}
	perMinute, burst := runtime.RateLimit()
	if perMinute != 120 || burst != 30 {
		t.Fatalf("RateLimit() = %d/%d, want 120/30 from config", perMinute, burst)
	}
	retention := runtime.Retention()
	if retention.ScanLog != 48*time.Hour || retention.AdminAuditLog != 72*time.Hour {
		t.Fatalf("Retention() = %+v, want config retention values", retention)
	}
}

func TestUpdateRetentionAppliesZeroAndIgnoresNegative(t *testing.T) {
	t.Parallel()

	runtime := NewRuntimeSettings("HIGH", 10, 10)
	runtime.UpdateRetention(24*time.Hour, 48*time.Hour)
	if retention := runtime.Retention(); retention.ScanLog != 24*time.Hour || retention.AdminAuditLog != 48*time.Hour {
		t.Fatalf("Retention() after update = %+v, want 24h/48h", retention)
	}

	runtime.UpdateRetention(0, -time.Hour)
	retention := runtime.Retention()
	if retention.ScanLog != 0 {
		t.Fatalf("Retention().ScanLog = %v, want 0 (pruning disabled)", retention.ScanLog)
	}
	if retention.AdminAuditLog != 48*time.Hour {
		t.Fatalf("Retention().AdminAuditLog = %v, want negative update ignored", retention.AdminAuditLog)
	}
}
