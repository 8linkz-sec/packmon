package config

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestF091RuntimeSettingsDefaultsAndConfigFallbackBoundaries(t *testing.T) {
	t.Parallel()

	direct := NewRuntimeSettings("HIGH", 120, 30)
	if got := direct.Retention(); got.ScanLog != 30*24*time.Hour || got.AdminAuditLog != 30*24*time.Hour {
		t.Fatalf("NewRuntimeSettings retention = %+v, want 30d/30d defaults", got)
	}

	fallback := NewRuntimeSettingsFromConfig(&Config{
		Server: ServerConfig{
			BlockThreshold:     "",
			RateLimitPerMinute: 0,
			RateLimitBurst:     -1,
		},
		Retention: RetentionConfig{
			ScanLog:       -time.Hour,
			AdminAuditLog: -time.Hour,
		},
	})
	if got := fallback.BlockThreshold(); got != "CRITICAL" {
		t.Fatalf("fallback BlockThreshold() = %q, want CRITICAL", got)
	}
	if perMinute, burst := fallback.RateLimit(); perMinute != 60 || burst != 60 {
		t.Fatalf("fallback RateLimit() = %d/%d, want 60/60", perMinute, burst)
	}
	if got := fallback.Retention(); got.ScanLog != 30*24*time.Hour || got.AdminAuditLog != 30*24*time.Hour {
		t.Fatalf("negative configured retention = %+v, want preserved 30d defaults", got)
	}

	disabled := NewRuntimeSettingsFromConfig(&Config{})
	if got := disabled.Retention(); got.ScanLog != 0 || got.AdminAuditLog != 0 {
		t.Fatalf("zero configured retention = %+v, want both disabled", got)
	}
}

func TestF091RuntimeSettingsSingleFieldUpdatesPreserveOtherValues(t *testing.T) {
	t.Parallel()

	runtime := NewRuntimeSettings("CRITICAL", 60, 10)
	runtime.Update("HIGH", 0, 0)
	if threshold := runtime.BlockThreshold(); threshold != "HIGH" {
		t.Fatalf("threshold-only update = %q, want HIGH", threshold)
	}
	if perMinute, burst := runtime.RateLimit(); perMinute != 60 || burst != 10 {
		t.Fatalf("threshold-only rate = %d/%d, want 60/10", perMinute, burst)
	}

	runtime.Update("", 120, 0)
	if threshold := runtime.BlockThreshold(); threshold != "HIGH" {
		t.Fatalf("per-minute update changed threshold to %q", threshold)
	}
	if perMinute, burst := runtime.RateLimit(); perMinute != 120 || burst != 10 {
		t.Fatalf("per-minute-only rate = %d/%d, want 120/10", perMinute, burst)
	}

	runtime.Update("", 0, 30)
	if perMinute, burst := runtime.RateLimit(); perMinute != 120 || burst != 30 {
		t.Fatalf("burst-only rate = %d/%d, want 120/30", perMinute, burst)
	}

	runtime.UpdateRetention(7*24*time.Hour, 14*24*time.Hour)
	runtime.UpdateRetention(0, -time.Hour)
	if got := runtime.Retention(); got.ScanLog != 0 || got.AdminAuditLog != 14*24*time.Hour {
		t.Fatalf("scan-only retention update = %+v, want 0/14d", got)
	}
	runtime.UpdateRetention(-time.Hour, 21*24*time.Hour)
	if got := runtime.Retention(); got.ScanLog != 0 || got.AdminAuditLog != 21*24*time.Hour {
		t.Fatalf("admin-only retention update = %+v, want 0/21d", got)
	}
}

func TestF091RuntimeSettingsConcurrentReadersObserveCompletePairs(t *testing.T) {
	t.Run("rate limits", func(t *testing.T) {
		runtime := NewRuntimeSettings("CRITICAL", 60, 10)
		start := make(chan struct{})
		errs := make(chan error, 1)
		report := func(err error) {
			select {
			case errs <- err:
			default:
			}
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 4000; i++ {
				if i%2 == 0 {
					runtime.Update("", 60, 10)
				} else {
					runtime.Update("", 120, 30)
				}
			}
		}()
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 4000 {
					perMinute, burst := runtime.RateLimit()
					if (perMinute != 60 || burst != 10) && (perMinute != 120 || burst != 30) {
						report(fmt.Errorf("observed mixed rate pair %d/%d", perMinute, burst))
						return
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		select {
		case err := <-errs:
			t.Fatal(err)
		default:
		}
	})

	t.Run("retention", func(t *testing.T) {
		runtime := NewRuntimeSettings("CRITICAL", 60, 10)
		runtime.UpdateRetention(24*time.Hour, 48*time.Hour)
		start := make(chan struct{})
		errs := make(chan error, 1)
		report := func(err error) {
			select {
			case errs <- err:
			default:
			}
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 4000; i++ {
				if i%2 == 0 {
					runtime.UpdateRetention(24*time.Hour, 48*time.Hour)
				} else {
					runtime.UpdateRetention(72*time.Hour, 96*time.Hour)
				}
			}
		}()
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 4000 {
					got := runtime.Retention()
					isA := got.ScanLog == 24*time.Hour && got.AdminAuditLog == 48*time.Hour
					isB := got.ScanLog == 72*time.Hour && got.AdminAuditLog == 96*time.Hour
					if !isA && !isB {
						report(fmt.Errorf("observed mixed retention pair %+v", got))
						return
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		select {
		case err := <-errs:
			t.Fatal(err)
		default:
		}
	})
}

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
