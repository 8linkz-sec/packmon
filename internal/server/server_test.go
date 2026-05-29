package server

import (
	"testing"

	"github.com/8linkz/packmon/internal/config"
)

func TestRateLimitConfigUsesServerSettings(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			RateLimitPerMinute: 120,
			RateLimitBurst:     25,
		},
	}

	got := rateLimitConfig(cfg)

	if got.Rate != 2 {
		t.Fatalf("Rate = %v, want 2", got.Rate)
	}
	if got.Burst != 25 {
		t.Fatalf("Burst = %d, want 25", got.Burst)
	}
}

func TestRateLimitConfigFallsBackToDefaults(t *testing.T) {
	got := rateLimitConfig(&config.Config{})

	if got.Rate != 1 {
		t.Fatalf("Rate = %v, want 1", got.Rate)
	}
	if got.Burst != 60 {
		t.Fatalf("Burst = %d, want 60", got.Burst)
	}
}
