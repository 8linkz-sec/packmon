package server

import (
	"testing"

	"github.com/8linkz/packmon/internal/config"
)

func TestSessionCookieSecureFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{
			name: "production defaults to secure cookies",
			cfg: &config.Config{
				Server: config.ServerConfig{Mode: config.ModeProduction},
			},
			want: true,
		},
		{
			name: "development uses insecure cookies",
			cfg: &config.Config{
				Server: config.ServerConfig{Mode: config.ModeDevelopment},
			},
			want: false,
		},
		{
			name: "local insecure HTTP override uses insecure cookies",
			cfg: &config.Config{
				Server: config.ServerConfig{
					Mode:                   config.ModeProduction,
					PublicHost:             "localhost:8080",
					AllowInsecureLocalHTTP: true,
				},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sessionCookieSecure(tc.cfg)
			if got != tc.want {
				t.Fatalf("sessionCookieSecure() = %t, want %t", got, tc.want)
			}
		})
	}
}
