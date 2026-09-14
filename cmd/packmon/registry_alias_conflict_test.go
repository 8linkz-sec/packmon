package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeDockerRegistryMirrorMapRejectsCanonicalAliasCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mirrors   map[string]string
		wantError string
	}{
		{
			name: "Docker Hub aliases",
			mirrors: map[string]string{
				"index.docker.io": "https://mirror.invalid/index",
				"docker.io":       "https://mirror.invalid/docker",
			},
			wantError: `mirrors defines colliding Docker registry mirror aliases "docker.io" and "index.docker.io" (both normalize to "registry-1.docker.io")`,
		},
		{
			name: "Docker Hub port alias",
			mirrors: map[string]string{
				"registry-1.docker.io:443": "https://mirror.invalid/registry",
				"docker.io":                "https://mirror.invalid/docker",
			},
			wantError: `mirrors defines colliding Docker registry mirror aliases "docker.io" and "registry-1.docker.io:443" (both normalize to "registry-1.docker.io")`,
		},
		{
			name: "case and trailing dot",
			mirrors: map[string]string{
				"GHCR.IO":  "https://mirror.invalid/upper",
				"ghcr.io.": "https://mirror.invalid/dot",
			},
			wantError: `mirrors defines colliding Docker registry mirror aliases "GHCR.IO" and "ghcr.io." (both normalize to "ghcr.io")`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 0; attempt < 20; attempt++ {
				_, err := normalizeDockerRegistryMirrorMap("mirrors", tc.mirrors)
				if err == nil {
					t.Fatal("normalizeDockerRegistryMirrorMap() error = nil, want collision rejection")
				}
				if got := err.Error(); got != tc.wantError {
					t.Fatalf("attempt %d error = %q, want %q", attempt, got, tc.wantError)
				}
			}
		})
	}
}

func TestNormalizeDockerRegistryMirrorMapAcceptsDistinctCanonicalHosts(t *testing.T) {
	t.Parallel()

	got, err := normalizeDockerRegistryMirrorMap("mirrors", map[string]string{
		"docker.io": "https://mirror.invalid/docker/",
		"ghcr.io":   "https://mirror.invalid/ghcr/",
	})
	if err != nil {
		t.Fatalf("normalizeDockerRegistryMirrorMap() error = %v", err)
	}
	if len(got) != 2 || got["registry-1.docker.io"] != "https://mirror.invalid/docker" || got["ghcr.io"] != "https://mirror.invalid/ghcr" {
		t.Fatalf("normalized mirrors = %#v", got)
	}
}

func TestDockerRegistryMirrorAliasConflictYAMLStopsBeforeRequest(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })
	var requests atomic.Int32
	registryClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("configuration validation must stop before a registry request")
	})}

	path := filepath.Join(t.TempDir(), "packmon.yaml")
	data := []byte("registries:\n  docker_registry_mirrors:\n    docker.io: https://mirror.invalid/docker\n    index.docker.io: https://mirror.invalid/index\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, _, err := loadCLIConfig(path)
	want := `registries.docker_registry_mirrors defines colliding Docker registry mirror aliases "docker.io" and "index.docker.io" (both normalize to "registry-1.docker.io")`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("loadCLIConfig() error = %v, want %q", err, want)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("YAML alias conflict sent %d registry request(s), want 0", got)
	}
}

func TestDockerRegistryMirrorAliasConflictEnvironmentStopsBeforeRequest(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "normalized aliases",
			raw:  "index.docker.io=https://mirror.invalid/index,docker.io=https://mirror.invalid/docker",
			want: `PACKMON_DOCKER_REGISTRY_MIRRORS defines colliding Docker registry mirror aliases "docker.io" and "index.docker.io" (both normalize to "registry-1.docker.io")`,
		},
		{
			name: "repeated source key",
			raw:  "docker.io=https://mirror.invalid/first,docker.io=https://mirror.invalid/second",
			want: `PACKMON_DOCKER_REGISTRY_MIRRORS defines colliding Docker registry mirror aliases "docker.io" and "docker.io" (both normalize to "registry-1.docker.io")`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateLatestRegistryEnvironment(t)
			t.Setenv("PACKMON_DOCKER_REGISTRY_MIRRORS", tc.raw)

			originalClient := registryClient
			t.Cleanup(func() { registryClient = originalClient })
			var requests atomic.Int32
			registryClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("configuration validation must stop before a registry request")
			})}

			err := applyLatestRegistryEnvSettings(&scanSettings{})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("applyLatestRegistryEnvSettings() error = %v, want %q", err, tc.want)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("environment alias conflict sent %d registry request(s), want 0", got)
			}
		})
	}
}
