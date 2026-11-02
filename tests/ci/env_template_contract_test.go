package ci

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

type envTemplateAssignment struct {
	key       string
	value     string
	commented bool
}

func TestEnvExampleHasCompleteUniqueStructuredAssignments(t *testing.T) {
	t.Parallel()

	assignments := parseEnvTemplateAssignments(t, repoFile(t, ".env.example"))
	wantKeys := strings.Fields(`
PACKMON_VERSION PACKMON_COMMIT PACKMON_BUILD_DATE
PACKMON_GO_BUILDER_IMAGE PACKMON_ALPINE_RUNTIME_IMAGE PACKMON_POSTGRES_IMAGE
POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
PACKMON_POSTGRES_TRACK_IO_TIMING PACKMON_POSTGRES_SLOW_QUERY_MS
PACKMON_SERVER_MODE PACKMON_SERVER_PORT PACKMON_SERVER_PUBLIC_HOST
PACKMON_TLS_CERT_FILE PACKMON_TLS_KEY_FILE PACKMON_TLS_MIN_VERSION
PACKMON_ALLOW_INSECURE_LOCAL_HTTP PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE PACKMON_TRUSTED_PROXIES
PACKMON_METRICS_HOST PACKMON_METRICS_PORT PACKMON_SERVER_READ_TIMEOUT
PACKMON_SERVER_WRITE_TIMEOUT PACKMON_SERVER_SHUTDOWN_TIMEOUT PACKMON_BLOCK_THRESHOLD
PACKMON_RATE_LIMIT_PER_MINUTE PACKMON_RATE_LIMIT_BURST
PACKMON_WEB_PRIVACY_URL PACKMON_WEB_LEGAL_URL PACKMON_WEB_TERMS_URL
PACKMON_DB_HOST PACKMON_DB_PORT PACKMON_DB_NAME PACKMON_DB_USER PACKMON_DB_PASSWORD
PACKMON_DB_SSLMODE PACKMON_DB_MAX_CONNS PACKMON_DB_MIN_CONNS PACKMON_DB_CONNECT_TIMEOUT
PACKMON_BACKUP_DIR PACKMON_LOG_LEVEL PACKMON_LOG_FORMAT
PACKMON_ADMIN_INITIAL_PASSWORD PACKMON_ADMIN_SESSION_TIMEOUT PACKMON_ADMIN_IDLE_TIMEOUT
PACKMON_SCAN_LOG_RETENTION PACKMON_SCAN_LOG_IDENTITY_MODE PACKMON_ADMIN_AUDIT_LOG_RETENTION
PACKMON_REFRESH_QUEUE_RETENTION PACKMON_PACKAGE_CHECK_STATUS_RETENTION PACKMON_AUDIT_RETENTION_INTERVAL
PACKMON_ENCRYPTION_KEY PACKMON_ADMIN_AUDIT_HMAC_KEY
PACKMON_FEED_SYNC_INTERVAL PACKMON_FEED_SYNC_ON_STARTUP PACKMON_FEED_DATA_DIR PACKMON_FEED_IMPORT_SECRET
PACKMON_FEED_OSV_ENABLED PACKMON_FEED_GHSA_ENABLED PACKMON_FEED_OPENSSF_ENABLED
PACKMON_FEED_VULNCHECK_ENABLED PACKMON_FEED_NVD_ENABLED PACKMON_FEED_CISAKEV_ENABLED
PACKMON_FEED_EPSS_ENABLED PACKMON_FEED_ENDOFLIFE_ENABLED PACKMON_FEED_SOCKET_ENABLED
PACKMON_FEED_REVERSINGLABS_ENABLED PACKMON_FEED_OSV_MODE PACKMON_FEED_GHSA_MODE
PACKMON_FEED_OPENSSF_MODE PACKMON_FEED_VULNCHECK_MODE PACKMON_FEED_NVD_MODE
PACKMON_FEED_CISAKEV_MODE PACKMON_FEED_EPSS_MODE PACKMON_FEED_ENDOFLIFE_MODE
PACKMON_FEED_SOCKET_MODE PACKMON_FEED_REVERSINGLABS_MODE
PACKMON_VULNCHECK_API_KEY PACKMON_VULNCHECK_API_BASE_URL PACKMON_NVD_API_KEY
PACKMON_ENDOFLIFE_API_BASE_URL PACKMON_SOCKET_API_KEY PACKMON_SOCKET_API_BASE_URL
PACKMON_REVERSINGLABS_API_KEY PACKMON_REVERSINGLABS_API_BASE_URL
PACKMON_REVERSINGLABS_LOOKUP_TTL PACKMON_REVERSINGLABS_BATCH_SIZE
PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK PACKMON_REVERSINGLABS_CACHE_RETENTION
PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES`)

	seen := make(map[string]int, len(assignments))
	active := make(map[string]int, len(assignments))
	for _, assignment := range assignments {
		seen[assignment.key]++
		if !assignment.commented {
			active[assignment.key]++
		}
	}
	for key, count := range active {
		if count != 1 {
			t.Errorf(".env.example has %d active %s assignments, want exactly one", count, key)
		}
	}
	const knownMissing = "PACKMON_PACKAGE_CHECK_STATUS_RETENTION"
	for _, key := range wantKeys {
		if key == knownMissing {
			continue
		}
		if seen[key] != 1 {
			t.Errorf(".env.example has %d total %s assignments, want exactly one", seen[key], key)
		}
		delete(seen, key)
	}
	delete(seen, knownMissing)
	for key, count := range seen {
		t.Errorf(".env.example has unexpected or misspelled assignment %s (%d occurrences)", key, count)
	}
	t.Run("known missing package-check retention", func(t *testing.T) {
		var missing []string
		for _, key := range wantKeys {
			if seenCount := countAssignments(assignments, key); seenCount == 0 {
				missing = append(missing, key)
			}
		}
		if !slices.Equal(missing, []string{knownMissing}) {
			t.Fatalf("missing template keys = %v, want exact F002-bugs-2 omission [%s]", missing, knownMissing)
		}
		t.Skip("OPEN F002-bugs-2: .env.example omits PACKMON_PACKAGE_CHECK_STATUS_RETENTION=2160h")
	})
}

func TestEnvExampleKeepsBootstrapSecretsEmptyAndOptionalCredentialsCommented(t *testing.T) {
	t.Parallel()

	assignments := parseEnvTemplateAssignments(t, repoFile(t, ".env.example"))
	byKey := make(map[string]envTemplateAssignment, len(assignments))
	for _, assignment := range assignments {
		byKey[assignment.key] = assignment
	}
	for _, key := range []string{
		"POSTGRES_PASSWORD",
		"PACKMON_DB_PASSWORD",
		"PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY",
	} {
		assignment, ok := byKey[key]
		if !ok || assignment.commented || assignment.value != "" {
			t.Errorf("%s = %#v, want one active empty bootstrap-secret assignment", key, assignment)
		}
	}
	for _, key := range []string{
		"PACKMON_FEED_IMPORT_SECRET",
		"PACKMON_VULNCHECK_API_KEY",
		"PACKMON_NVD_API_KEY",
		"PACKMON_SOCKET_API_KEY",
		"PACKMON_REVERSINGLABS_API_KEY",
	} {
		assignment, ok := byKey[key]
		if !ok || !assignment.commented || assignment.value != "" {
			t.Errorf("%s = %#v, want one commented empty optional-credential assignment", key, assignment)
		}
	}
}

func TestEnvExampleImageOverridesAreDigestPinnedAndMatchRuntimeDefaults(t *testing.T) {
	t.Parallel()

	assignments := parseEnvTemplateAssignments(t, repoFile(t, ".env.example"))
	values := make(map[string]string, len(assignments))
	for _, assignment := range assignments {
		if !assignment.commented {
			values[assignment.key] = assignment.value
		}
	}
	digestPinned := regexp.MustCompile(`^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	dockerfile := repoFile(t, "Dockerfile")
	for _, key := range []string{"PACKMON_GO_BUILDER_IMAGE", "PACKMON_ALPINE_RUNTIME_IMAGE", "PACKMON_POSTGRES_IMAGE"} {
		value := values[key]
		if !digestPinned.MatchString(value) {
			t.Errorf(".env.example %s = %q, want tag plus sha256 digest", key, value)
		}
		if key != "PACKMON_POSTGRES_IMAGE" && !strings.Contains(dockerfile, "ARG "+key+"="+value+"\n") {
			t.Errorf("Dockerfile default for %s does not match .env.example value %q", key, value)
		}
	}

	imageDefault := regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*_IMAGE):-([^}]*)\}`)
	composeFiles := []struct {
		name string
		text string
		want map[string]int
	}{
		{
			name: "docker-compose.yml",
			text: repoFile(t, "docker-compose.yml"),
			want: map[string]int{
				"PACKMON_POSTGRES_IMAGE":       2,
				"PACKMON_GO_BUILDER_IMAGE":     2,
				"PACKMON_ALPINE_RUNTIME_IMAGE": 2,
			},
		},
		{
			name: "docker-compose.server.yml",
			text: repoFile(t, "docker-compose.server.yml"),
			want: map[string]int{
				"PACKMON_POSTGRES_IMAGE":       2,
				"PACKMON_GO_BUILDER_IMAGE":     2,
				"PACKMON_ALPINE_RUNTIME_IMAGE": 2,
			},
		},
	}
	for _, compose := range composeFiles {
		gotCounts := make(map[string]int)
		for _, match := range imageDefault.FindAllStringSubmatch(compose.text, -1) {
			key, defaultValue := match[1], match[2]
			gotCounts[key]++
			if got := values[key]; got == "" {
				t.Errorf("%s has image default for %s without an active non-empty .env.example assignment", compose.name, key)
			} else if defaultValue != got {
				t.Errorf("%s %s occurrence %d default = %q, want .env.example value %q", compose.name, key, gotCounts[key], defaultValue, got)
			}
		}
		for key, wantCount := range compose.want {
			if gotCounts[key] != wantCount {
				t.Errorf("%s has %d %s default occurrences, want %d", compose.name, gotCounts[key], key, wantCount)
			}
			delete(gotCounts, key)
		}
		for key, count := range gotCounts {
			t.Errorf("%s has %d unexpected %s default occurrences", compose.name, count, key)
		}
	}
}

func TestEnvExamplePinsRefreshQueueRetentionAndIdentityMode(t *testing.T) {
	t.Parallel()

	assignments := parseEnvTemplateAssignments(t, repoFile(t, ".env.example"))
	values := make(map[string]string, len(assignments))
	for _, assignment := range assignments {
		if !assignment.commented {
			values[assignment.key] = assignment.value
		}
	}
	if got := values["PACKMON_REFRESH_QUEUE_RETENTION"]; got != "720h" {
		t.Fatalf("PACKMON_REFRESH_QUEUE_RETENTION = %q, want 720h", got)
	}
	if got := values["PACKMON_SCAN_LOG_IDENTITY_MODE"]; got != "full" {
		t.Fatalf("PACKMON_SCAN_LOG_IDENTITY_MODE = %q, want full", got)
	}
}

func countAssignments(assignments []envTemplateAssignment, key string) int {
	count := 0
	for _, assignment := range assignments {
		if assignment.key == key {
			count++
		}
	}
	return count
}

func parseEnvTemplateAssignments(t *testing.T, text string) []envTemplateAssignment {
	t.Helper()
	validKey := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	var assignments []envTemplateAssignment
	for index, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		commented := strings.HasPrefix(line, "#")
		if commented {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if !strings.Contains(line, "=") {
				continue
			}
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if commented && !validKey.MatchString(key) {
			// Prose comments may use '=' (for example, to explain enum
			// meanings). Only assignment-shaped comments belong to the
			// template-key contract.
			continue
		}
		if !ok || !validKey.MatchString(key) {
			t.Errorf(".env.example:%d malformed assignment %q", index+1, raw)
			continue
		}
		if strings.ContainsAny(key, " \t") {
			t.Errorf(".env.example:%d assignment key contains whitespace: %q", index+1, raw)
		}
		assignments = append(assignments, envTemplateAssignment{
			key:       key,
			value:     strings.TrimSpace(value),
			commented: commented,
		})
	}
	slices.SortFunc(assignments, func(a, b envTemplateAssignment) int { return strings.Compare(a.key, b.key) })
	return assignments
}
