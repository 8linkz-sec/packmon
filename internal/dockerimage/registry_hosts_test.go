package dockerimage

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNormalizeDockerHostCanonicalisesEveryForm covers the normalisation the
// allowlist checks depend on. Docker Hub answers to three names, and a host may
// arrive with a port, a trailing dot or in mixed case; each of those must map to
// the same canonical value or an allowlisted registry would be rejected.
func TestNormalizeDockerHostCanonicalisesEveryForm(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"docker.io", "index.docker.io", "DOCKER.IO", "  docker.io  ", "docker.io.",
		"docker.io:443", dockerHubRegistryHost,
	} {
		if got := normalizeDockerHost(raw); got != dockerHubRegistryHost {
			t.Errorf("normalizeDockerHost(%q) = %q, want %q", raw, got, dockerHubRegistryHost)
		}
	}

	for _, tc := range []struct{ raw, want string }{
		{raw: "GHCR.IO", want: "ghcr.io"},
		{raw: "ghcr.io:443", want: "ghcr.io"},
		{raw: "ghcr.io.", want: "ghcr.io"},
		{raw: "[::1]:5000", want: "::1"},
		{raw: "", want: ""},
	} {
		if got := normalizeDockerHost(tc.raw); got != tc.want {
			t.Errorf("normalizeDockerHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestIsAllowedDockerRegistryHostGuardsTheAllowlist is the security boundary for
// digest lookups: an image reference names its own registry, so only registries
// Packmon knows may be contacted.
func TestIsAllowedDockerRegistryHostGuardsTheAllowlist(t *testing.T) {
	t.Parallel()

	for host := range allowedDockerRegistryHosts {
		if !isAllowedDockerRegistryHost(host) {
			t.Errorf("allowlisted host %q was rejected", host)
		}
		// The same host must be accepted in its non-canonical spellings.
		if !isAllowedDockerRegistryHost(strings.ToUpper(host)) {
			t.Errorf("host %q was rejected in upper case", host)
		}
	}
	if !isAllowedDockerRegistryHost("docker.io") {
		t.Error("docker.io was rejected although it aliases Docker Hub")
	}

	for _, host := range []string{"", "evil.example", "ghcr.io.evil.example", "127.0.0.1", "localhost"} {
		if isAllowedDockerRegistryHost(host) {
			t.Errorf("host %q was accepted", host)
		}
	}
}

// TestIsAllowedDockerTokenRealmHostRestrictsWhereCredentialsGo is the stricter
// half. A registry's auth challenge names the realm to fetch a token from, and
// that value comes from the registry's own response -- so a compromised or
// misconfigured registry must not be able to redirect the token request to an
// arbitrary host.
func TestIsAllowedDockerTokenRealmHostRestrictsWhereCredentialsGo(t *testing.T) {
	t.Parallel()

	// A registry may always issue tokens for itself.
	for host := range allowedDockerRegistryHosts {
		if !isAllowedDockerTokenRealmHost(host, host) {
			t.Errorf("registry %q may not issue its own token", host)
		}
	}

	// The declared cross-host realms are permitted.
	for registry, realms := range allowedDockerTokenRealmHosts {
		for realm := range realms {
			if !isAllowedDockerTokenRealmHost(registry, realm) {
				t.Errorf("declared realm %q for registry %q was rejected", realm, registry)
			}
		}
		// Anything not declared is not.
		if isAllowedDockerTokenRealmHost(registry, "evil.example") {
			t.Errorf("registry %q accepted an undeclared token realm", registry)
		}
	}

	// A registry outside the allowlist gets no realm at all, not even its own.
	if isAllowedDockerTokenRealmHost("evil.example", "evil.example") {
		t.Error("a non-allowlisted registry was allowed to issue its own token")
	}
	if isAllowedDockerTokenRealmHost("", "") {
		t.Error("an empty registry/realm pair was accepted")
	}
}

// TestLookupHostShortCircuitsOnALiteralIP covers the resolver bypass. An image
// reference that already names an IP must not trigger a DNS query, both to save
// the round trip and because there is nothing to resolve.
func TestLookupHostShortCircuitsOnALiteralIP(t *testing.T) {
	t.Parallel()

	client := &RegistryClient{}
	called := false
	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		called = true
		return nil, nil
	}

	ips, err := client.lookupHost(t.Context(), "93.184.216.34")
	if err != nil {
		t.Fatalf("lookupHost: %v", err)
	}
	if called {
		t.Error("a literal IP triggered a DNS lookup")
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("ips = %v, want the literal address", ips)
	}
}

// TestCleanDockerInventoryRelPathRejectsEscapes covers the path guard on
// discovered Dockerfiles and compose files. The walk runs over the scanned
// repository, so a path that resolves outside the scan root must be refused.
func TestCleanDockerInventoryRelPathRejectsEscapes(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{".", "..", filepath.Join("..", "outside"), ""} {
		if got, err := cleanDockerInventoryRelPath(rel); err == nil {
			t.Errorf("cleanDockerInventoryRelPath(%q) = %q, nil; want a refusal", rel, got)
		}
	}

	got, err := cleanDockerInventoryRelPath("docker/Dockerfile")
	if err != nil {
		t.Fatalf("a normal relative path was rejected: %v", err)
	}
	if got != filepath.Clean("docker/Dockerfile") {
		t.Fatalf("cleaned path = %q, want the cleaned relative path", got)
	}
}

// TestDockerInventoryRelDisplayNeverLeaksAnAbsolutePath covers the message
// helper. These strings end up in scan warnings the user may share, so an
// absolute path would disclose the local directory layout.
func TestDockerInventoryRelDisplayNeverLeaksAnAbsolutePath(t *testing.T) {
	t.Parallel()

	// The input always comes from filepath.Rel, so it uses the host platform's
	// path syntax. A POSIX-absolute path is *relative* on Windows, which would
	// make this fixture test nothing there.
	absolute := filepath.Join(string(filepath.Separator), "home", "user", "secret-project", "Dockerfile")
	if runtime.GOOS == "windows" {
		absolute = filepath.Join("C:\\", "Users", "someone", "secret-project", "Dockerfile")
	}
	got := dockerInventoryRelDisplay(absolute)
	if strings.Contains(got, "secret-project") {
		t.Fatalf("display = %q, want only the file name", got)
	}
	if got != "Dockerfile" {
		t.Fatalf("display = %q, want Dockerfile", got)
	}

	for _, rel := range []string{"", "   ", "."} {
		if got := dockerInventoryRelDisplay(rel); got != "docker-inventory-file" {
			t.Errorf("dockerInventoryRelDisplay(%q) = %q, want the placeholder", rel, got)
		}
	}

	if got := dockerInventoryRelDisplay("docker/Dockerfile"); got != "docker/Dockerfile" {
		t.Errorf("display = %q, want the relative path with forward slashes", got)
	}
}
