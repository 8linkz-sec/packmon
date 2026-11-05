package dockerimage

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type f251ErrorReader struct {
	err error
}

func (r f251ErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestF251RegistryResponseErrors(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("transport failed")
	client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})})
	client.InsecureHTTP = true
	ref := Ref{Registry: "registry.example", Repository: "library/alpine", Reference: "latest"}
	if _, _, err := client.resolveDigestOnce(t.Context(), ref, ""); !errors.Is(err, transportErr) {
		t.Fatalf("resolveDigestOnce(transport error) = %v, want %v", err, transportErr)
	}

	if _, err := client.fetchBearerToken(t.Context(), `Bearer service="registry.example"`, ref.Registry); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("fetchBearerToken(missing realm) = %v, want ErrDigestUnavailable", err)
	}
	if _, err := client.fetchBearerToken(t.Context(), `Bearer realm="http://%"`, ref.Registry); err == nil {
		t.Fatal("fetchBearerToken(invalid realm) error = nil")
	}
	if _, err := client.fetchBearerToken(t.Context(), `Bearer realm="http://registry.example/token"`, ref.Registry); !errors.Is(err, transportErr) {
		t.Fatalf("fetchBearerToken(transport error) = %v, want %v", err, transportErr)
	}

	for _, tc := range []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "status", statusCode: http.StatusServiceUnavailable, body: `{}`},
		{name: "invalid JSON", statusCode: http.StatusOK, body: `{`},
		{name: "missing token", statusCode: http.StatusOK, body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			responseClient := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(strings.NewReader(tc.body)),
					Header:     make(http.Header),
				}, nil
			})})
			responseClient.InsecureHTTP = true
			if _, err := responseClient.fetchBearerToken(t.Context(), `Bearer realm="http://registry.example/token"`, ref.Registry); !errors.Is(err, ErrDigestUnavailable) {
				t.Fatalf("fetchBearerToken(%s) = %v, want ErrDigestUnavailable", tc.name, err)
			}
		})
	}

	readErr := errors.New("read failed")
	if _, err := readBoundedTokenResponse(f251ErrorReader{err: readErr}); !errors.Is(err, ErrDigestUnavailable) || !strings.Contains(err.Error(), readErr.Error()) {
		t.Fatalf("readBoundedTokenResponse(error) = %v, want wrapped diagnostic", err)
	}
}

func TestF251RegistryURLPolicyBranches(t *testing.T) {
	t.Parallel()

	client := NewRegistryClient(http.DefaultClient)
	if err := client.validateRegistryURL(t.Context(), "https://%", false); err == nil {
		t.Fatal("validateRegistryURL(invalid URL) error = nil")
	}
	if err := client.validateRegistryURL(t.Context(), "ftp://ghcr.io/v2/", false); !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("validateRegistryURL(unsupported scheme) = %v, want ErrRegistryUnsupported", err)
	}

	registryHost := "registry.example"
	client.Mirrors = map[string]string{registryHost: "%"}
	if err := client.validateTokenRealm(t.Context(), &url.URL{Scheme: "https", Host: "mirror.example"}, registryHost); err == nil {
		t.Fatal("validateTokenRealm(invalid mirror URL) error = nil")
	}

	client.Mirrors[registryHost] = "https://mirror.example/base"
	if err := client.validateTokenRealm(t.Context(), nil, registryHost); !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("validateTokenRealm(nil realm) = %v, want ErrRegistryUnsupported", err)
	}

	client.Mirrors[registryHost] = "ftp://mirror.example/base"
	if err := client.validateTokenRealm(t.Context(), &url.URL{Scheme: "https", Host: "mirror.example"}, registryHost); !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("validateTokenRealm(invalid mirror scheme) = %v, want ErrRegistryUnsupported", err)
	}

	client.Mirrors[registryHost] = "https://mirror.example/base"
	if err := client.validateTokenRealm(t.Context(), &url.URL{Scheme: "https", Host: "other.example"}, registryHost); !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("validateTokenRealm(mismatched mirror) = %v, want ErrRegistryUnsupported", err)
	}
	if err := client.validateTokenRealm(t.Context(), &url.URL{Scheme: "https", Host: "mirror.example", Path: "/token"}, registryHost); err != nil {
		t.Fatalf("validateTokenRealm(matching mirror) = %v", err)
	}

	client.Mirrors = nil
	if err := client.validateTokenRealm(t.Context(), nil, registryHost); !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("validateTokenRealm(nil public realm) = %v, want ErrRegistryUnsupported", err)
	}
	client.InsecureHTTP = true
	if err := client.validateTokenRealm(t.Context(), &url.URL{Scheme: "http", Host: registryHost}, registryHost); err != nil {
		t.Fatalf("validateTokenRealm(insecure test seam) = %v", err)
	}

	for _, tc := range []struct {
		name string
		u    *url.URL
	}{
		{name: "nil", u: nil},
		{name: "userinfo", u: &url.URL{Scheme: "https", Host: "mirror.example", User: url.UserPassword("user", "pass")}},
		{name: "insecure non-loopback mirror", u: &url.URL{Scheme: "http", Host: "mirror.example"}},
		{name: "blocked literal mirror IP", u: &url.URL{Scheme: "https", Host: "169.254.169.254"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeDockerMirrorURLTarget(tc.u); !errors.Is(err, ErrRegistryUnsupported) {
				t.Fatalf("normalizeDockerMirrorURLTarget(%s) = %v, want ErrRegistryUnsupported", tc.name, err)
			}
		})
	}

	for _, tc := range []struct {
		name      string
		u         *url.URL
		allowHTTP bool
	}{
		{name: "nil", u: nil},
		{name: "userinfo", u: &url.URL{Scheme: "https", Host: "registry.example", User: url.User("user")}},
		{name: "disallowed HTTP", u: &url.URL{Scheme: "http", Host: "registry.example"}},
		{name: "unsupported scheme", u: &url.URL{Scheme: "ftp", Host: "registry.example"}, allowHTTP: true},
		{name: "empty hostname", u: &url.URL{Scheme: "https", Host: ":443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeHTTPURLTarget(tc.u, tc.allowHTTP); !errors.Is(err, ErrRegistryUnsupported) {
				t.Fatalf("normalizeHTTPURLTarget(%s) = %v, want ErrRegistryUnsupported", tc.name, err)
			}
		})
	}

	if !dockerMirrorHostIsLoopback(" LOCALHOST ") {
		t.Fatal("dockerMirrorHostIsLoopback(localhost) = false")
	}
	if isAllowedDockerTokenRealmHost("ghcr.io", "auth.docker.io") {
		t.Fatal("ghcr.io unexpectedly accepted an undeclared token realm")
	}
}

func TestF251RegistryLookupBranches(t *testing.T) {
	t.Parallel()

	lookupErr := errors.New("lookup failed")
	client := &RegistryClient{LookupIP: func(context.Context, string) ([]net.IP, error) {
		return nil, lookupErr
	}}
	if err := client.rejectPrivateHTTPURLTarget(t.Context(), "registry.example"); !errors.Is(err, ErrDigestUnavailable) || !strings.Contains(err.Error(), lookupErr.Error()) {
		t.Fatalf("rejectPrivateHTTPURLTarget(lookup error) = %v", err)
	}

	client.LookupIP = func(context.Context, string) ([]net.IP, error) { return nil, nil }
	if err := client.rejectPrivateHTTPURLTarget(t.Context(), "registry.example"); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("rejectPrivateHTTPURLTarget(no addresses) = %v, want ErrDigestUnavailable", err)
	}

	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	if err := client.rejectPrivateHTTPURLTarget(t.Context(), "registry.example"); err != nil {
		t.Fatalf("rejectPrivateHTTPURLTarget(public address) = %v", err)
	}

	client.LookupIP = nil
	ips, err := client.lookupHost(t.Context(), "localhost")
	if err != nil {
		t.Fatalf("lookupHost(localhost): %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("lookupHost(localhost) returned no addresses")
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := defaultLookupIP(canceled, "unresolvable.invalid"); err == nil {
		t.Fatal("defaultLookupIP(canceled context) error = nil")
	}
}
