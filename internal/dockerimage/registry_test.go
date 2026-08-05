package dockerimage

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type registryRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn registryRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestRegistryClientResolvesDigestHeader(t *testing.T) {
	const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("method = %s, want HEAD", r.Method)
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.docker.distribution.manifest.v2+json") {
			t.Fatalf("Accept header = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if got != digest {
		t.Fatalf("digest = %q, want %q", got, digest)
	}
}

func TestRegistryClientUsesConfiguredRegistryMirror(t *testing.T) {
	const digest = "sha256:abababababababababababababababababababababababababababababababab"
	var sawMirrorRequest bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMirrorRequest = true
		if r.Method != http.MethodHead {
			t.Fatalf("method = %s, want HEAD", r.Method)
		}
		if r.URL.Path != "/mirror/dockerhub/v2/library/nginx/manifests/1.25" {
			t.Fatalf("mirror path = %q", r.URL.Path)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewRegistryClient(srv.Client())
	client.Mirrors = map[string]string{
		dockerHubRegistryHost: srv.URL + "/mirror/dockerhub",
	}
	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("configured registry mirror should not use public-registry DNS allowlist checks")
		return nil, nil
	}

	ref := Ref{Registry: dockerHubRegistryHost, Repository: "library/nginx", Reference: "1.25"}
	got, err := client.ResolveDigest(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveDigest(mirror): %v", err)
	}
	if !sawMirrorRequest || got != digest {
		t.Fatalf("sawMirrorRequest=%v digest=%q, want mirrored digest %q", sawMirrorRequest, got, digest)
	}
}

func TestRegistryClientHandlesBearerChallenge(t *testing.T) {
	const digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	var tokenSeen bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.URL.Query().Get("service") != "registry.example" || r.URL.Query().Get("scope") != "repository:library/alpine:pull" {
				t.Fatalf("token query = %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"abc123"}`))
		case "/v2/library/alpine/manifests/3.23":
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.example",scope="repository:library/alpine:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tokenSeen = true
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if got != digest || !tokenSeen {
		t.Fatalf("digest=%q tokenSeen=%v", got, tokenSeen)
	}
}

func TestRegistryClientReturnsEmptyDigestOnRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("ResolveDigest returned nil error for 429")
	}
	if got != "" {
		t.Fatalf("digest = %q, want empty on 429", got)
	}
}

func TestRegistryClientRejectsPrivateRegistryTargetsBeforeRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range privateRegistryIPTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lookupCalled bool
			client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unexpected HTTP request for private registry target")
				return nil, nil
			})})
			client.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
				lookupCalled = true
				if host != "ghcr.io" {
					t.Fatalf("lookup host = %q, want ghcr.io", host)
				}
				return []net.IP{tc.ip}, nil
			}

			ref := Ref{Registry: "ghcr.io", Repository: "library/alpine", Reference: "3.23"}
			if digest, err := client.ResolveDigest(context.Background(), ref); !errors.Is(err, ErrDigestUnavailable) || digest != "" {
				t.Fatalf("ResolveDigest(private registry) = %q, %v; want ErrDigestUnavailable", digest, err)
			}
			if !lookupCalled {
				t.Fatal("LookupIP was not called for allowlisted private registry target")
			}
		})
	}
}

func TestRegistryClientRejectsUnsupportedPublicRegistryBeforeRequest(t *testing.T) {
	t.Parallel()

	client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request for unsupported public registry")
		return nil, nil
	})})
	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	ref := Ref{Registry: "attacker.example.test", Repository: "library/alpine", Reference: "3.23"}
	if digest, err := client.ResolveDigest(context.Background(), ref); !errors.Is(err, ErrDigestUnavailable) || digest != "" {
		t.Fatalf("ResolveDigest(unsupported registry) = %q, %v; want ErrDigestUnavailable", digest, err)
	}
}

// TestRegistryClientPolicyRejectionSatisfiesBothSentinels pins the double-wrap
// contract: a client-side policy rejection -- one that never attempted a
// network request -- must still satisfy errors.Is against ErrDigestUnavailable
// (existing callers keep working) while also satisfying errors.Is against
// ErrRegistryUnsupported (new callers can tell it apart from a genuine
// registry/network failure).
func TestRegistryClientPolicyRejectionSatisfiesBothSentinels(t *testing.T) {
	t.Parallel()

	client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request for an unsupported public registry")
		return nil, nil
	})})
	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("unexpected DNS lookup for an unsupported public registry")
		return nil, nil
	}

	ref := Ref{Registry: "attacker.example.test", Repository: "library/alpine", Reference: "3.23"}
	_, err := client.ResolveDigest(context.Background(), ref)
	if !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("ResolveDigest(unsupported registry) = %v, want ErrDigestUnavailable", err)
	}
	if !errors.Is(err, ErrRegistryUnsupported) {
		t.Fatalf("ResolveDigest(unsupported registry) = %v, want ErrRegistryUnsupported", err)
	}
}

func TestRegistryClientRejectsPrivateBearerRealmBeforeRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range privateRegistryIPTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lookupCalled bool
			client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unexpected HTTP request for private bearer realm")
				return nil, nil
			})})
			client.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
				lookupCalled = true
				if host != "auth.docker.io" {
					t.Fatalf("lookup host = %q, want auth.docker.io", host)
				}
				return []net.IP{tc.ip}, nil
			}

			if _, err := client.fetchBearerToken(context.Background(), `Bearer realm="https://auth.docker.io/token"`, "registry-1.docker.io"); !errors.Is(err, ErrDigestUnavailable) {
				t.Fatalf("fetchBearerToken(private realm) = %v, want ErrDigestUnavailable", err)
			}
			if !lookupCalled {
				t.Fatal("LookupIP was not called for allowlisted private bearer realm")
			}
		})
	}
}

func TestRegistryClientRejectsUnexpectedPublicBearerRealmBeforeRequest(t *testing.T) {
	t.Parallel()

	client := NewRegistryClient(&http.Client{Transport: registryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request for unsupported bearer realm")
		return nil, nil
	})})
	client.LookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	if _, err := client.fetchBearerToken(context.Background(), `Bearer realm="https://attacker.example.test/token"`, "registry-1.docker.io"); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("fetchBearerToken(unexpected public realm) = %v, want ErrDigestUnavailable", err)
	}
}

func TestRegistryClientRejectsOversizedBearerTokenResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"` + strings.Repeat("a", dockerBearerTokenResponseLimit+1) + `"}`))
	}))
	defer srv.Close()

	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true
	if _, err := client.fetchBearerToken(context.Background(), `Bearer realm="`+srv.URL+`/token"`, strings.TrimPrefix(srv.URL, "http://")); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("fetchBearerToken(oversized response) = %v, want ErrDigestUnavailable", err)
	}
}

func privateRegistryIPTestCases() []struct {
	name string
	ip   net.IP
} {
	return []struct {
		name string
		ip   net.IP
	}{
		{name: "nil-address", ip: nil},
		{name: "private", ip: net.ParseIP("10.0.0.5")},
		{name: "loopback", ip: net.ParseIP("127.0.0.1")},
		{name: "link-local-unicast", ip: net.ParseIP("169.254.169.254")},
		{name: "link-local-multicast", ip: net.ParseIP("224.0.0.1")},
		{name: "multicast", ip: net.ParseIP("239.1.2.3")},
		{name: "unspecified", ip: net.ParseIP("0.0.0.0")},
	}
}
