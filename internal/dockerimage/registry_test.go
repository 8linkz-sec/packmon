package dockerimage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
