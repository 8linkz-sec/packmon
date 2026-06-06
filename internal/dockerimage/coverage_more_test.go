package dockerimage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalInspectorEdgeBranches(t *testing.T) {
	t.Parallel()

	if got := (LocalInspector{}).Digests(context.Background(), nil); got != nil {
		t.Fatalf("Digests(nil) = %#v, want nil", got)
	}
	if got := (LocalInspector{}).Digests(context.Background(), []Ref{{Name: "local/app", Registry: "local", Repository: "app", Reference: "latest"}}); got != nil {
		t.Fatalf("Digests(local only) = %#v, want nil", got)
	}

	ref, _ := ParseRef("alpine:3.23")
	if got := (LocalInspector{Runner: &fakeRunner{out: `not json`}}).Digests(context.Background(), []Ref{ref}); got != nil {
		t.Fatalf("Digests(invalid JSON) = %#v, want nil", got)
	}
	noMatch := (LocalInspector{Runner: &fakeRunner{out: `[{"RepoTags":["busybox:latest"],"RepoDigests":["busybox@sha256:abc"]}]`}}).Digests(context.Background(), []Ref{ref})
	if len(noMatch) != 0 {
		t.Fatalf("Digests(no matching tag) = %#v, want empty map", noMatch)
	}
	if got := normalizeLocalRepoTag("bad://ref"); got != "bad://ref" {
		t.Fatalf("normalizeLocalRepoTag(invalid) = %q", got)
	}
	if got := normalizeLocalRepoName("bad://name"); got != "bad://name" {
		t.Fatalf("normalizeLocalRepoName(invalid) = %q", got)
	}
}

func TestCollectorAndDiscoverEdgeBranches(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if _, err := DiscoverFiles(filepath.Join(root, "missing"), 1); err == nil {
		t.Fatal("DiscoverFiles(missing) error = nil")
	}
	regular := filepath.Join(root, "file")
	writeDockerImageTestFile(t, regular, "x")
	if _, err := DiscoverFiles(regular, 1); err == nil {
		t.Fatal("DiscoverFiles(file) error = nil")
	}

	writeDockerImageTestFile(t, filepath.Join(root, ".github", "workflows", "Dockerfile.ci"), "FROM alpine:3.23\n")
	writeDockerImageTestFile(t, filepath.Join(root, ".cache", "Dockerfile"), "FROM ignored:latest\n")
	files, err := DiscoverFiles(root, 5)
	if err != nil {
		t.Fatalf("DiscoverFiles(.github) error = %v", err)
	}
	var sawGitHub, sawCache bool
	for _, file := range files {
		if strings.Contains(file.RelPath, ".github") {
			sawGitHub = true
		}
		if strings.Contains(file.RelPath, ".cache") {
			sawCache = true
		}
	}
	if !sawGitHub || sawCache {
		t.Fatalf("DiscoverFiles hidden handling sawGitHub=%v sawCache=%v files=%+v", sawGitHub, sawCache, files)
	}

	if _, err := parseFile(File{Path: filepath.Join(root, "missing"), RelPath: "missing", Kind: KindDockerfile}); err == nil {
		t.Fatal("parseFile(missing) error = nil")
	}
	unknown := filepath.Join(root, "unknown.txt")
	writeDockerImageTestFile(t, unknown, "x")
	if _, err := parseFile(File{Path: unknown, RelPath: "unknown.txt", Kind: Kind("other")}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("parseFile(unsupported) = %v", err)
	}

	ref, _ := ParseRef("alpine:3.23")
	images := dedupImages([]Image{
		{Ref: ref, SourceFile: "Dockerfile", Relation: "base", Flags: []string{"stage=build"}, LocalBuild: false},
		{Ref: ref, SourceFile: "Dockerfile", Relation: "base", Flags: []string{"stage=build", "stage=runtime"}, LocalBuild: true},
	})
	if len(images) != 1 || !images[0].LocalBuild || strings.Join(images[0].Flags, ",") != "stage=build,stage=runtime" {
		t.Fatalf("dedupImages() = %+v", images)
	}
}

func TestRegistryClientErrorBranches(t *testing.T) {
	t.Parallel()

	client := NewRegistryClient(nil)
	if client.HTTP == nil {
		t.Fatal("NewRegistryClient(nil) did not install default HTTP client")
	}
	if _, err := client.ResolveDigest(context.Background(), Ref{Name: "local/app", Registry: "local", Repository: "app", Reference: "latest"}); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("ResolveDigest(local) = %v, want ErrDigestUnavailable", err)
	}

	noDigest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer noDigest.Close()
	ref := Ref{Registry: strings.TrimPrefix(noDigest.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client = NewRegistryClient(noDigest.Client())
	client.InsecureHTTP = true
	if digest, err := client.ResolveDigest(context.Background(), ref); !errors.Is(err, ErrDigestUnavailable) || digest != "" {
		t.Fatalf("ResolveDigest(no digest) = %q, %v", digest, err)
	}

	badChallenge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer badChallenge.Close()
	ref.Registry = strings.TrimPrefix(badChallenge.URL, "http://")
	client = NewRegistryClient(badChallenge.Client())
	client.InsecureHTTP = true
	if _, err := client.ResolveDigest(context.Background(), ref); !errors.Is(err, ErrDigestUnavailable) {
		t.Fatalf("ResolveDigest(bad challenge) = %v", err)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"token-from-access-token"}`))
		default:
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Docker-Content-Digest", "sha256:abc")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	ref.Registry = strings.TrimPrefix(srv.URL, "http://")
	client = NewRegistryClient(srv.Client())
	client.InsecureHTTP = true
	if digest, err := client.ResolveDigest(context.Background(), ref); err != nil || digest != "sha256:abc" {
		t.Fatalf("ResolveDigest(access_token) = %q, %v", digest, err)
	}

	if params, ok := parseBearerChallenge(`Bearer realm="https://auth.example",broken,service="registry"`); !ok || params["service"] != "registry" {
		t.Fatalf("parseBearerChallenge() = %+v, %v", params, ok)
	}
	if _, ok := parseBearerChallenge("Basic nope"); ok {
		t.Fatal("parseBearerChallenge(Basic) ok = true, want false")
	}
}

func TestClassifyFileVariants(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"docker-compose.yaml", "compose.yml", "compose.yaml"} {
		if kind, ok := classifyFile(name); !ok || kind != KindCompose {
			t.Fatalf("classifyFile(%q) = %q,%v; want compose", name, kind, ok)
		}
	}
	if kind, ok := classifyFile("Containerfile"); ok || kind != "" {
		t.Fatalf("classifyFile(Containerfile) = %q,%v; want false", kind, ok)
	}
}

func TestCollectReturnsDiscoverError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if _, err := Collect(path, 1); err == nil {
		t.Fatal("Collect(file) error = nil")
	}
}
