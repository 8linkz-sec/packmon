package httpclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSafeRedirectPolicy(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URL %q: %v", raw, err)
		}
		return u
	}
	req := func(raw string) *http.Request {
		return &http.Request{URL: mustURL(raw), Header: make(http.Header)}
	}

	t.Run("allows initial request and missing URL context", func(t *testing.T) {
		if err := SafeRedirectPolicy(req("https://example.test/a"), nil); err != nil {
			t.Fatalf("initial redirect error = %v", err)
		}
		if err := SafeRedirectPolicy(nil, []*http.Request{req("https://example.test/a")}); err != nil {
			t.Fatalf("nil request error = %v", err)
		}
	})

	t.Run("stops long redirect chains", func(t *testing.T) {
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = req("https://example.test/a")
		}
		if err := SafeRedirectPolicy(req("https://example.test/b"), via); err == nil || !strings.Contains(err.Error(), "10 redirects") {
			t.Fatalf("long chain error = %v, want 10 redirects", err)
		}
	})

	t.Run("rejects https to http downgrade", func(t *testing.T) {
		if err := SafeRedirectPolicy(req("http://example.test/b"), []*http.Request{req("https://example.test/a")}); err == nil || !strings.Contains(err.Error(), "https to http") {
			t.Fatalf("downgrade error = %v, want refusal", err)
		}
	})

	t.Run("strips authorization across origins", func(t *testing.T) {
		next := req("https://other.test/b")
		next.Header.Set("Authorization", "Bearer secret")
		if err := SafeRedirectPolicy(next, []*http.Request{req("https://example.test/a")}); err != nil {
			t.Fatalf("cross-origin redirect error = %v", err)
		}
		if got := next.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization after cross-origin redirect = %q, want empty", got)
		}
	})

	t.Run("preserves authorization on same origin", func(t *testing.T) {
		next := req("https://example.test/b")
		next.Header.Set("Authorization", "Bearer secret")
		if err := SafeRedirectPolicy(next, []*http.Request{req("https://example.test/a")}); err != nil {
			t.Fatalf("same-origin redirect error = %v", err)
		}
		if got := next.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization after same-origin redirect = %q", got)
		}
	})
}

func TestCloneWithSafeRedirectPolicy(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URL %q: %v", raw, err)
		}
		return u
	}

	t.Run("clones client and installs safe policy", func(t *testing.T) {
		original := &http.Client{}
		client := CloneWithSafeRedirectPolicy(original)
		if client == original {
			t.Fatal("CloneWithSafeRedirectPolicy returned original client, want shallow copy")
		}
		if err := client.CheckRedirect(
			&http.Request{URL: mustURL("http://example.test/next")},
			[]*http.Request{{URL: mustURL("https://example.test/start")}},
		); err == nil || !strings.Contains(err.Error(), "https to http") {
			t.Fatalf("CheckRedirect() error = %v, want HTTPS downgrade refusal", err)
		}
	})

	t.Run("preserves existing policy", func(t *testing.T) {
		existingCalled := false
		client := CloneWithSafeRedirectPolicy(&http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				existingCalled = true
				return nil
			},
		})

		err := client.CheckRedirect(
			&http.Request{URL: mustURL("https://other.test/next")},
			[]*http.Request{{URL: mustURL("https://example.test/start")}},
		)
		if err != nil {
			t.Fatalf("CheckRedirect() error = %v", err)
		}
		if !existingCalled {
			t.Fatal("existing CheckRedirect policy was not called")
		}
	})
}
