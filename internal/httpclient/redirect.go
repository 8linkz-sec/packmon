// Package httpclient contains shared outbound HTTP client policies for Packmon
// clients that may carry bearer tokens or signed payloads.
package httpclient

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SafeRedirectPolicy is a net/http redirect policy for Packmon clients that
// carry credentials. It stops after ten redirects, rejects HTTPS-to-HTTP
// downgrades, preserves Authorization only for same-origin redirects, and
// strips Authorization before cross-origin redirects. Use it for outbound
// Packmon API, local sync, and webhook clients that may send bearer tokens or
// signed scan payloads.
func SafeRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if len(via) == 0 || req == nil || req.URL == nil {
		return nil
	}
	prev := via[len(via)-1]
	if prev != nil && prev.URL != nil &&
		strings.EqualFold(prev.URL.Scheme, "https") &&
		strings.EqualFold(req.URL.Scheme, "http") {
		return fmt.Errorf("refusing redirect from https to http")
	}
	if prev != nil && prev.URL != nil && !sameOrigin(prev.URL, req.URL) {
		req.Header.Del("Authorization")
	}
	return nil
}

// CloneWithSafeRedirectPolicy returns a shallow copy of client with
// SafeRedirectPolicy installed. An existing CheckRedirect policy is preserved
// and must allow the redirect before the shared safe policy is evaluated.
func CloneWithSafeRedirectPolicy(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	existingRedirectPolicy := clone.CheckRedirect
	if existingRedirectPolicy == nil {
		clone.CheckRedirect = SafeRedirectPolicy
		return &clone
	}
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := existingRedirectPolicy(req, via); err != nil {
			return err
		}
		return SafeRedirectPolicy(req, via)
	}
	return &clone
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
