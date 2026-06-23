package httpclient

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
