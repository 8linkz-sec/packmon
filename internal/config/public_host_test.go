package config

import (
	"strings"
	"testing"
)

// validatePublicHost guards a value an operator sets to tell Packmon its own
// externally reachable address. It ends up in generated links and redirects, so
// a value carrying a scheme, a path or userinfo would produce a broken -- or
// attacker-chosen -- URL.

// TestValidatePublicHostAcceptsEveryLegitimateForm covers the shapes an operator
// can reasonably configure, including the bracketed IPv6 form that needs its own
// parsing branch.
func TestValidatePublicHostAcceptsEveryLegitimateForm(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"packmon.internal",
		"packmon.internal:8080",
		"  packmon.internal:8080  ",
		"192.0.2.10",
		"192.0.2.10:8080",
		"[2001:db8::1]",
		"[2001:db8::1]:8080",
		"2001:db8::1",
		"localhost",
		"localhost:8080",
	} {
		if err := validatePublicHost("server.public_host", host); err != nil {
			t.Errorf("validatePublicHost(%q) = %v, want it accepted", host, err)
		}
	}
}

// TestValidatePublicHostRejectsURLsAndUserinfo is the security-relevant half. A
// public host that smuggled in a scheme, a path or credentials would be pasted
// verbatim into generated links.
func TestValidatePublicHostRejectsURLsAndUserinfo(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"",
		"   ",
		"https://packmon.internal",
		"packmon.internal/path",
		`packmon.internal\path`,
		"user@packmon.internal",
		"user:pw@packmon.internal",
		"//packmon.internal",
	} {
		err := validatePublicHost("server.public_host", host)
		if err == nil {
			t.Errorf("validatePublicHost(%q) was accepted", host)
			continue
		}
		if !strings.Contains(err.Error(), "server.public_host") {
			t.Errorf("validatePublicHost(%q) error = %v, want it to name the key", host, err)
		}
	}
}

// TestValidatePublicHostRejectsNonHostCharacters covers values that pass the
// scheme/path/userinfo checks but still are not a bare host[:port]. The value
// is pasted into "https://" + host + path redirects and links, so a fragment,
// query, whitespace, or control character would change or truncate the URL.
func TestValidatePublicHostRejectsNonHostCharacters(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"packmon.internal#fragment",
		"packmon.internal:8443#fragment",
		"packmon.internal?x=1",
		"packmon.internal:8443?x=1",
		"packmon .internal",
		"packmon.internal\t:8443",
		"packmon.internal\x00",
		"packmon\x7f.internal",
		"packmon.internal\r\nX-Injected: 1",
		"packmon%2einternal",
		"packmon.internal:+443",
		"packmon.internal:",
		"[2001:db8::1]:",
		"packmon.internal: 443",
		"[2001:db8::1%25eth0]",
		"[packmon.internal]:8443",
		"[192.0.2.10]",
		"2001:db8::zz",
		"päckmon.internal",
		"packmon.internal;x",
	} {
		err := validatePublicHost("server.public_host", host)
		if err == nil {
			t.Errorf("validatePublicHost(%q) was accepted", host)
			continue
		}
		if !strings.Contains(err.Error(), "server.public_host") {
			t.Errorf("validatePublicHost(%q) error = %v, want it to name the key", host, err)
		}
	}
}

// TestValidatePublicHostRejectsMalformedIPv6Brackets covers the bracket parsing
// specifically. An unterminated or doubly-suffixed bracket form must be refused
// rather than silently reinterpreted as a hostname containing brackets.
func TestValidatePublicHostRejectsMalformedIPv6Brackets(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"[2001:db8::1",
		"[2001:db8::1]8080",
		"[2001:db8::1]:80:80",
		"[]",
		"[]:8080",
		"[   ]",
	} {
		if err := validatePublicHost("server.public_host", host); err == nil {
			t.Errorf("validatePublicHost(%q) was accepted", host)
		}
	}
}

// TestValidatePublicHostRejectsAnEmptyHostPart covers the case where a port is
// present but the host is not -- ":8080" names no host to build a link from.
func TestValidatePublicHostRejectsAnEmptyHostPart(t *testing.T) {
	t.Parallel()

	for _, host := range []string{":8080", " :8080", ":"} {
		if err := validatePublicHost("server.public_host", host); err == nil {
			t.Errorf("validatePublicHost(%q) was accepted", host)
		}
	}
}
