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
