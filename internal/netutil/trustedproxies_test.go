package netutil

import (
	"strings"
	"testing"
)

func TestParseTrustedProxiesAndContains(t *testing.T) {
	set, err := ParseTrustedProxies([]string{
		" 192.0.2.10 ",
		"198.51.100.0/24",
		"2001:db8::/32",
		"",
	})
	if err != nil {
		t.Fatalf("ParseTrustedProxies() error = %v", err)
	}
	if got := set.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	for _, ip := range []string{"192.0.2.10", "198.51.100.42", "2001:db8::1"} {
		if !set.Contains(ip) {
			t.Fatalf("Contains(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"192.0.2.11", "198.51.101.1", "not-an-ip"} {
		if set.Contains(ip) {
			t.Fatalf("Contains(%q) = true, want false", ip)
		}
	}
}

func TestParseTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"192.0.2.0/33"}); err == nil || !strings.Contains(err.Error(), "invalid trusted proxy entry") {
		t.Fatalf("ParseTrustedProxies(invalid) error = %v", err)
	}
}
