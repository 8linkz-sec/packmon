package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// TrustedProxySet is the parsed set of direct proxy peer IPs that may supply
// trusted forwarding headers. Callers must only honor X-Forwarded-* or similar
// headers when the direct peer address matches this set.
type TrustedProxySet struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies parses PACKMON_TRUSTED_PROXIES-style entries into a set
// of trusted direct proxy peers. Each non-empty value must be an IP address or
// CIDR prefix; hostnames and host:port strings are rejected, and CIDR prefixes
// are normalized with their masked network address.
func ParseTrustedProxies(values []string) (TrustedProxySet, error) {
	set := TrustedProxySet{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			set.prefixes = append(set.prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			set.prefixes = append(set.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return TrustedProxySet{}, fmt.Errorf("invalid trusted proxy entry (want IP address or CIDR prefix)")
	}
	return set, nil
}

// Len returns the number of parsed trusted proxy prefixes.
func (p TrustedProxySet) Len() int {
	return len(p.prefixes)
}

// Contains reports whether raw is a syntactically valid IP address contained in
// the trusted proxy set. Invalid, empty, hostname, or host:port values are never
// trusted.
func (p TrustedProxySet) Contains(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// IsLoopbackHost reports whether hostport is localhost or a loopback IP. It
// accepts bare hosts, host:port, and bracketed IPv6 host:port forms.
func IsLoopbackHost(hostport string) bool {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		end := strings.Index(host, "]")
		host = host[1:end]
	} else if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
