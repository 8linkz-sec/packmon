package netutil

import (
	"fmt"
	"net/netip"
	"strings"
)

type TrustedProxySet struct {
	prefixes []netip.Prefix
}

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

func (p TrustedProxySet) Len() int {
	return len(p.prefixes)
}

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
