package packagefilter

import "strings"

// ExcludedByNamespace reports whether a package coordinate matches one of the
// configured namespace prefixes. Prefixes may be ecosystem-qualified
// ("npm/@internal/", "maven/com.acme:") or raw name prefixes ("@internal/").
func ExcludedByNamespace(prefixes []string, ecosystem, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	key := ecosystem + "/" + strings.ToLower(name)
	lowerName := strings.ToLower(name)

	for _, prefix := range prefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		if strings.Contains(prefix, "/") {
			if strings.HasPrefix(key, prefix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	return false
}
