package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/8linkz/packmon/internal/config"
)

func dashboardURL(cfg *config.Config, listenerAddr string) string {
	scheme := "http"
	if cfg != nil && cfg.Server.TLS.Enabled() {
		scheme = "https"
	}

	if cfg != nil {
		if publicHost := strings.TrimSpace(cfg.Server.PublicHost); publicHost != "" {
			return normalizePublicDashboardURL(scheme, publicHost)
		}
	}

	host, port, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		host = "localhost"
		if cfg != nil && cfg.Server.Port > 0 {
			port = strconv.Itoa(cfg.Server.Port)
		}
	}
	if port == "" && cfg != nil && cfg.Server.Port > 0 {
		port = strconv.Itoa(cfg.Server.Port)
	}
	if isWildcardHost(host) {
		host = "localhost"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	if port == "" {
		return fmt.Sprintf("%s://%s/", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%s/", scheme, host, port)
}

func normalizePublicDashboardURL(scheme, host string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	if strings.Contains(host, "://") {
		return host + "/"
	}
	return scheme + "://" + host + "/"
}

func isWildcardHost(host string) bool {
	switch strings.TrimSpace(strings.ToLower(host)) {
	case "", "0.0.0.0", "::", "[::]":
		return true
	default:
		return false
	}
}
