package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/config"
)

// mainServerReadyMessage puts the dashboard URL in the log message itself so it
// is easy to spot when the "server listening" line scrolls past among the
// simultaneous feed-sync startup lines. The bind address stays in a separate
// structured field.
func mainServerReadyMessage(dashboard string) string {
	return "server ready -- open the dashboard at " + dashboard
}

// dashboardBanner frames the dashboard URL in a plain-text box. It is printed to
// stdout at startup independent of the structured JSON logger, so the URL stays
// unmissable even when it would otherwise scroll past among the ~10 simultaneous
// feed-sync startup lines -- or be hidden entirely when `docker compose up`
// merely re-attaches to an already-running container and never replays the
// startup log line. The border adapts to the content width.
func dashboardBanner(dashboard string) string {
	content := "  Packmon → " + dashboard + "  "
	rule := strings.Repeat("─", utf8.RuneCountInString(content))
	return "\n" + rule + "\n" + content + "\n" + rule + "\n"
}

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
