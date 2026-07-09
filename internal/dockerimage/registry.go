package dockerimage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	manifestAccept                   = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
	dockerBearerTokenResponseLimit   = 64 * 1024
	dockerHubRegistryHost            = "registry-1.docker.io"
	dockerHubAuthenticationRealmHost = "auth.docker.io"
)

// ErrDigestUnavailable means a registry digest lookup could not produce a
// trusted manifest digest. Callers treat this as missing freshness metadata, not
// as a package scan failure.
var ErrDigestUnavailable = errors.New("docker registry digest unavailable")

var allowedDockerRegistryHosts = map[string]struct{}{
	"asia.gcr.io":         {},
	"eu.gcr.io":           {},
	"gcr.io":              {},
	"ghcr.io":             {},
	"mcr.microsoft.com":   {},
	"public.ecr.aws":      {},
	"quay.io":             {},
	"registry.gitlab.com": {},
	"registry.k8s.io":     {},
	dockerHubRegistryHost: {},
	"us.gcr.io":           {},
}

var allowedDockerTokenRealmHosts = map[string]map[string]struct{}{
	dockerHubRegistryHost: {
		dockerHubAuthenticationRealmHost: {},
		dockerHubRegistryHost:            {},
	},
}

// RegistryClient performs metadata-only Docker manifest digest lookups for the
// list-all Docker inventory path. It allowlists public registry hosts, rejects
// private or local resolved addresses, validates supported bearer-token realms,
// and never performs vulnerability scans.
type RegistryClient struct {
	HTTP *http.Client
	// Mirrors maps normalized public registry hosts to trusted registry mirror
	// base URLs. Mirror values come only from trusted operator configuration;
	// repository-controlled image references cannot add entries here.
	Mirrors map[string]string
	// InsecureHTTP is a test seam for local registry fixtures and must not be
	// enabled for normal registry egress.
	InsecureHTTP bool
	// LookupIP resolves registry and token hosts; tests can inject it to verify
	// private, loopback, and link-local address rejection.
	LookupIP func(context.Context, string) ([]net.IP, error)
}

// NewRegistryClient returns a registry digest client with a bounded HTTP client
// and the default DNS resolver used for egress trust-boundary checks.
func NewRegistryClient(client *http.Client) *RegistryClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &RegistryClient{HTTP: client, LookupIP: defaultLookupIP}
}

// ResolveDigest returns the remote manifest digest for a supported public image
// reference. Unsupported registries, local images, unsafe network destinations,
// and registry failures return ErrDigestUnavailable so Docker inventory remains
// report-only metadata.
func (c *RegistryClient) ResolveDigest(ctx context.Context, ref Ref) (string, error) {
	if ref.Registry == "" || ref.Repository == "" || ref.Reference == "" || strings.HasPrefix(ref.Name, "local/") {
		return "", ErrDigestUnavailable
	}
	digest, challenge, err := c.resolveDigestOnce(ctx, ref, "")
	if err == nil || challenge == "" {
		return digest, err
	}
	token, tokenErr := c.fetchBearerToken(ctx, challenge, ref.Registry)
	if tokenErr != nil {
		return "", tokenErr
	}
	return c.resolveDigestOnceNoChallenge(ctx, ref, token)
}

func (c *RegistryClient) resolveDigestOnce(ctx context.Context, ref Ref, token string) (string, string, error) {
	manifestURL, mirrored := c.manifestURL(ref)
	if err := c.validateRegistryURL(ctx, manifestURL, mirrored); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", manifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusUnauthorized {
		return "", resp.Header.Get("WWW-Authenticate"), ErrDigestUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("%w: status %d", ErrDigestUnavailable, resp.StatusCode)
	}
	digest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if digest == "" {
		return "", "", ErrDigestUnavailable
	}
	return digest, "", nil
}

func (c *RegistryClient) resolveDigestOnceNoChallenge(ctx context.Context, ref Ref, token string) (string, error) {
	digest, _, err := c.resolveDigestOnce(ctx, ref, token)
	return digest, err
}

func (c *RegistryClient) manifestURL(ref Ref) (string, bool) {
	if baseURL, ok := c.registryMirrorBaseURL(ref.Registry); ok {
		return strings.TrimRight(baseURL, "/") + "/v2/" + strings.Trim(ref.Repository, "/") + "/manifests/" + url.PathEscape(ref.Reference), true
	}
	scheme := "https"
	if c.InsecureHTTP {
		scheme = "http"
	}
	return scheme + "://" + ref.Registry + "/v2/" + ref.Repository + "/manifests/" + url.PathEscape(ref.Reference), false
}

func (c *RegistryClient) registryMirrorBaseURL(registryHost string) (string, bool) {
	if len(c.Mirrors) == 0 {
		return "", false
	}
	baseURL, ok := c.Mirrors[normalizeDockerHost(registryHost)]
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return baseURL, ok && baseURL != ""
}

func (c *RegistryClient) fetchBearerToken(ctx context.Context, challenge, registryHost string) (string, error) {
	params, ok := parseBearerChallenge(challenge)
	if !ok {
		return "", ErrDigestUnavailable
	}
	realm := params["realm"]
	if realm == "" {
		return "", ErrDigestUnavailable
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	if err := c.validateTokenRealm(ctx, u, registryHost); err != nil {
		return "", err
	}
	q := u.Query()
	for _, key := range []string{"service", "scope"} {
		if value := params[key]; value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: token status %d", ErrDigestUnavailable, resp.StatusCode)
	}
	data, err := readBoundedTokenResponse(resp.Body)
	if err != nil {
		return "", err
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", fmt.Errorf("%w: decode token response: %v", ErrDigestUnavailable, err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", ErrDigestUnavailable
}

func (c *RegistryClient) validateRegistryURL(ctx context.Context, raw string, mirrored bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if mirrored {
		_, err := normalizeDockerMirrorURLTarget(u)
		return err
	}
	host, err := normalizeHTTPURLTarget(u, c.InsecureHTTP)
	if err != nil {
		return err
	}
	if c.InsecureHTTP {
		return nil
	}
	if !isAllowedDockerRegistryHost(host) {
		return fmt.Errorf("%w: unsupported docker registry host %s", ErrDigestUnavailable, host)
	}
	return c.rejectPrivateHTTPURLTarget(ctx, host)
}

func (c *RegistryClient) validateTokenRealm(ctx context.Context, u *url.URL, registryHost string) error {
	if mirrorBase, ok := c.registryMirrorBaseURL(registryHost); ok {
		mirrorURL, err := url.Parse(mirrorBase)
		if err != nil {
			return err
		}
		host, err := normalizeDockerMirrorURLTarget(u)
		if err != nil {
			return err
		}
		mirrorHost, err := normalizeDockerMirrorURLTarget(mirrorURL)
		if err != nil {
			return err
		}
		if host != mirrorHost {
			return fmt.Errorf("%w: unsupported docker registry token realm host %s", ErrDigestUnavailable, host)
		}
		return nil
	}
	host, err := normalizeHTTPURLTarget(u, c.InsecureHTTP)
	if err != nil {
		return err
	}
	if c.InsecureHTTP {
		return nil
	}
	if !isAllowedDockerTokenRealmHost(registryHost, host) {
		return fmt.Errorf("%w: unsupported docker registry token realm host %s", ErrDigestUnavailable, host)
	}
	return c.rejectPrivateHTTPURLTarget(ctx, host)
}

func normalizeDockerMirrorURLTarget(u *url.URL) (string, error) {
	host, err := normalizeHTTPURLTarget(u, true)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(u.Scheme, "http") && !dockerMirrorHostIsLoopback(u.Hostname()) {
		return "", fmt.Errorf("%w: insecure registry URL scheme %q", ErrDigestUnavailable, u.Scheme)
	}
	if ip := net.ParseIP(strings.Trim(u.Hostname(), "[]")); ip != nil && dockerMirrorIPBlocked(ip) {
		return "", fmt.Errorf("%w: registry mirror host %s is not allowed", ErrDigestUnavailable, host)
	}
	return host, nil
}

func normalizeHTTPURLTarget(u *url.URL, allowHTTP bool) (string, error) {
	if u == nil || u.Host == "" {
		return "", fmt.Errorf("%w: missing registry host", ErrDigestUnavailable)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: registry URL must not include userinfo", ErrDigestUnavailable)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowHTTP {
			return "", fmt.Errorf("%w: insecure registry URL scheme %q", ErrDigestUnavailable, u.Scheme)
		}
	default:
		return "", fmt.Errorf("%w: unsupported registry URL scheme %q", ErrDigestUnavailable, u.Scheme)
	}

	host := normalizeDockerHost(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: missing registry host", ErrDigestUnavailable)
	}
	return host, nil
}

func dockerMirrorHostIsLoopback(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func dockerMirrorIPBlocked(ip net.IP) bool {
	return ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func (c *RegistryClient) rejectPrivateHTTPURLTarget(ctx context.Context, host string) error {
	ips, err := c.lookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: resolve registry host %s: %v", ErrDigestUnavailable, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: registry host %s resolved no addresses", ErrDigestUnavailable, host)
	}
	for _, ip := range ips {
		if isPrivateRegistryIP(ip) {
			return fmt.Errorf("%w: registry host %s resolves to private address %s", ErrDigestUnavailable, host, ip.String())
		}
	}
	return nil
}

func readBoundedTokenResponse(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(dockerBearerTokenResponseLimit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read token response: %v", ErrDigestUnavailable, err)
	}
	if len(data) > dockerBearerTokenResponseLimit {
		return nil, fmt.Errorf("%w: token response too large", ErrDigestUnavailable)
	}
	return data, nil
}

func isAllowedDockerRegistryHost(host string) bool {
	_, ok := allowedDockerRegistryHosts[normalizeDockerHost(host)]
	return ok
}

func isAllowedDockerTokenRealmHost(registryHost, realmHost string) bool {
	registryHost = normalizeDockerHost(registryHost)
	realmHost = normalizeDockerHost(realmHost)
	if !isAllowedDockerRegistryHost(registryHost) {
		return false
	}
	if registryHost == realmHost {
		return true
	}
	allowed, ok := allowedDockerTokenRealmHosts[registryHost]
	if !ok {
		return false
	}
	_, ok = allowed[realmHost]
	return ok
}

func normalizeDockerHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(parsedHost, "[]")
	}
	switch host {
	case "docker.io", "index.docker.io":
		return dockerHubRegistryHost
	default:
		return host
	}
}

func (c *RegistryClient) lookupHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	lookup := c.LookupIP
	if lookup == nil {
		lookup = defaultLookupIP
	}
	return lookup(ctx, host)
}

func defaultLookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

func isPrivateRegistryIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func parseBearerChallenge(raw string) (map[string]string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return nil, false
	}
	raw = strings.TrimSpace(raw[len("Bearer "):])
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.ToLower(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out, len(out) > 0
}
