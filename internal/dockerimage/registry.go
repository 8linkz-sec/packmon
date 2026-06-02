package dockerimage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

var ErrDigestUnavailable = errors.New("docker registry digest unavailable")

type RegistryClient struct {
	HTTP         *http.Client
	InsecureHTTP bool
}

func NewRegistryClient(client *http.Client) *RegistryClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &RegistryClient{HTTP: client}
}

func (c *RegistryClient) ResolveDigest(ctx context.Context, ref Ref) (string, error) {
	if ref.Registry == "" || ref.Repository == "" || ref.Reference == "" || strings.HasPrefix(ref.Name, "local/") {
		return "", ErrDigestUnavailable
	}
	digest, challenge, err := c.resolveDigestOnce(ctx, ref, "")
	if err == nil || challenge == "" {
		return digest, err
	}
	token, tokenErr := c.fetchBearerToken(ctx, challenge)
	if tokenErr != nil {
		return "", tokenErr
	}
	return c.resolveDigestOnceNoChallenge(ctx, ref, token)
}

func (c *RegistryClient) resolveDigestOnce(ctx context.Context, ref Ref, token string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.manifestURL(ref), nil)
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
	defer resp.Body.Close()
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

func (c *RegistryClient) manifestURL(ref Ref) string {
	scheme := "https"
	if c.InsecureHTTP {
		scheme = "http"
	}
	return scheme + "://" + ref.Registry + "/v2/" + ref.Repository + "/manifests/" + url.PathEscape(ref.Reference)
}

func (c *RegistryClient) fetchBearerToken(ctx context.Context, challenge string) (string, error) {
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
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: token status %d", ErrDigestUnavailable, resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", ErrDigestUnavailable
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
