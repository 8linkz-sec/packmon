package endoflife

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL   = "https://endoflife.date/api/v1"
	defaultUserAgent = "packmon-server"
	maxResponseSize  = 100 << 20
)

// ErrHTTPStatus identifies non-success upstream HTTP responses.
var ErrHTTPStatus = errors.New("endoflife http status")

// Client fetches lifecycle data from the endoflife.date v1 API.
type Client struct {
	BaseURL    string
	UserAgent  string
	HTTPClient *http.Client
}

type ProductsResponse struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   string    `json:"generated_at"`
	Total         int       `json:"total"`
	Result        []Product `json:"result"`
}

type Product struct {
	Name        string           `json:"name"`
	Label       string           `json:"label"`
	Category    string           `json:"category"`
	Identifiers []Identifier     `json:"identifiers"`
	Releases    []ProductRelease `json:"releases"`
}

type Identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ProductVersion struct {
	Name string `json:"name"`
	Date string `json:"date"`
	Link string `json:"link"`
}

type ProductRelease struct {
	Name             string          `json:"name"`
	ReleaseDate      string          `json:"releaseDate"`
	IsLTS            bool            `json:"isLts"`
	LTSFrom          string          `json:"ltsFrom"`
	IsEOAS           bool            `json:"isEoas"`
	EOASFrom         string          `json:"eoasFrom"`
	IsEOL            bool            `json:"isEol"`
	EOLFrom          string          `json:"eolFrom"`
	IsDiscontinued   bool            `json:"isDiscontinued"`
	DiscontinuedFrom string          `json:"discontinuedFrom"`
	IsEOES           *bool           `json:"isEoes"`
	EOESFrom         string          `json:"eoesFrom"`
	IsMaintained     bool            `json:"isMaintained"`
	Latest           *ProductVersion `json:"latest"`
}

// FetchProductsFull downloads /products/full. The bool return value is true
// when the server replied 304 Not Modified.
func (c *Client) FetchProductsFull(ctx context.Context, etag string) (ProductsResponse, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.productsFullURL(), nil)
	if err != nil {
		return ProductsResponse{}, "", false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent())
	if strings.TrimSpace(etag) != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return ProductsResponse{}, "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	respETag := resp.Header.Get("ETag")
	if resp.StatusCode == http.StatusNotModified {
		if respETag == "" {
			respETag = etag
		}
		return ProductsResponse{}, respETag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return ProductsResponse{}, respETag, false, fmt.Errorf("%w: %d", ErrHTTPStatus, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return ProductsResponse{}, respETag, false, err
	}
	if len(body) > maxResponseSize {
		return ProductsResponse{}, respETag, false, fmt.Errorf("endoflife response exceeds %d bytes", maxResponseSize)
	}

	var out ProductsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return ProductsResponse{}, respETag, false, err
	}
	return out, respETag, false, nil
}

func (c *Client) productsFullURL() string {
	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return baseURL + "/products/full"
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) userAgent() string {
	if value := strings.TrimSpace(c.UserAgent); value != "" {
		return value
	}
	return defaultUserAgent
}
