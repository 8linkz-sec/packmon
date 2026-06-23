//go:build integration

package integration

import (
	"io"
	"net/http"
	"time"
)

const integrationHTTPTimeout = 5 * time.Second

var integrationHTTPClient = &http.Client{Timeout: integrationHTTPTimeout}

func integrationHTTPGet(url string) (*http.Response, error) {
	return integrationHTTPClient.Get(url)
}

func integrationHTTPPost(url, contentType string, body io.Reader) (*http.Response, error) {
	return integrationHTTPClient.Post(url, contentType, body)
}

func integrationHTTPDo(req *http.Request) (*http.Response, error) {
	return integrationHTTPClient.Do(req)
}
