package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestProxyForwardsOnlyValidatedTestClientIdentity(t *testing.T) {
	observed := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed <- request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(newProxyHandler(target))
	defer proxy.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxy.URL+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(testClientIPHeader, " 192.0.2.40 ")
	request.Header.Set("Forwarded", "for=attacker.example")
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	request.Header.Set("X-Real-IP", "198.51.100.99")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("proxy status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	headers := <-observed
	for key, want := range map[string]string{
		"X-Forwarded-For":   "192.0.2.40",
		"X-Real-IP":         "192.0.2.40",
		"X-Forwarded-Proto": "https",
	} {
		if got := headers.Get(key); got != want {
			t.Fatalf("backend %s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{testClientIPHeader, "Forwarded"} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("backend received stripped header %s = %q", key, got)
		}
	}
}

func TestProxyRejectsInvalidTestClientIdentity(t *testing.T) {
	var backendCalled atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		backendCalled.Store(true)
	}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := newProxyHandler(target)
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set(testClientIPHeader, "not-an-ip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid identity status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if backendCalled.Load() {
		t.Fatal("invalid identity reached backend")
	}
}
