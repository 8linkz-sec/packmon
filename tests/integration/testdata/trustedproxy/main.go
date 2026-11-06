package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const testClientIPHeader = "X-Packmon-Test-Client-IP"

func main() {
	listenAddr := requiredEnvironment("PACKMON_TEST_PROXY_LISTEN_ADDR")
	target, err := url.Parse(requiredEnvironment("PACKMON_TEST_PROXY_TARGET"))
	if err != nil || target.Scheme != "http" || target.Host == "" {
		log.Fatal("invalid test proxy target")
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           newProxyHandler(target),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func newProxyHandler(target *url.URL) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			clientIP := strings.TrimSpace(request.In.Header.Get(testClientIPHeader))
			request.SetURL(target)
			request.Out.Header.Del(testClientIPHeader)
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Set("X-Forwarded-For", clientIP)
			request.Out.Header.Set("X-Real-IP", clientIP)
			request.Out.Header.Set("X-Forwarded-Proto", "https")
		},
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		clientIP := strings.TrimSpace(request.Header.Get(testClientIPHeader))
		if address, parseErr := netip.ParseAddr(clientIP); parseErr != nil || !address.IsValid() {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(writer, request)
	})
}

func requiredEnvironment(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("missing %s", key)
	}
	return value
}
