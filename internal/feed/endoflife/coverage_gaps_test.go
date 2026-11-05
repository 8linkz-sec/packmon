package endoflife

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type failingResponseBody struct{}

func (failingResponseBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingResponseBody) Close() error             { return nil }

func TestFetchProductsFullErrorAndDefaultBranches(t *testing.T) {
	t.Parallel()

	t.Run("invalid request URL", func(t *testing.T) {
		client := &Client{BaseURL: "://bad"}
		if _, _, _, err := client.FetchProductsFull(context.Background(), ""); err == nil {
			t.Fatal("FetchProductsFull() error = nil, want request construction error")
		}
	})

	t.Run("response read error", func(t *testing.T) {
		client := &Client{
			BaseURL: "https://example.test/api/v1",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: failingResponseBody{}}, nil
			})},
		}
		if _, _, _, err := client.FetchProductsFull(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("FetchProductsFull() error = %v, want response read error", err)
		}
	})

	if err := validateProductsResponse(ProductsResponse{Total: -1, Result: []Product{}}); err == nil {
		t.Fatal("validateProductsResponse() error = nil, want negative total rejection")
	}
	client := &Client{}
	if got := client.productsFullURL(); got != defaultBaseURL+"/products/full" {
		t.Fatalf("productsFullURL() = %q", got)
	}
	if got := client.httpClient().Timeout; got == 0 {
		t.Fatal("httpClient() default timeout = 0")
	}
}

func TestMapProductDateAndPackageMapBranches(t *testing.T) {
	t.Parallel()

	fields := []struct {
		name  string
		apply func(*ProductRelease)
	}{
		{"releaseDate", func(r *ProductRelease) { r.ReleaseDate = "invalid" }},
		{"ltsFrom", func(r *ProductRelease) { r.LTSFrom = "invalid" }},
		{"eoasFrom", func(r *ProductRelease) { r.EOASFrom = "invalid" }},
		{"eolFrom", func(r *ProductRelease) { r.EOLFrom = "invalid" }},
		{"discontinuedFrom", func(r *ProductRelease) { r.DiscontinuedFrom = "invalid" }},
		{"eoesFrom", func(r *ProductRelease) { r.EOESFrom = "invalid" }},
	}
	for _, tc := range fields {
		t.Run(tc.name, func(t *testing.T) {
			release := ProductRelease{Name: "1"}
			tc.apply(&release)
			if _, err := mapProduct(Product{Name: "product", Releases: []ProductRelease{release}}); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("mapProduct() error = %v, want %s date error", err, tc.name)
			}
		})
	}

	product := db.LifecycleProduct{ProductSlug: "product"}
	set := make(map[string]struct{})
	addPackageMap(&product, set, db.LifecyclePackageMap{Ecosystem: "npm", Name: "pkg"})
	addPackageMap(&product, set, db.LifecyclePackageMap{Ecosystem: "npm", Name: "pkg"})
	addPackageMap(&product, set, db.LifecyclePackageMap{Name: "missing-ecosystem"})
	if len(product.PackageMaps) != 1 {
		t.Fatalf("PackageMaps = %+v, want one defaulted, deduplicated map", product.PackageMaps)
	}
	if product.PackageMaps[0].ProductSlug != "product" || product.PackageMaps[0].Source != lifecycleSource {
		t.Fatalf("defaulted package map = %+v", product.PackageMaps[0])
	}
}

func TestPURLPartsMalformedAndEscapedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw                        string
		wantType, wantNS, wantName string
	}{
		{raw: "pkg:npm", wantType: "", wantNS: "", wantName: ""},
		{raw: "pkg:npm/%zz", wantType: "npm", wantNS: "", wantName: ""},
		{raw: "pkg:npm/", wantType: "npm", wantNS: "", wantName: ""},
		{raw: "pkg:maven/org.example/demo@1.0?type=jar#src", wantType: "maven", wantNS: "org.example", wantName: "demo"},
	}
	for _, tc := range tests {
		gotType, gotNS, gotName := purlParts(tc.raw)
		if gotType != tc.wantType || gotNS != tc.wantNS || gotName != tc.wantName {
			t.Fatalf("purlParts(%q) = (%q, %q, %q), want (%q, %q, %q)", tc.raw, gotType, gotNS, gotName, tc.wantType, tc.wantNS, tc.wantName)
		}
	}
}
