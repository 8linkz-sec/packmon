package ci

import (
	"os"
	"strings"
	"testing"
)

func TestWebhookTerminologyUsesHMACAuthentication(t *testing.T) {
	t.Parallel()

	files := []string{
		"../../SECURITY.md",
		"../../cmd/packmon/scan.go",
		"../../internal/scanner/webhook.go",
		"../../internal/scanner/webhook_test.go",
	}
	for _, path := range files {
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		for _, forbidden := range []string{
			"webhook signature",
			"HMAC signature",
			"sign payloads",
			"signed with HMAC-SHA256",
			"signature is sent",
			"Sign the payload",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s uses %q; describe the webhook header as HMAC authentication instead", path, forbidden)
			}
		}
	}
}
