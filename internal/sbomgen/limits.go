package sbomgen

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/sbom"
)

const (
	maxAutoSBOMManifestBytes     = 1 << 20
	maxGeneratedSBOMBytes        = sbom.MaxSizeBytes
	maxCommandOutputBytes        = 64 << 10
	commandOutputTruncatedMarker = "\n...[truncated]\n"
)

func readAutoSBOMManifest(path string) ([]byte, error) {
	return readFileLimited(path, maxAutoSBOMManifestBytes, "auto-SBOM manifest")
}

func readGeneratedSBOMFile(path string) ([]byte, error) {
	return readFileLimited(path, maxGeneratedSBOMBytes, "SBOM")
}

func readFileLimited(path string, maxBytes int, label string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("%s %s exceeds maximum %s size of %d bytes", label, path, label, maxBytes)
	}

	file, err := os.Open(path) // #nosec G304 -- callers pass paths discovered or reserved by auto-SBOM generation.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%s %s exceeds maximum %s size of %d bytes", label, path, label, maxBytes)
	}
	return data, nil
}

func boundedCommandOutput(raw []byte) []byte {
	if len(raw) <= maxCommandOutputBytes {
		return raw
	}
	out := make([]byte, 0, maxCommandOutputBytes+len(commandOutputTruncatedMarker))
	out = append(out, raw[:maxCommandOutputBytes]...)
	out = append(out, commandOutputTruncatedMarker...)
	return out
}

func commandOutputSummary(raw []byte) string {
	out := logsafe.BoundedDiagnosticValue(string(boundedCommandOutput(raw)), maxCommandOutputBytes)
	if strings.TrimSpace(out) == "" {
		return "<empty>"
	}
	return out
}

type boundedOutputWriter struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (w *boundedOutputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	remaining := maxCommandOutputBytes - len(w.buf)
	if remaining > 0 {
		if len(p) <= remaining {
			w.buf = append(w.buf, p...)
		} else {
			w.buf = append(w.buf, p[:remaining]...)
			w.truncated = true
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

func (w *boundedOutputWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := append([]byte(nil), w.buf...)
	if w.truncated {
		out = append(out, commandOutputTruncatedMarker...)
	}
	return out
}
