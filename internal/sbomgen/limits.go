package sbomgen

import (
	"bytes"
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
	// maxGoListStdoutBytes bounds go list module JSON captured as data via
	// RunOptions.Stdout. It mirrors the generated-SBOM size cap because the
	// module list is SBOM input, not diagnostics; the small diagnostic capture
	// bound would truncate real module lists mid-JSON.
	maxGoListStdoutBytes = maxGeneratedSBOMBytes
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

	return readOpenedFileLimited(file, path, maxBytes, label)
}

func readOpenedFileLimited(file *os.File, path string, maxBytes int, label string) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("%s %s exceeds maximum %s size of %d bytes", label, path, label, maxBytes)
	}

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

// limitedDataBuffer captures command stdout as data up to limit bytes. Unlike
// boundedOutputWriter it never truncates silently: a write beyond the limit
// fails, which aborts the producing command with an explicit error.
type limitedDataBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (b *limitedDataBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("command output exceeds maximum data size of %d bytes", b.limit)
	}
	return b.buf.Write(p)
}

func (b *limitedDataBuffer) Bytes() []byte { return b.buf.Bytes() }

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
