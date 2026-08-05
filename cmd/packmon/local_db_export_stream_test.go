package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestLocalDBExportJSONStreamProducesValidJSON is the load-bearing test for the
// export stream. It writes JSON by hand -- braces, commas and indentation are
// assembled from string literals rather than by encoding/json -- so the only
// assertion that matters is that the result parses and carries every field.
func TestLocalDBExportJSONStreamProducesValidJSON(t *testing.T) {
	t.Parallel()

	generatedAt := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	info := &localDBInfo{
		Path:            "local.db",
		Exists:          true,
		Vulnerabilities: 3,
		Malicious:       1,
	}

	var buf bytes.Buffer
	stream := newLocalDBExportJSONStream(&buf)
	if err := stream.begin(generatedAt, info); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stream.writeArrayField("vulnerabilities", func(emit func(any) error) error {
		for _, id := range []string{"GHSA-1", "GHSA-2", "GHSA-3"} {
			if err := emit(map[string]string{"id": id}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("writeArrayField: %v", err)
	}
	if err := stream.end(); err != nil {
		t.Fatalf("end: %v", err)
	}

	var decoded struct {
		GeneratedAt time.Time `json:"generated_at"`
		Info        struct {
			Path            string `json:"path"`
			Exists          bool   `json:"exists"`
			Vulnerabilities int    `json:"vulnerabilities"`
		} `json:"info"`
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("stream produced invalid JSON: %v\n%s", err, buf.String())
	}
	if !decoded.GeneratedAt.Equal(generatedAt) {
		t.Errorf("generated_at = %v, want %v", decoded.GeneratedAt, generatedAt)
	}
	if decoded.Info.Path != "local.db" || !decoded.Info.Exists || decoded.Info.Vulnerabilities != 3 {
		t.Errorf("info = %+v, want the supplied values", decoded.Info)
	}
	if len(decoded.Vulnerabilities) != 3 {
		t.Fatalf("decoded %d array entries, want 3", len(decoded.Vulnerabilities))
	}
	if decoded.Vulnerabilities[0].ID != "GHSA-1" || decoded.Vulnerabilities[2].ID != "GHSA-3" {
		t.Errorf("array entries = %+v, want them in emit order", decoded.Vulnerabilities)
	}
}

// TestLocalDBExportJSONStreamEmitsAnEmptyArrayNotNull covers the zero-item path.
// An array field with no rows must still be `[]`, because a consumer iterating
// the export would otherwise have to special-case a missing key.
func TestLocalDBExportJSONStreamEmitsAnEmptyArrayNotNull(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	stream := newLocalDBExportJSONStream(&buf)
	if err := stream.begin(time.Now().UTC(), &localDBInfo{}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stream.writeArrayField("malicious", func(func(any) error) error { return nil }); err != nil {
		t.Fatalf("writeArrayField: %v", err)
	}
	if err := stream.end(); err != nil {
		t.Fatalf("end: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("stream produced invalid JSON: %v\n%s", err, buf.String())
	}
	raw, ok := decoded["malicious"]
	if !ok {
		t.Fatal("empty array field was omitted entirely")
	}
	if string(raw) != "[]" {
		t.Fatalf("malicious = %s, want []", raw)
	}
}

// TestLocalDBExportJSONStreamSeparatesEveryField guards the comma placement
// between top-level fields, which is the failure mode hand-written JSON is most
// prone to: a missing or doubled comma only shows up once several fields exist.
func TestLocalDBExportJSONStreamSeparatesEveryField(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	stream := newLocalDBExportJSONStream(&buf)
	if err := stream.begin(time.Now().UTC(), &localDBInfo{}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for _, name := range []string{"vulnerabilities", "malicious", "reputation", "lifecycle"} {
		field := name
		if err := stream.writeArrayField(field, func(emit func(any) error) error {
			return emit(map[string]string{"field": field})
		}); err != nil {
			t.Fatalf("writeArrayField(%s): %v", field, err)
		}
	}
	if err := stream.end(); err != nil {
		t.Fatalf("end: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("stream produced invalid JSON: %v\n%s", err, buf.String())
	}
	for _, name := range []string{"generated_at", "info", "vulnerabilities", "malicious", "reputation", "lifecycle"} {
		if _, ok := decoded[name]; !ok {
			t.Errorf("field %q missing from the export", name)
		}
	}
	if strings.Contains(buf.String(), ",,") {
		t.Errorf("export contains a doubled comma:\n%s", buf.String())
	}
}

// TestLocalDBExportJSONStreamRefusesANilStreamFunction keeps a programming error
// from producing a truncated but syntactically valid export.
func TestLocalDBExportJSONStreamRefusesANilStreamFunction(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	stream := newLocalDBExportJSONStream(&buf)
	err := stream.writeArrayField("vulnerabilities", nil)
	if err == nil {
		t.Fatal("writeArrayField(nil stream) error = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "vulnerabilities") {
		t.Fatalf("error = %v, want it to name the field", err)
	}
}

// TestLocalDBExportJSONStreamPropagatesStreamErrors covers the failure path: an
// error from the row source must surface instead of ending up as a silently
// short export.
func TestLocalDBExportJSONStreamPropagatesStreamErrors(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("row source failed")
	var buf bytes.Buffer
	stream := newLocalDBExportJSONStream(&buf)

	err := stream.writeArrayField("vulnerabilities", func(emit func(any) error) error {
		if err := emit(map[string]string{"id": "GHSA-1"}); err != nil {
			return err
		}
		return sourceErr
	})
	if !errors.Is(err, sourceErr) {
		t.Fatalf("writeArrayField error = %v, want the source failure", err)
	}
}

// TestLocalDBExportJSONStreamPropagatesWriterErrors covers the other half: a
// failing destination -- a full disk, a closed pipe -- must be reported rather
// than leaving a half-written export behind.
func TestLocalDBExportJSONStreamPropagatesWriterErrors(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("disk full")
	stream := newLocalDBExportJSONStream(failingWriter{err: writeErr})

	if err := stream.begin(time.Now().UTC(), &localDBInfo{}); !errors.Is(err, writeErr) {
		t.Fatalf("begin error = %v, want the writer failure", err)
	}
	if err := stream.end(); !errors.Is(err, writeErr) {
		t.Fatalf("end error = %v, want the writer failure", err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
