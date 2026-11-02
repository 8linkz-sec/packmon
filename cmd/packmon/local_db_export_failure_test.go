package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type localDBPrefixActionWriter struct {
	buffer bytes.Buffer
	prefix string
	action func() error
	fired  bool
	err    error
}

func (w *localDBPrefixActionWriter) Write(data []byte) (int, error) {
	n, err := w.buffer.Write(data)
	if err != nil {
		return n, err
	}
	if !w.fired && strings.Contains(w.buffer.String(), w.prefix) {
		w.fired = true
		w.err = w.action()
	}
	return n, nil
}

func TestExportLocalDBPropagatesEachCollectionFailure(t *testing.T) {
	for _, tt := range []struct {
		field       string
		table       string
		wantContext string
	}{
		{field: "vulnerabilities", table: "vulnerabilities_local", wantContext: "query local vulnerabilities"},
		{field: "malicious", table: "malicious_local", wantContext: "query local malicious findings"},
		{field: "reputation", table: "reputation_findings_local", wantContext: "query local reputation findings"},
		{field: "lifecycle", table: "lifecycle_releases_local", wantContext: "query local lifecycle releases"},
		{field: "scan_history", table: "scan_history", wantContext: "query local scan history"},
	} {
		t.Run(tt.field, func(t *testing.T) {
			store, _ := newTestSQLiteStore(t, t.TempDir())
			writer := &localDBPrefixActionWriter{
				prefix: fmt.Sprintf("\n  %q: ", tt.field),
				action: func() error {
					_, err := store.DB().ExecContext(context.Background(), "DROP TABLE "+tt.table)
					return err
				},
			}

			err := exportLocalDB(context.Background(), store, writer)
			if !writer.fired {
				t.Fatalf("writer never observed field prefix %q in %q", writer.prefix, writer.buffer.String())
			}
			if writer.err != nil {
				t.Fatalf("drop target table: %v", writer.err)
			}
			if err == nil || !strings.Contains(err.Error(), "encode local database export") || !strings.Contains(err.Error(), tt.wantContext) {
				t.Fatalf("exportLocalDB() error = %v, want encode and %q context", err, tt.wantContext)
			}
		})
	}
}

type localDBFragmentFailWriter struct {
	buffer   bytes.Buffer
	fragment []byte
	err      error
	calls    int
}

func (w *localDBFragmentFailWriter) Write(data []byte) (int, error) {
	w.calls++
	if bytes.Equal(data, w.fragment) {
		return 0, w.err
	}
	return w.buffer.Write(data)
}

type localDBRecordingWriter struct {
	buffer bytes.Buffer
	calls  int
}

func (w *localDBRecordingWriter) Write(data []byte) (int, error) {
	w.calls++
	return w.buffer.Write(data)
}

func TestExportLocalDBPropagatesInitialAndFinalFailures(t *testing.T) {
	t.Run("load failure before stream", func(t *testing.T) {
		store, _ := newTestSQLiteStore(t, t.TempDir())
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		writer := &localDBRecordingWriter{}

		err := exportLocalDB(context.Background(), store, writer)
		if err == nil || !strings.Contains(err.Error(), "read local database counts") {
			t.Fatalf("exportLocalDB() error = %v, want pre-stream counts failure", err)
		}
		if writer.calls != 0 || writer.buffer.Len() != 0 {
			t.Fatalf("writer received %d calls and %q, want no stream output", writer.calls, writer.buffer.String())
		}
	})

	for _, tt := range []struct {
		name     string
		fragment string
		assert   func(*testing.T, *localDBFragmentFailWriter)
	}{
		{
			name:     "initial document write",
			fragment: "{\n",
			assert: func(t *testing.T, writer *localDBFragmentFailWriter) {
				t.Helper()
				if writer.buffer.Len() != 0 {
					t.Fatalf("initial-failure output = %q, want empty", writer.buffer.String())
				}
			},
		},
		{
			name:     "final document write",
			fragment: "\n}\n",
			assert: func(t *testing.T, writer *localDBFragmentFailWriter) {
				t.Helper()
				if !strings.Contains(writer.buffer.String(), `"scan_history": []`) {
					t.Fatalf("final-failure output does not contain the completed scan_history field:\n%s", writer.buffer.String())
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestSQLiteStore(t, t.TempDir())
			writeErr := errors.New("sentinel export write failure")
			writer := &localDBFragmentFailWriter{fragment: []byte(tt.fragment), err: writeErr}

			err := exportLocalDB(context.Background(), store, writer)
			if !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "encode local database export") {
				t.Fatalf("exportLocalDB() error = %v, want wrapped sentinel write failure", err)
			}
			tt.assert(t, writer)
		})
	}
}

type localDBWriteRecorder struct {
	writes [][]byte
}

func (w *localDBWriteRecorder) Write(data []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(data))
	return len(data), nil
}

type localDBFailNthWriter struct {
	failureAt int
	calls     int
	err       error
}

func (w *localDBFailNthWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == w.failureAt {
		return 0, w.err
	}
	return len(data), nil
}

func runLocalDBExportStreamScenario(writer interface{ Write([]byte) (int, error) }) error {
	stream := newLocalDBExportJSONStream(writer)
	if err := stream.begin(time.Date(2026, 11, 2, 12, 13, 14, 0, time.UTC), &localDBInfo{
		Path:            "packmon.db",
		Exists:          true,
		Vulnerabilities: 2,
	}); err != nil {
		return err
	}
	if err := stream.writeArrayField("vulnerabilities", func(emit func(any) error) error {
		for _, item := range []map[string]string{
			{"id": "GHSA-one", "summary": "first"},
			{"id": "GHSA-two", "summary": "second"},
		} {
			if err := emit(item); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return stream.end()
}

func TestLocalDBExportJSONStreamPropagatesStageSpecificWriterFailures(t *testing.T) {
	recorder := &localDBWriteRecorder{}
	if err := runLocalDBExportStreamScenario(recorder); err != nil {
		t.Fatalf("record stream scenario: %v", err)
	}
	if len(recorder.writes) != 23 {
		t.Fatalf("stream scenario writes = %d, want exact 23-stage contract", len(recorder.writes))
	}
	if !bytes.Contains(recorder.writes[9], []byte("\n  ")) {
		t.Fatalf("info JSON write = %q, want continued lines indented with two spaces", recorder.writes[9])
	}
	for _, index := range []int{17, 20} {
		if !bytes.Contains(recorder.writes[index], []byte("\n    ")) {
			t.Fatalf("row JSON write %d = %q, want continued lines indented with four spaces", index+1, recorder.writes[index])
		}
	}

	for ordinal := 1; ordinal <= len(recorder.writes); ordinal++ {
		t.Run(fmt.Sprintf("write_%02d", ordinal), func(t *testing.T) {
			writeErr := errors.New("sentinel stage write failure")
			writer := &localDBFailNthWriter{failureAt: ordinal, err: writeErr}

			err := runLocalDBExportStreamScenario(writer)
			if !errors.Is(err, writeErr) {
				t.Fatalf("stream error at write %d = %v, want sentinel", ordinal, err)
			}
			if writer.calls != ordinal {
				t.Fatalf("writer calls = %d, want stop exactly at failing write %d", writer.calls, ordinal)
			}
		})
	}
}

func TestLocalDBExportJSONValueRejectsUnsupportedValues(t *testing.T) {
	var output bytes.Buffer
	err := writeLocalDBExportJSONValue(&output, make(chan int), "  ")
	var unsupported *json.UnsupportedTypeError
	if !errors.As(err, &unsupported) {
		t.Fatalf("writeLocalDBExportJSONValue() error = %v, want json.UnsupportedTypeError", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, want no bytes when marshaling fails", output.String())
	}
}
