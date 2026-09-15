package parser

import (
	"errors"
	"strings"
	"testing"
)

type strictJSONErrorReader struct {
	err error
}

func (r strictJSONErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestDecodeStrictJSON(t *testing.T) {
	t.Parallel()

	t.Run("rejects a second JSON value", func(t *testing.T) {
		t.Parallel()

		var got map[string]string
		err := decodeStrictJSON(strings.NewReader(`{"package":"first"} {"package":"second"}`), &got)
		if err == nil || !strings.Contains(err.Error(), "unexpected trailing data") {
			t.Fatalf("decodeStrictJSON() error = %v, want trailing-data error", err)
		}
	})

	t.Run("adds location to malformed trailing JSON", func(t *testing.T) {
		t.Parallel()

		var got map[string]string
		err := decodeStrictJSON(strings.NewReader("{\n  \"package\": \"safe\"\n} !"), &got)
		if err == nil {
			t.Fatal("decodeStrictJSON() error = nil, want malformed trailing JSON error")
		}
		for _, want := range []string{"line 3", "column 3"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("decodeStrictJSON() error = %q, want %q", err, want)
			}
		}
	})

	t.Run("preserves reader errors", func(t *testing.T) {
		t.Parallel()

		want := errors.New("source unavailable")
		var got map[string]string
		err := decodeStrictJSON(strictJSONErrorReader{err: want}, &got)
		if !errors.Is(err, want) {
			t.Fatalf("decodeStrictJSON() error = %v, want %v", err, want)
		}
	})
}

func TestJSONSyntaxLocationClampsOffsets(t *testing.T) {
	t.Parallel()

	data := []byte("first\nsecond")
	tests := []struct {
		name       string
		offset     int64
		wantLine   int
		wantColumn int
	}{
		{name: "before input", offset: 0, wantLine: 1, wantColumn: 1},
		{name: "after input", offset: int64(len(data)) + 10, wantLine: 2, wantColumn: 6},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			line, column := jsonSyntaxLocation(data, tt.offset)
			if line != tt.wantLine || column != tt.wantColumn {
				t.Fatalf("jsonSyntaxLocation(%d) = (%d, %d), want (%d, %d)", tt.offset, line, column, tt.wantLine, tt.wantColumn)
			}
		})
	}
}
