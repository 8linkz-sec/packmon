package envfile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParsePreservesCommentsAndOrder(t *testing.T) {
	in := []byte("# header\nA=1\n\nB=two words\n")
	got := Parse(in)
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	if got[0].Key != "" || got[0].Raw != "# header" {
		t.Fatalf("comment not preserved: %#v", got[0])
	}
	if got[1].Key != "A" || got[1].Value != "1" {
		t.Fatalf("A parsed wrong: %#v", got[1])
	}
	if got[3].Key != "B" || got[3].Value != "two words" {
		t.Fatalf("B parsed wrong: %#v", got[3])
	}
}

func TestUpsertUpdatesInPlaceAndAppends(t *testing.T) {
	e := Parse([]byte("A=1\nB=2\n"))
	e = Upsert(e, "A", "9")
	e = Upsert(e, "C", "3")
	if v, _ := Value(e, "A"); v != "9" {
		t.Fatalf("A = %q, want 9", v)
	}
	if v, ok := Value(e, "C"); !ok || v != "3" {
		t.Fatalf("C = %q ok=%v, want 3", v, ok)
	}
	// order: A,B,C
	if e[0].Key != "A" || e[1].Key != "B" || e[2].Key != "C" {
		t.Fatalf("order wrong: %#v", e)
	}
}

func TestRenderIsLFNoBOM(t *testing.T) {
	out := Render(Parse([]byte("A=1\nB=2\n")))
	if bytes.Contains(out, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("BOM present")
	}
	if bytes.Contains(out, []byte("\r")) {
		t.Fatal("CR present")
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("must end with LF")
	}
}

func TestIsBlank(t *testing.T) {
	for _, s := range []string{"", "  ", `""`, `''`} {
		if !IsBlank(s) {
			t.Fatalf("IsBlank(%q) = false, want true", s)
		}
	}
	if IsBlank("x") {
		t.Fatal("IsBlank(x) = true, want false")
	}
}

func TestWriteAtomicAndLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := WriteAtomic(p, []byte("A=1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v, _ := Value(got, "A"); v != "1" {
		t.Fatalf("A = %q, want 1", v)
	}
	// On Unix, verify 0600 permissions; Windows uses a different permission model
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestLoadMissingReturnsNil(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.env"))
	if err != nil || got != nil {
		t.Fatalf("Load(missing) = %#v, %v; want nil, nil", got, err)
	}
}
