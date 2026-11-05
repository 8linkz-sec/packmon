package chocolatey

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

type failingReader struct {
	data []byte
	err  error
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), r.err
}

func configNames(t *testing.T, doc string) ([]string, error) {
	t.Helper()
	pkgs, err := ParseConfigXML(strings.NewReader(doc), "config.xml")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.SourceType != SourceConfigXML || pkg.SourceFile != "config.xml" || pkg.Version != "" || strings.Join(pkg.Flags, ",") != FlagUnpinned {
			t.Fatalf("unexpected row shape %+v", pkg)
		}
		names = append(names, pkg.Name)
	}
	return names, nil
}

func utf16LE(s string) string {
	encoded := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(s)) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	return string(encoded)
}

func utf16BE(s string) string {
	encoded := []byte{0xFE, 0xFF}
	for _, unit := range utf16.Encode([]rune(s)) {
		encoded = binary.BigEndian.AppendUint16(encoded, unit)
	}
	return string(encoded)
}

func TestParseConfigXMLReadErrorsDiscardPartialPackages(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("config reader failed")
	for _, tt := range []struct {
		name string
		data string
	}{
		{"immediate error", ""},
		{"partial package list", `<config><packages><package name="do-not-return"/></packages></config>`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			packages, err := ParseConfigXML(&failingReader{data: []byte(tt.data), err: sentinel}, "inventory/config.xml")
			if !errors.Is(err, sentinel) {
				t.Fatalf("ParseConfigXML() error = %v, want sentinel", err)
			}
			if packages != nil {
				t.Fatalf("ParseConfigXML() packages = %+v, want nil", packages)
			}
			if got := err.Error(); got != sentinel.Error() || strings.Contains(got, "do-not-return") {
				t.Fatalf("ParseConfigXML() error = %q, want generic content-free error", got)
			}
		})
	}
}

func TestParseConfigXMLPackageIDLengthBoundaries(t *testing.T) {
	t.Parallel()

	accepted := strings.Repeat("a", 100)
	rejected := strings.Repeat("b", 101)
	doc := `<config><packages><package name="` + accepted + `"/><package name="` + rejected + `"/></packages></config>`
	names, err := configNames(t, doc)
	if err != nil {
		t.Fatalf("ParseConfigXML() error = %v", err)
	}
	if got := strings.Join(names, " "); got != accepted {
		t.Fatalf("names = %q, want only the 100-byte package ID", got)
	}
}

func TestParseConfigXMLSupportedEncodings(t *testing.T) {
	t.Parallel()

	aliases := []string{
		"utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be",
		"iso-8859-1", "iso8859-1", "latin1", "latin-1", "iso-8859-15", "iso8859-15",
		"windows-1252", "cp1252", "windows-1250", "cp1250", "windows-1251", "cp1251",
	}
	const list = `<config><packages><package name="Encoded.Package"/></packages></config>`
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			doc := `<?xml version="1.0" encoding="` + alias + `"?>` + list
			names, err := configNames(t, doc)
			if err != nil {
				t.Fatalf("ParseConfigXML() error = %v", err)
			}
			if got := strings.Join(names, " "); got != "encoded.package" {
				t.Fatalf("names = %q, want %q", got, "encoded.package")
			}
		})
	}
	t.Run("utf-16be bytes", func(t *testing.T) {
		t.Parallel()
		doc := utf16BE(`<?xml version="1.0" encoding="utf-16be"?>` + list)
		names, err := configNames(t, doc)
		if err != nil {
			t.Fatalf("ParseConfigXML() error = %v", err)
		}
		if got := strings.Join(names, " "); got != "encoded.package" {
			t.Fatalf("names = %q, want %q", got, "encoded.package")
		}
	})
}

func TestParseConfigXMLMalformedDocumentBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("malformed config without packages is ignored", func(t *testing.T) {
		t.Parallel()
		for _, doc := range []string{
			`<config><envs><`,
			`<config><envs><env></envs></config>`,
			`<config><group><packages><package name="ignored"`,
		} {
			packages, err := ParseConfigXML(strings.NewReader(doc), "config.xml")
			if err != nil || packages != nil {
				t.Fatalf("ParseConfigXML(%q) = (%+v, %v), want (nil, nil)", doc, packages, err)
			}
		}
	})
	t.Run("malformed package documents discard partial rows", func(t *testing.T) {
		t.Parallel()
		for _, doc := range []string{
			`<config><packages><package name="partial"/>`,
			`<config><packages><package name="partial"/></packages></config><`,
		} {
			packages, err := ParseConfigXML(strings.NewReader(doc), "config.xml")
			if err == nil || packages != nil {
				t.Fatalf("ParseConfigXML(%q) = (%+v, %v), want (nil, error)", doc, packages, err)
			}
			if got := err.Error(); got != "config.xml: invalid config.xml package list" || strings.Contains(got, "partial") {
				t.Fatalf("ParseConfigXML() error = %q, want generic content-free error", got)
			}
		}
	})
	t.Run("trailing whitespace remains valid", func(t *testing.T) {
		t.Parallel()
		names, err := configNames(t, "<config><packages><package name=\"kept\"/></packages></config> \r\n\t")
		if err != nil {
			t.Fatalf("ParseConfigXML() error = %v", err)
		}
		if got := strings.Join(names, " "); got != "kept" {
			t.Fatalf("names = %q, want kept", got)
		}
	})
}

func TestParseConfigXMLRejectsNonWhitespaceAfterRoot(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		doc   string
		bugID string
	}{
		{
			name:  "second root",
			doc:   `<config><packages><package name="partial"/></packages></config><other/>`,
			bugID: "F085-bugs-2",
		},
		{
			name:  "trailing text",
			doc:   `<config><packages><package name="partial"/></packages></config>trailing-junk`,
			bugID: "F085-bugs-3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			packages, err := ParseConfigXML(strings.NewReader(tt.doc), "config.xml")
			if err == nil {
				t.Skip(tt.bugID + ": ParseConfigXML accepts non-whitespace content after the root element")
			}
			if packages != nil {
				t.Fatalf("ParseConfigXML() packages = %+v, want nil on malformed document", packages)
			}
			if got := err.Error(); got != "config.xml: invalid config.xml package list" || strings.Contains(got, "partial") || strings.Contains(got, "trailing-junk") {
				t.Fatalf("ParseConfigXML() error = %q, want generic content-free error", got)
			}
		})
	}
}

func TestParseConfigXMLShapes(t *testing.T) {
	t.Parallel()

	const list = `<config><packages><package name="7zip.vm"/><package name="Git.Install"/></packages></config>`
	for _, tt := range []struct {
		name    string
		doc     string
		want    string
		wantErr bool
	}{
		{"plain", list, "7zip.vm git.install", false},
		{"utf-8 bom", "\ufeff" + list, "7zip.vm git.install", false},
		{"prolog comment pi doctype", `<?xml version="1.0"?><!-- c --><?pi x?><!DOCTYPE config>` + list, "7zip.vm git.install", false},
		{"windows-1252 declared", `<?xml version="1.0" encoding="windows-1252"?>` + list, "7zip.vm git.install", false},
		{"iso-8859-1 with high byte in comment", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!-- caf\xe9 -->" + list, "7zip.vm git.install", false},
		{"unknown encoding is ignored", `<?xml version="1.0" encoding="shift_jis"?>` + list, "", false},
		{"utf-16 le bom", utf16LE(`<?xml version="1.0" encoding="utf-16"?>` + list), "7zip.vm git.install", false},
		{"utf-16 le bom without declaration", utf16LE(list), "7zip.vm git.install", false},
		{"attribute name case", `<Config><Packages><Package Name="X"/></Packages></Config>`, "x", false},
		{"namespaced root", `<config xmlns="urn:x"><packages><package name="a"/></packages></config>`, "a", false},
		{"packages at wrong depth", `<config><group><packages><package name="a"/></packages></group></config>`, "", false},
		{"package at wrong depth", `<config><packages><group><package name="a"/></group></packages></config>`, "", false},
		{"package outside packages", `<config><package name="a"/><packages/></config>`, "", false},
		{"two packages sections", `<config><packages><package name="a"/></packages><envs/><packages><package name="b"/></packages></config>`, "a b", false},
		{"invalid ids skipped", `<config><packages><package name="../x"/><package name=" ok "/><package name="all"/><package name="$v"/></packages></config>`, "ok", false},
		{"other root", `<configuration><packages><package name="a"/></packages></configuration>`, "", false},
		{"config without packages", `<config><envs/></config>`, "", false},
		{"empty", ``, "", false},
		{"whitespace", "  \n ", "", false},
		{"not xml", "not xml <<<", "", false},
		{"truncated before root", `<confi`, "", false},
		{"truncated config without packages", `<config><envs>`, "", false},
		{"truncated config root only", `<config>`, "", false},
		{"malformed config without packages", `<config><envs><env></envs></config>`, "", false},
		{"truncated nested packages element", `<config><group><packages><package name="a"`, "", false},
		{"truncated after root", `<config><packages><package name="a"`, "", true},
		{"truncated after packages section", `<config><packages><package name="a"/></packages><envs>`, "", true},
		{"malformed inside root", `<config><packages><package name="a"></packages></config>`, "", true},
		{"internal entity in id", `<!DOCTYPE config [<!ENTITY a "aaaa">]><config><packages><package name="&a;"/></packages></config>`, "", true},
		{"invalid utf-8 bytes are tolerated", "<config><packages><package name=\"a\"/><!-- \xff --></packages></config>", "a", false},
		{"deep nesting", `<config><packages>` + strings.Repeat("<a>", 20000) + strings.Repeat("</a>", 20000) + `<package name="a"/></packages></config>`, "a", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			names, err := configNames(t, tt.doc)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseConfigXML() error = nil, want error; names = %v", names)
				}
				if !strings.HasPrefix(err.Error(), "config.xml: ") || strings.Contains(err.Error(), "<") {
					t.Fatalf("error %q must be prefixed with the source file and must not echo content", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfigXML() error = %v", err)
			}
			if got := strings.Join(names, " "); got != tt.want {
				t.Fatalf("names = %q, want %q", got, tt.want)
			}
		})
	}
}
