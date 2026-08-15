package chocolatey

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

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
		{"truncated after root", `<config><packages><package name="a"`, "", true},
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
