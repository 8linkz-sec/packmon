package chocolatey

import (
	"bytes"
	"testing"
)

func FuzzParseConfigXML(f *testing.F) {
	f.Add([]byte(flareConfigXML))
	f.Add([]byte(`<config><packages><package name="x"`))
	f.Add([]byte(`<configuration/>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseConfigXML(bytes.NewReader(data), "config.xml")
	})
}

func FuzzParseScript(f *testing.F) {
	f.Add([]byte("choco install 7zip --version 1.0 -y\n"))
	f.Add([]byte("if ($x) { choco upgrade a b --source=\"x\" }\r\n"))
	f.Add([]byte{0xFF, 0xFE, 'c', 0, 'h', 0})
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseScript(bytes.NewReader(data), "x.ps1")
	})
}
