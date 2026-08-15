package chocolatey

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// packageIDPattern matches Chocolatey/NuGet package IDs: leading
// alphanumeric, then alphanumerics, dots, dashes, underscores.
var packageIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// normalizePackageID lowercases and validates a Chocolatey package ID.
func normalizePackageID(raw string) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" || len(id) > 100 || !packageIDPattern.MatchString(id) {
		return "", false
	}
	id = strings.ToLower(id)
	if id == "all" { // choco meta target, not a package
		return "", false
	}
	return id, true
}

// ParseConfigXML parses a FLARE-VM / VM-Packages style package list:
//
//	<config>
//	  <packages>
//	    <package name="7zip.vm"/>
//	  </packages>
//	</config>
//
// Files whose root element is not <config>, that are not well-formed XML
// before the root element, that declare an unsupported character encoding, or
// that carry no <packages> section are silently ignored so unrelated
// config.xml files never produce warnings. A truncated or malformed document
// that already identified itself as a package list is reported as an error.
// UTF-8/UTF-16 byte-order marks and ASCII-compatible single-byte encodings
// are tolerated; invalid byte sequences are replaced, never reported.
func ParseConfigXML(r io.Reader, sourceFile string) ([]Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoder(strings.NewReader(decodeTextBytes(data)))
	decoder.Strict = true
	decoder.CharsetReader = asciiCompatibleCharsetReader

	sawRoot := false
	depth := 0
	inPackages := false
	var packages []Package
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if !sawRoot {
				return nil, nil
			}
			return nil, fmt.Errorf("%s: invalid config.xml package list", sourceFile)
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			name := strings.ToLower(t.Name.Local)
			if depth == 1 {
				if name != "config" {
					return nil, nil
				}
				sawRoot = true
				continue
			}
			if depth == 2 && name == "packages" {
				inPackages = true
				continue
			}
			if depth == 3 && inPackages && name == "package" {
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Name.Local, "name") {
						if id, ok := normalizePackageID(attr.Value); ok {
							packages = append(packages, Package{
								Name:       id,
								SourceFile: sourceFile,
								SourceType: SourceConfigXML,
								Flags:      []string{FlagUnpinned},
							})
						}
						break
					}
				}
			}
		case xml.EndElement:
			if depth == 2 && inPackages {
				inPackages = false
			}
			depth--
		}
	}
	if !sawRoot {
		return nil, nil
	}
	return packages, nil
}

// asciiCompatibleCharsetReader accepts XML encoding declarations that are
// ASCII-compatible (package IDs are ASCII) and passes the already
// UTF-8-sanitized input through unchanged. Any other declared charset makes
// the decoder fail before the root element, so the file is ignored silently.
func asciiCompatibleCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be",
		"iso-8859-1", "iso8859-1", "latin1", "latin-1", "iso-8859-15", "iso8859-15",
		"windows-1252", "cp1252", "windows-1250", "cp1250", "windows-1251", "cp1251":
		return input, nil
	}
	return nil, fmt.Errorf("unsupported charset")
}
