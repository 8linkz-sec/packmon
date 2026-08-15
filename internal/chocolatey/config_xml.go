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
// before the root element, or that carry no <packages> section are silently
// ignored so unrelated config.xml files never produce warnings. A truncated
// or malformed document that already identified itself as a package list is
// reported as an error.
func ParseConfigXML(r io.Reader, sourceFile string) ([]Package, error) {
	decoder := xml.NewDecoder(r)
	decoder.Strict = true

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
