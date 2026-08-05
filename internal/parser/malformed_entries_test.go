package parser

import (
	"strings"
	"testing"
)

// A lock file is attacker-adjacent input: it ships with the repository being
// scanned. These tests cover the guards that keep a malformed entry from
// becoming a package Packmon then queries advisory feeds for -- a package with
// an empty name or version matches nothing and would show up as a phantom row in
// the report.

// TestGradleParserRejectsIncompleteCoordinates covers the group/artifact/version
// guards. Gradle lock lines are `group:artifact:version=configurations`, and a
// blank component makes the coordinate unusable.
func TestGradleParserRejectsIncompleteCoordinates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{name: "blank group", line: " :artifact:1.0.0=compile", want: "empty group or artifact"},
		{name: "blank artifact", line: "com.example: :1.0.0=compile", want: "empty group or artifact"},
		{name: "both blank", line: " : :1.0.0=compile", want: "empty group or artifact"},
		{name: "blank version", line: "com.example:artifact: =compile", want: "missing version"},
		{name: "too few parts", line: "com.example:artifact=compile", want: "expected group:artifact:version"},
	} {
		packages, err := NewGradleParser().Parse(strings.NewReader(tc.line + "\n"))
		if err == nil {
			t.Errorf("%s: parsed %d packages without an error", tc.name, len(packages))
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, tc.want)
		}
		if len(packages) != 0 {
			t.Errorf("%s: produced %d packages from an unusable line", tc.name, len(packages))
		}
	}
}

// TestGradleParserAcceptsAWellFormedLockFile is the control, so the rejection
// tests above cannot pass by rejecting everything. It also pins that a valid
// entry survives alongside an invalid one -- one bad line must not discard the
// whole file.
func TestGradleParserAcceptsAWellFormedLockFile(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"# This is a Gradle dependency lock file",
		"empty=",
		"",
		"com.example:library:1.2.3=compileClasspath,runtimeClasspath",
		" :broken:1.0.0=compileClasspath",
		"org.example:other:4.5.6=runtimeClasspath",
	}, "\n")

	packages, err := NewGradleParser().Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("the malformed line produced no error")
	}
	if len(packages) != 2 {
		t.Fatalf("parsed %d packages, want the two valid entries kept", len(packages))
	}
	if packages[0].Name != "com.example:library" || packages[0].Version != "1.2.3" {
		t.Errorf("first package = %+v, want the coordinate joined", packages[0])
	}
}

// TestNuGetParserRejectsAnUnusablePackageName covers the guard after name
// normalisation. NuGet names are matched case-insensitively, so a name that
// normalises to nothing cannot be looked up and must be reported rather than
// stored.
func TestNuGetParserRejectsAnUnusablePackageName(t *testing.T) {
	t.Parallel()

	input := `{
	  "version": 1,
	  "dependencies": {
	    "net8.0": {
	      "   ": {"type": "Direct", "resolved": "1.0.0"},
	      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}
	    }
	  }
	}`

	packages, err := NewNuGetParser().Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("a blank package name was accepted")
	}
	if !strings.Contains(err.Error(), "empty package name") {
		t.Fatalf("error = %v, want it to name the empty package", err)
	}
	// The usable entry alongside it must still be parsed.
	if len(packages) != 1 || !strings.EqualFold(packages[0].Name, "newtonsoft.json") {
		t.Fatalf("packages = %+v, want the valid entry kept", packages)
	}
}

// TestHexTupleFieldsHandlesEscapedQuotes covers the field splitter's string
// state machine. A backslash-escaped quote inside a Hex lock tuple must not end
// the string, or every field after it shifts by one and the parser reads a
// checksum as a version.
func TestHexTupleFieldsHandlesEscapedQuotes(t *testing.T) {
	t.Parallel()

	line := `"pkg": {:hex, :pkg, "1.2.3", "checksum", ["mix"], [], "hexpm", "with \" quote"},`
	fields := hexTupleFields(line)
	if len(fields) < 7 {
		t.Fatalf("split into %d fields, want at least 7: %q", len(fields), fields)
	}
	if !strings.Contains(fields[1], "1.2.3") {
		t.Errorf("field 1 = %q, want the version", fields[1])
	}
	if !strings.Contains(fields[6], `\"`) {
		t.Errorf("field 6 = %q, want the escaped quote preserved inside the string", fields[6])
	}
}

// TestHexTupleFieldsIgnoresLinesWithoutATuple keeps ordinary lock-file lines
// from being split into phantom fields.
func TestHexTupleFieldsIgnoresLinesWithoutATuple(t *testing.T) {
	t.Parallel()

	for _, line := range []string{"", "%{", "}", `"pkg": {:git, "https://example.test"},`} {
		if fields := hexTupleFields(line); fields != nil {
			t.Errorf("hexTupleFields(%q) = %q, want nil", line, fields)
		}
	}
}

// TestHexParserKeepsValidEntriesFromAMixedLockFile pins that the Hex parser is
// resilient in the same way: an unrecognised line is skipped, not fatal.
func TestHexParserKeepsValidEntriesFromAMixedLockFile(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"%{",
		`  "jason": {:hex, :jason, "1.4.1", "abc", [:mix], [], "hexpm", "def"},`,
		`  "local_dep": {:path, "../local"},`,
		`  "plug": {:hex, :plug, "1.15.2", "ghi", [:mix], [], "hexpm", "jkl"},`,
		"}",
	}, "\n")

	packages, err := NewHexParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	names := map[string]string{}
	for _, pkg := range packages {
		names[pkg.Name] = pkg.Version
	}
	if names["jason"] != "1.4.1" || names["plug"] != "1.15.2" {
		t.Fatalf("packages = %v, want both hex entries with their versions", names)
	}
	if _, ok := names["local_dep"]; ok {
		t.Error("a non-hex dependency was reported as a hex package")
	}
}
