package parser

import (
	"strings"
	"testing"
)

func TestParserErrorsDoNotLeakDependencyCoordinates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		p     Parser
		input string
		leaks []string
	}{
		{
			name: "go.mod malformed require",
			p:    NewGoModParser(),
			input: `module example.com/app

require github.com/acme/private-go-token
`,
			leaks: []string{"github.com/acme/private-go-token", "private-go-token"},
		},
		{
			name: "gradle malformed coordinate",
			p:    NewGradleParser(),
			input: `com.acme.secret:private-gradle-token
`,
			leaks: []string{"com.acme.secret:private-gradle-token", "private-gradle-token"},
		},
		{
			name: "gradle missing version",
			p:    NewGradleParser(),
			input: `com.acme.secret:private-gradle-empty:=compileClasspath
`,
			leaks: []string{"com.acme.secret:private-gradle-empty", "private-gradle-empty"},
		},
		{
			name:  "composer missing version",
			p:     NewComposerParser(),
			input: `{"packages":[{"name":"acme/private-composer-token"}]}`,
			leaks: []string{"acme/private-composer-token", "private-composer-token"},
		},
		{
			name: "cargo missing version",
			p:    NewCargoParser(),
			input: `[[package]]
name = "private-cargo-token"
`,
			leaks: []string{"private-cargo-token"},
		},
		{
			name:  "maven missing version",
			p:     NewMavenParser(),
			input: `<project><dependencies><dependency><groupId>com.acme.secret</groupId><artifactId>private-maven-token</artifactId></dependency></dependencies></project>`,
			leaks: []string{"com.acme.secret:private-maven-token", "private-maven-token"},
		},
		{
			name:  "nuget missing resolved version",
			p:     NewNuGetParser(),
			input: `{"version":1,"dependencies":{"net8.0":{"Private.NuGet.Token":{"type":"Direct"}}}}`,
			leaks: []string{"Private.NuGet.Token"},
		},
		{
			name: "pub missing version",
			p:    NewPubParser(),
			input: `packages:
  private_pub_token:
    source: hosted
`,
			leaks: []string{"private_pub_token"},
		},
		{
			name:  "cran missing version",
			p:     NewCRANParser(),
			input: `{"Packages":{"private.cran.token":{"Package":"private.cran.token"}}}`,
			leaks: []string{"private.cran.token"},
		},
		{
			name: "requirements unpinned",
			p:    NewRequirementsParser(),
			input: `private-pypi-token>=1.0
`,
			leaks: []string{"private-pypi-token"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.p.Parse(strings.NewReader(tt.input))
			if err == nil {
				t.Fatal("Parse() error = nil, want skipped-entry parse error")
			}
			msg := err.Error()
			for _, leak := range tt.leaks {
				if strings.Contains(msg, leak) {
					t.Fatalf("Parse() error leaked %q in %q", leak, msg)
				}
			}
		})
	}
}

func TestDecodeStrictJSONReportsSyntaxLocationWithoutEchoingContent(t *testing.T) {
	t.Parallel()

	input := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/private-json-location-token": {"version": "1.0.0"}
  },
  !
}
`

	_, err := NewNPMParser().Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want syntax error with location")
	}

	msg := err.Error()
	for _, want := range []string{"line 6", "column 3"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Parse() error = %q, want %q", msg, want)
		}
	}
	if strings.Contains(msg, "private-json-location-token") {
		t.Fatalf("Parse() error leaked dependency content: %q", msg)
	}
}
