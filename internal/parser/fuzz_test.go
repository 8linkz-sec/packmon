package parser

import (
	"bytes"
	"testing"
)

// Fuzz targets for all parsers. The goal is to ensure no parser panics on
// arbitrary input. Errors are expected and acceptable; panics are not.

func FuzzNPMParser(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion": 3, "packages": {"node_modules/foo": {"version": "1.0.0"}}}`))
	f.Add([]byte(`{"lockfileVersion": 1, "dependencies": {"bar": {"version": "2.0.0"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewNPMParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzYarnParser(f *testing.F) {
	f.Add([]byte("# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n"))
	f.Add([]byte("\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewYarnParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzPnpmParser(f *testing.F) {
	f.Add([]byte("lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewPnpmParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzPipfileParser(f *testing.F) {
	f.Add([]byte(`{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewPipfileParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzPoetryParser(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewPoetryParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzUVParser(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"httpx\"\nversion = \"0.27.0\"\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewUVParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzRequirementsParser(f *testing.F) {
	f.Add([]byte("requests==2.31.0\nflask==3.0.0\n"))
	f.Add([]byte("# comment\n-i https://pypi.org/simple\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewRequirementsParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzGoSumParser(f *testing.F) {
	f.Add([]byte("golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewGoSumParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzGoModParser(f *testing.F) {
	f.Add([]byte("module example.com/mod\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.7\n)\n"))
	f.Add([]byte("module example.com/mod\n\nrequire golang.org/x/text v0.3.7\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewGoModParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzCargoParser(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewCargoParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzNuGetParser(f *testing.F) {
	f.Add([]byte(`{"version": 2, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewNuGetParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzComposerParser(f *testing.F) {
	f.Add([]byte(`{"packages": [{"name": "monolog/monolog", "version": "v3.5.0"}], "packages-dev": []}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewComposerParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzGemParser(f *testing.F) {
	f.Add([]byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.5)\n\nPLATFORMS\n  ruby\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewGemParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzPubParser(f *testing.F) {
	f.Add([]byte("packages:\n  http:\n    version: \"1.2.1\"\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewPubParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzCocoaPodsParser(f *testing.F) {
	f.Add([]byte("PODS:\n  - Alamofire (5.9.0)\n\nDEPENDENCIES:\n  - Alamofire\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewCocoaPodsParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzSwiftPMParser(f *testing.F) {
	f.Add([]byte(`{"version": 2, "pins": [{"identity": "alamofire", "location": "https://github.com/Alamofire/Alamofire.git", "state": {"version": "5.9.0", "revision": "abc"}}]}`))
	f.Add([]byte(`{"version": 1, "object": {"pins": [{"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire.git", "state": {"version": "5.9.0", "revision": "abc", "branch": null}}]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewSwiftPMParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzHexParser(f *testing.F) {
	f.Add([]byte(`%{` + "\n" + `  "jason": {:hex, :jason, "1.4.1", "hash", [:mix], [], "hexpm", "hash"},` + "\n" + `}` + "\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewHexParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzCRANParser(f *testing.F) {
	f.Add([]byte(`{"Packages": {"dplyr": {"Package": "dplyr", "Version": "1.1.4"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewCRANParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzMavenParser(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><project><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.0.0-jre</version></dependency></dependencies></project>`))
	f.Add([]byte(`<project><dependencyManagement><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>6.1.4</version></dependency></dependencies></dependencyManagement></project>`))
	f.Add([]byte(`<project></project>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewMavenParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzGradleParser(f *testing.F) {
	f.Add([]byte("# This is a Gradle generated file\ncom.google.guava:guava:33.0.0-jre=compileClasspath\nempty=\n"))
	f.Add([]byte("org.apache.commons:commons-lang3:3.14.0=runtimeClasspath\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewGradleParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}

func FuzzActionsParser(f *testing.F) {
	f.Add([]byte("name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"))
	f.Add([]byte("jobs:\n  reuse:\n    uses: octo-org/reusable/.github/workflows/build.yml@v2\n"))
	f.Add([]byte("jobs:\n  build:\n    steps:\n      - uses: docker://alpine:3\n      - uses: ./local-action\n"))
	f.Add([]byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"))
	f.Add([]byte("jobs:\n  build:\n    steps: [{uses: \"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\"}] # v4\n  jobs: 1\n"))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewActionsParser()
		_, _ = p.Parse(bytes.NewReader(data))
	})
}
