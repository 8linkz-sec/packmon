package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestMavenParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewMavenParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"pom.xml", true},
		{"POM.XML", true},   // case-insensitive
		{"Pom.Xml", true},   // case-insensitive
		{"build.gradle", false},
		{"package-lock.json", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestMavenParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewMavenParser().Ecosystem(); got != domain.EcosystemMaven {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemMaven)
	}
}

func TestMavenParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "normal pom.xml with dependencies",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"com.google.guava:guava":             "33.0.0-jre",
				"org.apache.commons:commons-lang3":   "3.14.0",
			},
		},
		{
			name: "pom.xml with dependencyManagement",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>6.1.4</version>
      </dependency>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-web</artifactId>
        <version>6.1.4</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.16.1</version>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"com.fasterxml.jackson.core:jackson-databind": "2.16.1",
				"org.springframework:spring-core":             "6.1.4",
				"org.springframework:spring-web":              "6.1.4",
			},
		},
		{
			name: "skip test scope dependencies",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 1,
			wantPkgs: map[string]string{
				"com.google.guava:guava": "33.0.0-jre",
			},
		},
		{
			name: "skip property placeholders",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
    <dependency>
      <groupId>ch.qos.logback</groupId>
      <artifactId>logback-classic</artifactId>
      <version>${logback.version}</version>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 1,
			wantPkgs: map[string]string{
				"com.google.guava:guava": "33.0.0-jre",
			},
		},
		{
			name: "empty pom.xml",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
</project>`,
			wantCount: 0,
		},
		{
			name:      "minimal pom.xml with no dependencies element",
			input:     `<project></project>`,
			wantCount: 0,
		},
		{
			name:    "invalid XML",
			input:   `{not xml at all`,
			wantErr: true,
		},
		{
			name: "dependency missing version",
			input: `<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>no-version</artifactId>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 1,
			wantPkgs:  map[string]string{"com.google.guava:guava": "33.0.0-jre"},
			wantErr:   true,
		},
		{
			name: "dependency missing groupId",
			input: `<project>
  <dependencies>
    <dependency>
      <artifactId>orphan</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>`,
			wantCount: 1,
			wantPkgs:  map[string]string{"com.google.guava:guava": "33.0.0-jre"},
			wantErr:   true,
		},
		{
			name: "duplicate dependencies are deduplicated",
			input: `<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>33.0.0-jre</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
			wantCount: 1,
			wantPkgs:  map[string]string{"com.google.guava:guava": "33.0.0-jre"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewMavenParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if len(pkgs) != tt.wantCount {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemMaven {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemMaven)
				}
				if wantVer, ok := tt.wantPkgs[pkg.Name]; ok {
					if pkg.Version != wantVer {
						t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
					}
				}
			}
		})
	}
}
