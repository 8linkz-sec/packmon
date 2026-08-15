package parser

import (
	"strings"
	"testing"
)

const actionsEdgeSHA = "11bd71901bbe5b1630ceea73d27597364c9af683"

func TestActionsParserEmptyDocumentsReturnNoPackagesWithoutError(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"empty":            "",
		"whitespace":       "   \n\n",
		"document marker":  "---\n",
		"null document":    "~\n",
		"comment only":     "# nothing here\n",
		"multi doc empty":  "---\n---\n",
		"jobs null":        "jobs:\n",
		"jobs empty map":   "jobs: {}\n",
		"job null":         "jobs:\n  build:\n",
		"steps null":       "jobs:\n  build:\n    steps:\n",
		"steps empty flow": "jobs:\n  build:\n    steps: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			pkgs, err := NewActionsParser().Parse(strings.NewReader(input))
			if err != nil {
				t.Fatalf("Parse(%q) error = %v, want nil", input, err)
			}
			if len(pkgs) != 0 {
				t.Fatalf("Parse(%q) = %+v, want no packages", input, pkgs)
			}
		})
	}
}

func TestActionsParserRejectsNonMappingJobsLikeBefore(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"jobs scalar":   "jobs: 1\n",
		"jobs sequence": "jobs:\n  - build\n",
		"root sequence": "- jobs\n",
		"job scalar":    "jobs:\n  build: nope\n",
		"steps mapping": "jobs:\n  build:\n    steps:\n      uses: actions/checkout@v4\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewActionsParser().Parse(strings.NewReader(input)); err == nil {
				t.Fatalf("Parse(%q) error = nil, want decode error", input)
			}
		})
	}
}

func TestActionsParserReadsOnlyTheFirstDocument(t *testing.T) {
	t.Parallel()

	input := "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + actionsEdgeSHA + " # v4.2.2\n" +
		"---\njobs:\n  b:\n    steps:\n      - uses: actions/setup-go@v5\n"
	pkgs, err := NewActionsParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "actions/checkout" || pkgs[0].DeclaredVersion != "v4.2.2" {
		t.Fatalf("Parse(multi-doc) = %+v, want only the first document's checkout pin with hint", pkgs)
	}
}

func TestActionsParserDeclaredVersionCommentPlacement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  map[string]string // name -> declared version
	}{
		{
			name: "comment on the next line does not attach",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - uses: actions/checkout@" + actionsEdgeSHA + "\n" +
				"        # v4.2.2\n" +
				"      - uses: actions/setup-go@" + actionsEdgeSHA + "\n" +
				"      # v9.9.9\n" +
				"      - run: echo\n",
			want: map[string]string{"actions/checkout": "", "actions/setup-go": ""},
		},
		{
			name: "comment on the following key line does not attach",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - uses: actions/checkout@" + actionsEdgeSHA + "\n" +
				"        with: # v4.2.2\n          fetch-depth: 0\n",
			want: map[string]string{"actions/checkout": ""},
		},
		{
			name:  "flow sequence trailing comment does not attach to the uses scalar",
			input: "jobs:\n  build:\n    steps: [{uses: \"actions/checkout@" + actionsEdgeSHA + "\"}] # v4\n",
			want:  map[string]string{"actions/checkout": ""},
		},
		{
			name:  "flow mapping trailing comment does not attach to the uses scalar",
			input: "jobs:\n  build:\n    steps:\n      - {uses: actions/checkout@" + actionsEdgeSHA + "} # v4.2.2\n",
			want:  map[string]string{"actions/checkout": ""},
		},
		{
			name: "hash inside quoted value is not a comment",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - uses: \"actions/checkout@" + actionsEdgeSHA + " # v4.2.2\"\n",
			// The whole quoted scalar is the ref (version "<sha> # v4.2.2"), so
			// it is not a SHA pin and carries no hint.
			want: map[string]string{"actions/checkout": ""},
		},
		{
			name: "trailing spaces before the comment",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - uses:   actions/checkout@" + actionsEdgeSHA + "     #   v4.2.2   \n",
			want: map[string]string{"actions/checkout": "v4.2.2"},
		},
		{
			name: "anchor and alias share the pin and the hint",
			input: "jobs:\n  a:\n    steps:\n" +
				"      - uses: &co actions/checkout@" + actionsEdgeSHA + " # v4.2.2\n" +
				"  b:\n    steps:\n      - uses: *co\n",
			want: map[string]string{"actions/checkout": "v4.2.2"},
		},
		{
			name: "alias without a comment on the anchor stays undeclared",
			input: "x: &co actions/checkout@" + actionsEdgeSHA + "\njobs:\n  a:\n    steps:\n" +
				"      - uses: *co # v4.2.2\n",
			want: map[string]string{"actions/checkout": ""},
		},
		{
			name:  "tag pin comment is ignored",
			input: "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4 # v4.2.2\n",
			want:  map[string]string{"actions/checkout": ""},
		},
		{
			name:  "short sha is not treated as a sha pin",
			input: "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@11bd719 # v4.2.2\n",
			want:  map[string]string{"actions/checkout": ""},
		},
		{
			name:  "job-level reusable workflow with hint",
			input: "jobs:\n  reuse:\n    uses: octo/reusable/.github/workflows/ci.yml@" + actionsEdgeSHA + " # v1.4.0\n",
			want:  map[string]string{"octo/reusable": "v1.4.0"},
		},
		{
			name:  "job-level uses inside a flow mapping",
			input: "jobs:\n  reuse: {uses: octo/reusable/.github/workflows/ci.yml@" + actionsEdgeSHA + "} # v1.4.0\n",
			want:  map[string]string{"octo/reusable": ""},
		},
		{
			name: "same hint text inside a run block does not leak",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - run: |\n          echo uses: actions/checkout@" + actionsEdgeSHA + " # v9.9.9\n" +
				"      - uses: actions/checkout@" + actionsEdgeSHA + "\n",
			want: map[string]string{"actions/checkout": ""},
		},
		{
			name: "uses key with a comment on the value under a with mapping is not a step uses",
			input: "jobs:\n  build:\n    steps:\n" +
				"      - uses: actions/checkout@" + actionsEdgeSHA + "\n" +
				"        with:\n          uses: actions/checkout@" + actionsEdgeSHA + " # v4.2.2\n",
			want: map[string]string{"actions/checkout": ""},
		},
		{
			name:  "utf8 bom and crlf",
			input: "\ufeffjobs:\r\n  build:\r\n    steps:\r\n      - uses: actions/checkout@" + actionsEdgeSHA + " # v4.2.2\r\n",
			want:  map[string]string{"actions/checkout": "v4.2.2"},
		},
		{
			name:  "uppercase sha keeps hint",
			input: "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + strings.ToUpper(actionsEdgeSHA) + " # v4.2.2\n",
			want:  map[string]string{"actions/checkout": "v4.2.2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := NewActionsParser().Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			got := map[string]string{}
			for _, pkg := range pkgs {
				got[pkg.Name] = pkg.DeclaredVersion
			}
			if len(got) != len(tt.want) {
				t.Fatalf("packages = %+v, want names %v", pkgs, tt.want)
			}
			for name, declared := range tt.want {
				actual, ok := got[name]
				if !ok {
					t.Fatalf("missing package %q in %+v", name, pkgs)
				}
				if actual != declared {
					t.Errorf("package %q declared version = %q, want %q", name, actual, declared)
				}
			}
		})
	}
}
