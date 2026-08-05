package packageid

import "testing"

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		want      string
	}{
		{ecosystem: "nuget", name: "Newtonsoft.Json", want: "newtonsoft.json"},
		{ecosystem: "NuGet", name: "NuGet.Mixed_Case", want: "nuget.mixed_case"},
		{ecosystem: "pypi", name: "My.Pkg_Name", want: "my-pkg-name"},
		{ecosystem: "PyPI", name: "a..B__c---d", want: "a-b-c-d"},
		{ecosystem: "actions", name: "Actions/Checkout", want: "actions/checkout"},
		{ecosystem: "GitHub Actions", name: "GitHub/CodeQL-Action", want: "github/codeql-action"},
		{ecosystem: "npm", name: "@Scope/Name", want: "@Scope/Name"},
	}

	for _, tt := range tests {
		if got := NormalizeName(tt.ecosystem, tt.name); got != tt.want {
			t.Fatalf("NormalizeName(%q, %q) = %q, want %q", tt.ecosystem, tt.name, got, tt.want)
		}
	}
}
