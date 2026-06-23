package plural

import "testing"

func TestCountUsesSingularOnlyForOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		count int
		want  string
	}{
		{0, "0 packages"},
		{1, "1 package"},
		{2, "2 packages"},
	}
	for _, tt := range tests {
		if got := Count(tt.count, "package", "packages"); got != tt.want {
			t.Fatalf("Count(%d) = %q, want %q", tt.count, got, tt.want)
		}
	}
}

func TestWordUsesSingularOnlyForOne(t *testing.T) {
	t.Parallel()

	if got := Word(1, "day", "days"); got != "day" {
		t.Fatalf("Word(1) = %q, want day", got)
	}
	if got := Word(0, "day", "days"); got != "days" {
		t.Fatalf("Word(0) = %q, want days", got)
	}
	if got := Word(2, "day", "days"); got != "days" {
		t.Fatalf("Word(2) = %q, want days", got)
	}
}
