package feed

import (
	"math"
	"testing"
)

func TestParseCVSSVector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vector  string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "critical vector (scope changed, all high)",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			wantMin: 9.0,
			wantMax: 10.0,
		},
		{
			name:    "high vector (no scope change, all high impact)",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			wantMin: 7.0,
			wantMax: 8.9,
		},
		{
			name:    "medium vector (network, high complexity, low impact)",
			vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
			wantMin: 4.0,
			wantMax: 6.9,
		},
		{
			name:    "low vector (local, high complexity, high privileges)",
			vector:  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
			wantMin: 0.1,
			wantMax: 3.9,
		},
		{
			name:    "empty string returns zero",
			vector:  "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "invalid garbage string returns zero",
			vector:  "not-a-cvss-vector",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "malformed vector missing metrics returns zero or low",
			vector:  "CVSS:3.1/AV:N",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "all none impact metrics returns zero",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "CVSS 3.0 prefix also works",
			vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantMin: 9.0,
			wantMax: 10.0,
		},
		{
			name:    "physical access vector reduces score",
			vector:  "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantMin: 4.0,
			wantMax: 7.9,
		},
		{
			name:    "unknown metric value falls back to default",
			vector:  "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantMin: 7.0,
			wantMax: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseCVSSVector(tt.vector)

			if tt.wantMin == 0 && tt.wantMax == 0 {
				if got != 0 {
					t.Fatalf("ParseCVSSVector(%q) = %v, want 0", tt.vector, got)
				}
				return
			}

			if got < tt.wantMin || got > tt.wantMax {
				t.Fatalf("ParseCVSSVector(%q) = %v, want [%v, %v]",
					tt.vector, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestParseCVSSVectorNeverExceedsTen(t *testing.T) {
	t.Parallel()

	// The maximum possible vector should still be capped at 10.0.
	score := ParseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	if score > 10.0 {
		t.Fatalf("score %v exceeds 10.0", score)
	}
}

func TestParseCVSSVectorNeverNegative(t *testing.T) {
	t.Parallel()

	// Even with all unknown/fallback metrics, score must not be negative.
	score := ParseCVSSVector("CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:U/C:?/I:?/A:?")
	if score < 0 {
		t.Fatalf("score %v is negative", score)
	}
}

func TestCVSSToSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		score    float64
		wantSev  string
	}{
		{"critical lower bound", 9.0, "CRITICAL"},
		{"critical exact ten", 10.0, "CRITICAL"},
		{"critical mid", 9.5, "CRITICAL"},
		{"high lower bound", 7.0, "HIGH"},
		{"high upper bound", 8.9, "HIGH"},
		{"high mid", 7.5, "HIGH"},
		{"medium lower bound", 4.0, "MEDIUM"},
		{"medium upper bound", 6.9, "MEDIUM"},
		{"medium mid", 5.5, "MEDIUM"},
		{"low lower bound", 0.1, "LOW"},
		{"low upper bound", 3.9, "LOW"},
		{"low mid", 2.0, "LOW"},
		{"zero is unknown", 0, "UNKNOWN"},
		{"negative is unknown", -1.0, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CVSSToSeverity(tt.score)
			if got != tt.wantSev {
				t.Fatalf("CVSSToSeverity(%v) = %q, want %q", tt.score, got, tt.wantSev)
			}
		})
	}
}

func TestRoundUp1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   float64
		want float64
	}{
		{"exact tenth", 7.5, 7.5},
		{"needs rounding up", 7.51, 7.6},
		{"just above", 7.50001, 7.6},
		{"zero", 0.0, 0.0},
		{"ten", 10.0, 10.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := roundUp1(tt.in)
			if math.Abs(got-tt.want) > 0.001 {
				t.Fatalf("roundUp1(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestPow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base float64
		exp  int
		want float64
	}{
		{"2^3", 2.0, 3, 8.0},
		{"any^0", 5.0, 0, 1.0},
		{"1^100", 1.0, 100, 1.0},
		{"0.5^2", 0.5, 2, 0.25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pow(tt.base, tt.exp)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Fatalf("pow(%v, %d) = %v, want %v", tt.base, tt.exp, got, tt.want)
			}
		})
	}
}

func TestParseCVSSVectorAndSeverityIntegration(t *testing.T) {
	t.Parallel()

	// Verify that parsing a vector and mapping to severity produces consistent
	// results end-to-end.
	tests := []struct {
		vector  string
		wantSev string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "HIGH"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "MEDIUM"},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "LOW"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "UNKNOWN"},
		{"", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.wantSev, func(t *testing.T) {
			t.Parallel()
			score := ParseCVSSVector(tt.vector)
			sev := CVSSToSeverity(score)
			if sev != tt.wantSev {
				t.Fatalf("CVSSToSeverity(ParseCVSSVector(%q)) = %q (score=%v), want %q",
					tt.vector, sev, score, tt.wantSev)
			}
		})
	}
}
