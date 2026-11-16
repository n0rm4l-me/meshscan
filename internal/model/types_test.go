package model

import "testing"

func TestSeverityString(t *testing.T) {
	tests := map[Severity]string{
		SeverityCritical: "CRITICAL",
		SeverityHigh:     "HIGH",
		SeverityMedium:   "MEDIUM",
		SeverityLow:      "LOW",
		Severity(42):     "UNKNOWN",
	}
	for sev, want := range tests {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(sev), got, want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for i, sev := range order {
		for j, threshold := range order {
			// A severity is "at least" a threshold when it is as severe or more severe.
			if got, want := sev.AtLeast(threshold), i <= j; got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", sev, threshold, got, want)
			}
		}
	}
}

func TestParseSeverity(t *testing.T) {
	valid := map[string]Severity{
		"critical": SeverityCritical,
		"CRITICAL": SeverityCritical,
		" High ":   SeverityHigh,
		"Medium":   SeverityMedium,
		"low":      SeverityLow,
	}
	for in, want := range valid {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "none", "fatal", "crit"} {
		if _, err := ParseSeverity(in); err == nil {
			t.Errorf("ParseSeverity(%q) succeeded, want error", in)
		}
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		got, err := ParseSeverity(sev.String())
		if err != nil || got != sev {
			t.Errorf("ParseSeverity(%s.String()) = %v, %v", sev, got, err)
		}
	}
}
