package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestHumanNoFindings(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, nil, "prod", false)
	if got, want := buf.String(), "✓ no issues found in namespace prod\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHumanNoFindingsAllNamespaces(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, nil, "", false)
	if got, want := buf.String(), "✓ no issues found in all namespaces\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHumanWithFindings(t *testing.T) {
	findings := []model.Finding{
		{
			Severity:  model.SeverityCritical,
			Check:     "mtls-enforcement",
			Resource:  "PeerAuthentication",
			Namespace: "app",
			Message:   "no PA found",
			Fix:       "kubectl apply -f - <<EOF\nkind: PeerAuthentication\nEOF",
		},
		{
			Severity:  model.SeverityHigh,
			Check:     "dead-subsets",
			Resource:  "VirtualService/vs",
			Namespace: "app",
			Message:   "dead subset",
		},
	}
	var buf bytes.Buffer
	Human(&buf, findings, "app", false)

	want := `meshscan report: namespace app
2 issues: 1 critical, 1 high, 0 medium, 0 low

[CRITICAL] PeerAuthentication
  check: mtls-enforcement
  no PA found
  fix: kubectl apply -f - <<EOF
  kind: PeerAuthentication
  EOF

[HIGH] VirtualService/vs
  check: dead-subsets
  dead subset

`
	if got := buf.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHumanAllNamespacesPrefixesFindings(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityHigh, Check: "c", Resource: "VirtualService/vs", Namespace: "staging", Message: "m"},
	}
	var buf bytes.Buffer
	Human(&buf, findings, "", false)
	got := buf.String()

	if !strings.Contains(got, "meshscan report: all namespaces\n") {
		t.Errorf("header should read 'all namespaces', got: %q", got)
	}
	if !strings.Contains(got, "[HIGH] staging/VirtualService/vs\n") {
		t.Errorf("finding should be prefixed with its namespace, got: %q", got)
	}
}

func TestHumanColor(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical, Check: "c", Resource: "r", Namespace: "ns", Message: "m", Fix: "f"},
		{Severity: model.SeverityLow, Check: "c", Resource: "r", Namespace: "ns", Message: "m"},
	}

	var plain, colored bytes.Buffer
	Human(&plain, findings, "ns", false)
	Human(&colored, findings, "ns", true)

	if strings.Contains(plain.String(), "\033[") {
		t.Errorf("plain output contains ANSI escape codes: %q", plain.String())
	}
	if !strings.Contains(plain.String(), "[CRITICAL]") {
		t.Errorf("expected [CRITICAL] in plain output, got: %q", plain.String())
	}
	for _, want := range []string{colorRed + colorBold + "[CRITICAL]", colorCyan + "[LOW]", colorReset} {
		if !strings.Contains(colored.String(), want) {
			t.Errorf("colored output lacks %q: %q", want, colored.String())
		}
	}
}

func TestSeverityColors(t *testing.T) {
	tests := map[model.Severity]string{
		model.SeverityCritical: colorRed + colorBold,
		model.SeverityHigh:     colorRed,
		model.SeverityMedium:   colorYellow,
		model.SeverityLow:      colorCyan,
	}
	for sev, want := range tests {
		if got := severityColor(sev, true); got != want {
			t.Errorf("severityColor(%s) = %q, want %q", sev, got, want)
		}
		if got := severityColor(sev, false); got != "" {
			t.Errorf("severityColor(%s, false) = %q, want empty", sev, got)
		}
	}
}
