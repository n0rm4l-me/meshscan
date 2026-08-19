package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestHumanNoFindings(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, nil, "prod")
	got := buf.String()
	if !strings.Contains(got, "no issues found") {
		t.Errorf("expected no-issues message, got: %q", got)
	}
	if !strings.Contains(got, "prod") {
		t.Errorf("expected namespace in output, got: %q", got)
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
			Fix:       "kubectl apply ...",
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
	Human(&buf, findings, "app")
	got := buf.String()

	for _, want := range []string{"[CRITICAL]", "[HIGH]", "mtls-enforcement", "dead-subsets", "kubectl apply", "2 issues"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got: %q", want, got)
		}
	}
}

func TestHumanNoColorMode(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	findings := []model.Finding{{
		Severity:  model.SeverityCritical,
		Check:     "test",
		Resource:  "Pod/foo",
		Namespace: "ns",
		Message:   "msg",
	}}
	var buf bytes.Buffer
	Human(&buf, findings, "ns")
	got := buf.String()

	if strings.Contains(got, "\033[") {
		t.Errorf("output contains ANSI escape codes when NO_COLOR is set: %q", got)
	}
	if !strings.Contains(got, "[CRITICAL]") {
		t.Errorf("expected [CRITICAL] in plain output, got: %q", got)
	}
}
