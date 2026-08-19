package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestJSONEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("want [], got %q", buf.String())
	}
}

func TestJSONNoHTMLEscaping(t *testing.T) {
	findings := []model.Finding{{
		Severity:  model.SeverityCritical,
		Check:     "mtls-enforcement",
		Resource:  "PeerAuthentication",
		Namespace: "app",
		Message:   "test message",
		Fix:       "kubectl apply -f - <<EOF\napiVersion: example\nEOF",
	}}
	var buf bytes.Buffer
	if err := JSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// json.Encoder HTML-escaping converts < to the 6-char sequence <.
	// With SetEscapeHTML(false), that must NOT happen — <<EOF must appear literally.
	if !strings.Contains(got, "<<EOF") {
		t.Errorf("expected literal <<EOF in JSON output (angle brackets were escaped); got: %q", got)
	}
}

func TestJSONStructure(t *testing.T) {
	findings := []model.Finding{{
		Severity:  model.SeverityHigh,
		Check:     "dead-subsets",
		Resource:  "VirtualService/vs",
		Namespace: "app",
		Message:   "test",
	}}
	var buf bytes.Buffer
	if err := JSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{`"severity": "HIGH"`, `"check": "dead-subsets"`, `"resource": "VirtualService/vs"`, `"namespace": "app"`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got: %q", want, got)
		}
	}
	if strings.Contains(got, `"fix"`) {
		t.Errorf("fix field should be omitted when empty")
	}
}
