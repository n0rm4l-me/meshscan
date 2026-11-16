package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// decoded mirrors only the SARIF fields the tests assert on, so the tests
// verify the wire format rather than our own structs.
type decoded struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID                   string `json:"id"`
					ShortDescription     struct{ Text string }
					DefaultConfiguration struct{ Level string }
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct{ Text string }
			Locations []struct {
				LogicalLocations []struct {
					Name               string `json:"name"`
					FullyQualifiedName string `json:"fullyQualifiedName"`
					Kind               string `json:"kind"`
				} `json:"logicalLocations"`
			} `json:"locations"`
			Properties map[string]string `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, findings []model.Finding, rules []Rule) (decoded, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, findings, rules, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var d decoded
	if err := json.Unmarshal(buf.Bytes(), &d); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return d, buf.String()
}

var testRules = []Rule{
	{ID: "mtls-enforcement", Description: "mTLS not enforced", Severity: model.SeverityCritical},
	{ID: "missing-dr", Description: "no DestinationRule", Severity: model.SeverityMedium},
}

func TestSARIFEnvelope(t *testing.T) {
	d, _ := decodeSARIF(t, nil, testRules)

	if d.Version != "2.1.0" || !strings.Contains(d.Schema, "sarif-2.1.0") {
		t.Errorf("version/schema = %q / %q", d.Version, d.Schema)
	}
	if len(d.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(d.Runs))
	}
	drv := d.Runs[0].Tool.Driver
	if drv.Name != "meshscan" || drv.Version != "1.2.3" || drv.InformationURI == "" {
		t.Errorf("driver = %+v", drv)
	}
	if len(drv.Rules) != 2 || drv.Rules[0].ID != "mtls-enforcement" || drv.Rules[0].DefaultConfiguration.Level != "error" || drv.Rules[1].DefaultConfiguration.Level != "warning" {
		t.Errorf("rules = %+v", drv.Rules)
	}
}

func TestSARIFEmptyResultsIsAnArrayNotNull(t *testing.T) {
	_, raw := decodeSARIF(t, nil, testRules)
	if !strings.Contains(raw, `"results": []`) {
		t.Errorf("results must serialize as [], got:\n%s", raw)
	}
}

func TestSARIFResults(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical, Check: "mtls-enforcement", Resource: "PeerAuthentication", Namespace: "prod", Message: "no PA", Fix: "kubectl apply -f - <<EOF"},
		{Severity: model.SeverityMedium, Check: "missing-dr", Resource: "VirtualService/vs", Namespace: "prod", Message: "no DR"},
	}
	d, raw := decodeSARIF(t, findings, testRules)

	res := d.Runs[0].Results
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2", len(res))
	}

	first := res[0]
	if first.RuleID != "mtls-enforcement" || first.RuleIndex != 0 || first.Level != "error" || first.Message.Text != "no PA" {
		t.Errorf("first result = %+v", first)
	}
	loc := first.Locations[0].LogicalLocations[0]
	if loc.Name != "PeerAuthentication" || loc.FullyQualifiedName != "prod/PeerAuthentication" || loc.Kind != "resource" {
		t.Errorf("logical location = %+v", loc)
	}
	if first.Properties["severity"] != "CRITICAL" || first.Properties["namespace"] != "prod" || first.Properties["fix"] != "kubectl apply -f - <<EOF" {
		t.Errorf("properties = %v", first.Properties)
	}

	second := res[1]
	if second.RuleIndex != 1 || second.Level != "warning" {
		t.Errorf("second result = %+v", second)
	}
	if _, hasFix := second.Properties["fix"]; hasFix {
		t.Errorf("empty fix must be omitted: %v", second.Properties)
	}

	if !strings.Contains(raw, "<<EOF") {
		t.Errorf("angle brackets were HTML-escaped:\n%s", raw)
	}
}

func TestSARIFAddsRuleForUnknownCheck(t *testing.T) {
	findings := []model.Finding{{Severity: model.SeverityLow, Check: "custom", Resource: "Pod/p", Namespace: "ns", Message: "m"}}
	d, _ := decodeSARIF(t, findings, testRules)

	rules := d.Runs[0].Tool.Driver.Rules
	if len(rules) != 3 || rules[2].ID != "custom" {
		t.Fatalf("rules = %+v, want custom appended", rules)
	}
	if got := d.Runs[0].Results[0]; got.RuleIndex != 2 || got.Level != "note" {
		t.Errorf("result = %+v", got)
	}
}

func TestSARIFLevels(t *testing.T) {
	tests := map[model.Severity]string{
		model.SeverityCritical: "error",
		model.SeverityHigh:     "error",
		model.SeverityMedium:   "warning",
		model.SeverityLow:      "note",
	}
	for sev, want := range tests {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %s, want %s", sev, got, want)
		}
	}
}
