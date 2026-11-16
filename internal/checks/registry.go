package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// Check names. They are part of the public interface: they appear in reports,
// in --checks/--skip-checks and in meshscan.io/ignore annotations.
const (
	NameMTLS             = "mtls-enforcement"
	NameEnvoyFilterScope = "envoyfilter-scope"
	NameSidecarCoverage  = "sidecar-coverage"
	NameDeadSubsets      = "dead-subsets"
	NameGatewayMissing   = "gateway-missing"
	NameOutlierDetection = "outlier-detection"
	NameMissingDR        = "missing-dr"
	NameRetryNoTimeout   = "retry-without-timeout"
)

// Func is the implementation of one audit rule.
type Func func(snap *model.Snapshot) []model.Finding

// Check is a registered audit rule.
type Check struct {
	Name        string
	Description string
	// Severity is the highest severity the check can report.
	Severity model.Severity
	Run      Func
}

// All returns every registered check in execution order.
func All() []Check {
	return []Check{
		{NameMTLS, "namespace without STRICT mTLS (no PeerAuthentication, or a PERMISSIVE/DISABLE policy)", model.SeverityCritical, CheckMTLS},
		{NameEnvoyFilterScope, "EnvoyFilter without workloadSelector or targetRefs (CRITICAL in istio-system)", model.SeverityCritical, CheckEnvoyFilterScope},
		{NameSidecarCoverage, "running pod without an istio-proxy sidecar that has not opted out", model.SeverityHigh, CheckSidecarCoverage},
		{NameDeadSubsets, "VirtualService routes to a subset the DestinationRule does not define", model.SeverityHigh, CheckDeadSubsets},
		{NameGatewayMissing, "VirtualService references a Gateway that does not exist", model.SeverityHigh, CheckMissingGateway},
		{NameOutlierDetection, "DestinationRule without outlier detection", model.SeverityHigh, CheckOutlierDetection},
		{NameMissingDR, "VirtualService destination without a DestinationRule", model.SeverityMedium, CheckMissingDR},
		{NameRetryNoTimeout, "HTTP route with retries but no timeout", model.SeverityMedium, CheckRetryWithoutTimeout},
	}
}

// Names returns the names of all registered checks, sorted.
func Names() []string {
	all := All()
	names := make([]string, len(all))
	for i, c := range all {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}

// Select returns the checks to run: those in only (all when only is empty)
// minus those in skip. Unknown names are an error so that a typo can never
// silently disable a check.
func Select(only, skip []string) ([]Check, error) {
	known := map[string]bool{}
	for _, n := range Names() {
		known[n] = true
	}
	validate := func(flag string, names []string) error {
		for _, n := range names {
			if !known[n] {
				return fmt.Errorf("unknown check %q in %s (available: %s)", n, flag, strings.Join(Names(), ", "))
			}
		}
		return nil
	}
	if err := validate("--checks", only); err != nil {
		return nil, err
	}
	if err := validate("--skip-checks", skip); err != nil {
		return nil, err
	}

	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	skipped := map[string]bool{}
	for _, n := range skip {
		skipped[n] = true
	}

	var selected []Check
	for _, c := range All() {
		if (len(want) == 0 || want[c.Name]) && !skipped[c.Name] {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checks selected: --checks and --skip-checks leave nothing to run")
	}
	return selected, nil
}
