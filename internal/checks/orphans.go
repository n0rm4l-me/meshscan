package checks

import (
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckMissingDR finds VirtualService hosts that have no DestinationRule.
// Without a DR there is no traffic policy: no retries, no outlier detection,
// no connection pool limits.
func CheckMissingDR(snap *model.Snapshot) []model.Finding {
	drHosts := map[string]bool{}
	for _, dr := range snap.DestinationRules {
		drHosts[dr.Spec.GetHost()] = true
	}

	seen := map[string]bool{}
	var findings []model.Finding

	check := func(vsName, vsNS, host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		if isExternalHost(host) {
			return
		}
		if !drHosts[host] {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityMedium,
				Check:     "missing-dr",
				Resource:  "VirtualService/" + vsName,
				Namespace: vsNS,
				Message:   "routes to " + host + " but no DestinationRule (no traffic policy applied)",
				Fix:       "create a DestinationRule for " + host + " with outlier detection and connection pool limits",
			})
		}
	}

	for _, vs := range snap.VirtualServices {
		for _, rule := range vs.Spec.GetHttp() {
			for _, dest := range rule.GetRoute() {
				check(vs.Name, vs.Namespace, dest.GetDestination().GetHost())
			}
		}
		for _, rule := range vs.Spec.GetTcp() {
			for _, dest := range rule.GetRoute() {
				check(vs.Name, vs.Namespace, dest.GetDestination().GetHost())
			}
		}
		for _, rule := range vs.Spec.GetTls() {
			for _, dest := range rule.GetRoute() {
				check(vs.Name, vs.Namespace, dest.GetDestination().GetHost())
			}
		}
	}
	return findings
}

// isExternalHost skips wildcard patterns and obvious external FQDNs.
func isExternalHost(host string) bool {
	if strings.HasPrefix(host, "*") {
		return true
	}
	if strings.Contains(host, ".") && !strings.HasSuffix(host, ".svc.cluster.local") {
		return true
	}
	return false
}
