package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// CheckMissingDR finds VirtualService destinations that have no DestinationRule.
// Without a DR there is no traffic policy: no outlier detection, no connection
// pool limits.
//
// Only in-cluster services of the VirtualService's own namespace are checked
// (see classifyHost): external hosts, wildcards and services of other
// namespaces cannot be judged from a single-namespace snapshot.
func CheckMissingDR(snap *model.Snapshot) []model.Finding {
	drs := newDRLookup(snap.DestinationRules)

	seen := map[string]bool{}
	var findings []model.Finding

	for _, vs := range snap.VirtualServices {
		forEachDestination(vs, func(host, _ string) {
			fqdn, local := classifyHost(host, vs.Namespace)
			if !local {
				return
			}
			key := vs.Name + "|" + fqdn
			if seen[key] {
				return
			}
			seen[key] = true

			if _, found := drs.find(fqdn); found {
				return
			}
			findings = append(findings, model.Finding{
				Severity:  model.SeverityMedium,
				Check:     NameMissingDR,
				Resource:  "VirtualService/" + vs.Name,
				Namespace: vs.Namespace,
				Message:   "routes to " + host + " but no DestinationRule (no traffic policy applied)",
				Fix:       "create a DestinationRule for " + host + " with outlier detection and connection pool limits",
			})
		})
	}
	return findings
}
