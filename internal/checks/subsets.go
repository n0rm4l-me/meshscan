package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// CheckDeadSubsets finds VirtualService routes that reference a subset not
// defined in the corresponding DestinationRule. These routes produce 503.
//
// Hosts are matched after normalization (see classifyHost), so a short name in
// the VirtualService matches an FQDN in the DestinationRule and vice versa.
// A route to an in-cluster service of another namespace, or to an external
// host, is only reported when a DestinationRule visible in this namespace
// proves the subset is missing.
func CheckDeadSubsets(snap *model.Snapshot) []model.Finding {
	drs := newDRLookup(snap.DestinationRules)

	seen := map[string]bool{}
	var findings []model.Finding

	for _, vs := range snap.VirtualServices {
		forEachDestination(vs, func(host, subset string) {
			if subset == "" {
				return
			}
			fqdn, local := classifyHost(host, vs.Namespace)
			if fqdn == "" {
				return
			}
			key := vs.Name + "|" + fqdn + "|" + subset
			if seen[key] {
				return
			}
			seen[key] = true

			entry, found := drs.find(fqdn)
			switch {
			case !found && local:
				findings = append(findings, model.Finding{
					Severity:  model.SeverityHigh,
					Check:     NameDeadSubsets,
					Resource:  "VirtualService/" + vs.Name,
					Namespace: vs.Namespace,
					Message:   "routes to " + host + " subset=" + subset + " but no DestinationRule exists for this host (traffic will 503)",
					Fix:       "create a DestinationRule for " + host + " with subset " + subset + " defined",
				})
			case found && !entry.subsets[subset]:
				findings = append(findings, model.Finding{
					Severity:  model.SeverityHigh,
					Check:     NameDeadSubsets,
					Resource:  "VirtualService/" + vs.Name,
					Namespace: vs.Namespace,
					Message:   "routes to " + host + " subset=" + subset + " but DestinationRule does not define that subset (traffic will 503)",
					Fix:       "add subset " + subset + " to DestinationRule/" + entry.names[0],
				})
			}
		})
	}
	return findings
}
