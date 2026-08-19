package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// CheckDeadSubsets finds VirtualService routes that reference a subset not
// defined in the corresponding DestinationRule. These routes produce 503.
func CheckDeadSubsets(snap *model.Snapshot) []model.Finding {
	// host → set of defined subsets
	drSubsets := map[string]map[string]bool{}
	drExists := map[string]bool{}
	for _, dr := range snap.DestinationRules {
		host := dr.Spec.GetHost()
		drExists[host] = true
		subsets := map[string]bool{}
		for _, s := range dr.Spec.GetSubsets() {
			subsets[s.GetName()] = true
		}
		drSubsets[host] = subsets
	}

	seen := map[string]bool{}
	var findings []model.Finding

	check := func(vsName, vsNS, host, subset string) {
		if subset == "" {
			return
		}
		key := vsName + "|" + host + "|" + subset
		if seen[key] {
			return
		}
		seen[key] = true

		if !drExists[host] {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     "dead-subsets",
				Resource:  "VirtualService/" + vsName,
				Namespace: vsNS,
				Message:   "routes to " + host + " subset=" + subset + " but no DestinationRule exists for this host (traffic will 503)",
				Fix:       "create a DestinationRule for " + host + " with subset " + subset + " defined",
			})
		} else if !drSubsets[host][subset] {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     "dead-subsets",
				Resource:  "VirtualService/" + vsName,
				Namespace: vsNS,
				Message:   "routes to " + host + " subset=" + subset + " but DestinationRule does not define that subset (traffic will 503)",
				Fix:       "add subset " + subset + " to DestinationRule/" + host,
			})
		}
	}

	for _, vs := range snap.VirtualServices {
		for _, rule := range vs.Spec.GetHttp() {
			for _, dest := range rule.GetRoute() {
				d := dest.GetDestination()
				check(vs.Name, vs.Namespace, d.GetHost(), d.GetSubset())
			}
		}
		for _, rule := range vs.Spec.GetTcp() {
			for _, dest := range rule.GetRoute() {
				d := dest.GetDestination()
				check(vs.Name, vs.Namespace, d.GetHost(), d.GetSubset())
			}
		}
		for _, rule := range vs.Spec.GetTls() {
			for _, dest := range rule.GetRoute() {
				d := dest.GetDestination()
				check(vs.Name, vs.Namespace, d.GetHost(), d.GetSubset())
			}
		}
	}
	return findings
}
