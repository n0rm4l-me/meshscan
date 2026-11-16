package checks

import (
	"strings"

	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
)

// clusterDomainSuffix is the default Kubernetes service DNS suffix.
const clusterDomainSuffix = ".svc.cluster.local"

// classifyHost normalizes a VirtualService destination host or a
// DestinationRule host that is declared in namespace ns.
//
// Istio resolves a short name (no dots) relative to the namespace of the rule
// that mentions it, so "reviews" in namespace "shop" means
// "reviews.shop.svc.cluster.local". classifyHost returns that FQDN and
// local=true when the host is an in-cluster service in ns. Hosts that are
// external, wildcards, or in-cluster services of another namespace are
// returned unchanged with local=false: a single-namespace snapshot cannot
// prove that no DestinationRule exists for them.
func classifyHost(host, ns string) (fqdn string, local bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case host == "":
		return "", false
	case strings.Contains(host, "*"):
		return host, false
	case !strings.Contains(host, "."):
		return host + "." + ns + clusterDomainSuffix, true
	case strings.HasSuffix(host, clusterDomainSuffix):
		trimmed := strings.TrimSuffix(host, clusterDomainSuffix) // "<name>.<namespace>"
		i := strings.LastIndex(trimmed, ".")
		return host, i >= 0 && trimmed[i+1:] == ns
	}
	return host, false
}

// forEachDestination calls fn for every route destination of a VirtualService
// across its HTTP, TCP and TLS rules.
func forEachDestination(vs *networkingv1alpha3.VirtualService, fn func(host, subset string)) {
	for _, rule := range vs.Spec.GetHttp() {
		for _, dest := range rule.GetRoute() {
			d := dest.GetDestination()
			fn(d.GetHost(), d.GetSubset())
		}
	}
	for _, rule := range vs.Spec.GetTcp() {
		for _, dest := range rule.GetRoute() {
			d := dest.GetDestination()
			fn(d.GetHost(), d.GetSubset())
		}
	}
	for _, rule := range vs.Spec.GetTls() {
		for _, dest := range rule.GetRoute() {
			d := dest.GetDestination()
			fn(d.GetHost(), d.GetSubset())
		}
	}
}

// drEntry aggregates every DestinationRule that targets one host.
type drEntry struct {
	names   []string
	subsets map[string]bool
}

// drLookup indexes DestinationRules by normalized host. Istio merges subsets
// of several rules for the same host, so entries accumulate rather than
// overwrite. Wildcard hosts ("*.example.com") match by suffix and the longest
// suffix wins, like Istio's most-specific-host selection.
type drLookup struct {
	exact map[string]*drEntry
	wild  map[string]*drEntry // key: host without the leading "*"
}

func newDRLookup(drs []*networkingv1alpha3.DestinationRule) *drLookup {
	l := &drLookup{exact: map[string]*drEntry{}, wild: map[string]*drEntry{}}
	for _, dr := range drs {
		host := strings.ToLower(dr.Spec.GetHost())
		if host == "" {
			continue
		}
		index, key := l.exact, ""
		if strings.HasPrefix(host, "*") {
			index, key = l.wild, strings.TrimPrefix(host, "*")
		} else {
			key, _ = classifyHost(host, dr.Namespace)
		}
		e := index[key]
		if e == nil {
			e = &drEntry{subsets: map[string]bool{}}
			index[key] = e
		}
		e.names = append(e.names, dr.Name)
		for _, s := range dr.Spec.GetSubsets() {
			e.subsets[s.GetName()] = true
		}
	}
	return l
}

// find returns the entry that applies to fqdn, if any.
func (l *drLookup) find(fqdn string) (*drEntry, bool) {
	if e, ok := l.exact[fqdn]; ok {
		return e, true
	}
	var best *drEntry
	bestLen := -1
	for suffix, e := range l.wild {
		if strings.HasSuffix(fqdn, suffix) && len(suffix) > bestLen {
			best, bestLen = e, len(suffix)
		}
	}
	return best, best != nil
}
