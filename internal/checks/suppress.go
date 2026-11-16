package checks

import (
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// IgnoreAnnotation lets the owner of a resource (or of a whole namespace)
// acknowledge findings. Its value is a comma-separated list of check names, or
// "*" (also "all") for every check:
//
//	meshscan.io/ignore: "retry-without-timeout, missing-dr"
const IgnoreAnnotation = "meshscan.io/ignore"

// Suppress drops findings acknowledged through IgnoreAnnotation, either on the
// resource a finding names or on the namespace. It returns the remaining
// findings and how many were dropped.
func Suppress(snap *model.Snapshot, findings []model.Finding) (kept []model.Finding, suppressed int) {
	if len(findings) == 0 {
		return findings, 0
	}
	nsIgnore := parseIgnore(snap.NamespaceAnnotations[IgnoreAnnotation])
	byResource := resourceAnnotations(snap)

	for _, f := range findings {
		resIgnore := parseIgnore(byResource[f.Resource][IgnoreAnnotation])
		if nsIgnore.has(f.Check) || resIgnore.has(f.Check) {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

// resourceAnnotations indexes annotations by the "Kind/name" form findings use.
func resourceAnnotations(snap *model.Snapshot) map[string]map[string]string {
	idx := map[string]map[string]string{}
	for _, o := range snap.VirtualServices {
		idx["VirtualService/"+o.Name] = o.Annotations
	}
	for _, o := range snap.DestinationRules {
		idx["DestinationRule/"+o.Name] = o.Annotations
	}
	for _, o := range snap.Gateways {
		idx["Gateway/"+o.Name] = o.Annotations
	}
	for _, o := range snap.EnvoyFilters {
		idx["EnvoyFilter/"+o.Name] = o.Annotations
	}
	for _, o := range snap.PeerAuths {
		idx["PeerAuthentication/"+o.Name] = o.Annotations
	}
	for i := range snap.Pods {
		idx["Pod/"+snap.Pods[i].Name] = snap.Pods[i].Annotations
	}
	return idx
}

type ignoreSet map[string]bool

func parseIgnore(value string) ignoreSet {
	set := ignoreSet{}
	for _, part := range strings.Split(value, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			set[part] = true
		}
	}
	return set
}

func (s ignoreSet) has(check string) bool {
	return s["*"] || s["all"] || s[check]
}
