package checks

import (
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckMissingGateway finds VirtualServices that reference a Gateway which does
// not exist in the same namespace. When a Gateway is missing, no traffic reaches
// the VirtualService from outside the mesh.
func CheckMissingGateway(snap *model.Snapshot) []model.Finding {
	gwNames := map[string]bool{}
	for _, gw := range snap.Gateways {
		gwNames[gw.Name] = true
	}

	var findings []model.Finding
	for _, vs := range snap.VirtualServices {
		refs := vs.Spec.GetGateways()
		if len(refs) == 0 {
			continue // no explicit gateways: applies to mesh sidecar traffic only
		}
		for _, ref := range refs {
			if ref == "mesh" {
				continue
			}
			// cross-namespace ref "namespace/name": cannot verify without listing other namespaces
			if strings.Contains(ref, "/") {
				continue
			}
			if !gwNames[ref] {
				findings = append(findings, model.Finding{
					Severity:  model.SeverityHigh,
					Check:     "gateway-missing",
					Resource:  "VirtualService/" + vs.Name,
					Namespace: vs.Namespace,
					Message:   "references Gateway/" + ref + " which does not exist in namespace " + vs.Namespace + " (no ingress traffic will be routed)",
					Fix:       "create Gateway/" + ref + " or correct the gateway reference in VirtualService/" + vs.Name,
				})
			}
		}
	}
	return findings
}
