package checks

import (
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckMissingGateway finds VirtualServices that reference a Gateway which does
// not exist in the namespace the reference points to. When a Gateway is
// missing, no traffic reaches the VirtualService from outside the mesh.
//
// References to Gateways in other namespaces cannot be verified from a
// single-namespace snapshot and are skipped.
func CheckMissingGateway(snap *model.Snapshot) []model.Finding {
	gwNames := map[string]bool{}
	for _, gw := range snap.Gateways {
		gwNames[gw.Name] = true
	}

	var findings []model.Finding
	for _, vs := range snap.VirtualServices {
		// No explicit gateways: the VirtualService applies to mesh sidecar traffic only.
		for _, ref := range vs.Spec.GetGateways() {
			name, ok := localGatewayName(ref, vs.Namespace)
			if !ok || gwNames[name] {
				continue
			}
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     NameGatewayMissing,
				Resource:  "VirtualService/" + vs.Name,
				Namespace: vs.Namespace,
				Message:   "references Gateway/" + name + " which does not exist in namespace " + vs.Namespace + " (no ingress traffic will be routed)",
				Fix:       "create Gateway/" + name + " or correct the gateway reference in VirtualService/" + vs.Name,
			})
		}
	}
	return findings
}

// localGatewayName extracts the Gateway name from a VirtualService gateway
// reference when the Gateway lives in namespace ns. Istio accepts three forms:
// a short name (resolved in the VirtualService namespace), "namespace/name"
// (where "." means the current namespace), and "name.namespace.svc.cluster.local".
// The reserved name "mesh" is not a Gateway.
func localGatewayName(ref, ns string) (string, bool) {
	if ref == "mesh" {
		return "", false
	}
	if gwNS, name, ok := strings.Cut(ref, "/"); ok {
		if gwNS == "." || gwNS == ns {
			return name, true
		}
		return "", false
	}
	if !strings.Contains(ref, ".") {
		return ref, true
	}
	if trimmed, ok := strings.CutSuffix(ref, clusterDomainSuffix); ok {
		if name, gwNS, ok := strings.Cut(trimmed, "."); ok && gwNS == ns {
			return name, true
		}
	}
	return "", false
}
