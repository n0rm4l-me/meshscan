package checks

import (
	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckMTLS flags namespaces with no PeerAuthentication or a PERMISSIVE mesh-wide policy.
func CheckMTLS(snap *model.Snapshot) []model.Finding {
	if len(snap.PeerAuths) == 0 {
		// No namespace-level PA; check if a mesh-wide STRICT policy in istio-system protects this namespace.
		if hasMeshWideStrict(snap.SystemPeerAuths) {
			return nil
		}
		return []model.Finding{{
			Severity:  model.SeverityCritical,
			Check:     "mtls-enforcement",
			Resource:  "PeerAuthentication",
			Namespace: snap.Namespace,
			Message:   "no PeerAuthentication found; namespace defaults to PERMISSIVE (plaintext allowed)",
			Fix:       "kubectl apply -f - <<EOF\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata:\n  name: default\n  namespace: " + snap.Namespace + "\nspec:\n  mtls:\n    mode: STRICT\nEOF",
		}}
	}

	var findings []model.Finding
	for _, pa := range snap.PeerAuths {
		mode := pa.Spec.GetMtls().GetMode()
		// selector-less PA with PERMISSIVE = namespace-wide plaintext
		if pa.Spec.Selector == nil && mode == istiov1beta1.PeerAuthentication_MutualTLS_PERMISSIVE {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityCritical,
				Check:     "mtls-enforcement",
				Resource:  "PeerAuthentication/" + pa.Name,
				Namespace: snap.Namespace,
				Message:   "mesh-wide PeerAuthentication is PERMISSIVE, mTLS not enforced",
				Fix:       "set spec.mtls.mode: STRICT",
			})
		}
	}
	return findings
}

// hasMeshWideStrict returns true if any selector-less PeerAuthentication in the list enforces STRICT mTLS.
func hasMeshWideStrict(pas []*securityv1beta1.PeerAuthentication) bool {
	for _, pa := range pas {
		if pa.Spec.Selector == nil && pa.Spec.GetMtls().GetMode() == istiov1beta1.PeerAuthentication_MutualTLS_STRICT {
			return true
		}
	}
	return false
}
