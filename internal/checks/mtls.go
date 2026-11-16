package checks

import (
	"fmt"

	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

// rootNamespace is Istio's default root namespace. A selector-less
// PeerAuthentication there is the mesh-wide policy.
const rootNamespace = "istio-system"

// CheckMTLS flags namespaces whose effective namespace-level mTLS mode is not STRICT.
//
// Istio resolves the mode top-down: workload policy, then the namespace-wide
// policy (a PeerAuthentication without selector), then the mesh-wide policy in
// the root namespace, then the PERMISSIVE default. A mode of UNSET inherits from
// the level above. Workload-scoped policies are not judged here.
func CheckMTLS(snap *model.Snapshot) []model.Finding {
	parent := meshLevelMode(snap)

	nsPA := oldestNamespaceWide(snap.PeerAuths)
	if nsPA == nil {
		if parent == istiov1beta1.PeerAuthentication_MutualTLS_STRICT {
			return nil
		}
		msg := "no PeerAuthentication found; namespace defaults to PERMISSIVE (plaintext allowed)"
		if len(snap.PeerAuths) > 0 {
			msg = "no namespace-wide PeerAuthentication (only workload-scoped ones); workloads without a matching policy default to PERMISSIVE (plaintext allowed)"
		}
		return []model.Finding{{
			Severity:  model.SeverityCritical,
			Check:     NameMTLS,
			Resource:  "PeerAuthentication",
			Namespace: snap.Namespace,
			Message:   msg,
			Fix:       "kubectl apply -f - <<EOF\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata:\n  name: default\n  namespace: " + snap.Namespace + "\nspec:\n  mtls:\n    mode: STRICT\nEOF",
		}}
	}

	mode := nsPA.Spec.GetMtls().GetMode()
	detail := fmt.Sprintf("is %s, mTLS not enforced", mode)
	if mode == istiov1beta1.PeerAuthentication_MutualTLS_UNSET {
		mode = parent
		detail = fmt.Sprintf("has no mode and inherits %s, mTLS not enforced", mode)
	}
	if mode == istiov1beta1.PeerAuthentication_MutualTLS_STRICT {
		return nil
	}

	scope := "namespace-wide"
	if snap.Namespace == rootNamespace {
		scope = "mesh-wide"
	}
	return []model.Finding{{
		Severity:  model.SeverityCritical,
		Check:     NameMTLS,
		Resource:  "PeerAuthentication/" + nsPA.Name,
		Namespace: snap.Namespace,
		Message:   scope + " PeerAuthentication " + detail,
		Fix:       "set spec.mtls.mode: STRICT",
	}}
}

// meshLevelMode returns the mTLS mode the namespace inherits from the mesh level.
func meshLevelMode(snap *model.Snapshot) istiov1beta1.PeerAuthentication_MutualTLS_Mode {
	const permissive = istiov1beta1.PeerAuthentication_MutualTLS_PERMISSIVE
	if snap.Namespace == rootNamespace {
		return permissive // nothing sits above the root namespace except the default
	}
	pa := oldestNamespaceWide(snap.SystemPeerAuths)
	if pa == nil {
		return permissive
	}
	if mode := pa.Spec.GetMtls().GetMode(); mode != istiov1beta1.PeerAuthentication_MutualTLS_UNSET {
		return mode
	}
	return permissive
}

// oldestNamespaceWide returns the selector-less PeerAuthentication that Istio
// would honor: when several exist, the oldest one wins.
func oldestNamespaceWide(pas []*securityv1beta1.PeerAuthentication) *securityv1beta1.PeerAuthentication {
	var best *securityv1beta1.PeerAuthentication
	for _, pa := range pas {
		if pa.Spec.Selector != nil {
			continue
		}
		if best == nil || olderThan(pa, best) {
			best = pa
		}
	}
	return best
}

func olderThan(a, b *securityv1beta1.PeerAuthentication) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}
