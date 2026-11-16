package checks

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const (
	injectKey        = "sidecar.istio.io/inject"
	dataplaneModeKey = "istio.io/dataplane-mode"
)

// CheckSidecarCoverage finds Running pods that lack the istio-proxy sidecar.
//
// A pod is not reported when it opted out (sidecar.istio.io/inject=false as
// annotation or label), when it uses the host network (Istio never injects
// those), or when it is enrolled in ambient mode, or explicitly excluded from
// it, through the istio.io/dataplane-mode label on the pod or its namespace.
func CheckSidecarCoverage(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, pod := range snap.Pods {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if pod.Annotations[injectKey] == "false" || pod.Labels[injectKey] == "false" {
			continue
		}
		if pod.Spec.HostNetwork {
			continue
		}
		if isAmbientOrExcluded(pod, snap.NamespaceLabels) {
			continue
		}
		if !hasSidecar(pod) {
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     NameSidecarCoverage,
				Resource:  "Pod/" + pod.Name,
				Namespace: pod.Namespace,
				Message:   "running pod has no istio-proxy sidecar; traffic bypasses mesh policies" + ownerKind(pod),
				Fix:       "ensure namespace label istio-injection=enabled and pod is not annotated sidecar.istio.io/inject=false",
			})
		}
	}
	return findings
}

// isAmbientOrExcluded reports whether the data plane mode label (pod label wins
// over namespace label) says the pod does not use sidecars on purpose.
func isAmbientOrExcluded(pod corev1.Pod, nsLabels map[string]string) bool {
	mode, ok := pod.Labels[dataplaneModeKey]
	if !ok {
		mode = nsLabels[dataplaneModeKey]
	}
	return mode == "ambient" || mode == "none"
}

func hasSidecar(pod corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" {
			return true
		}
	}
	// Istio 1.21+ native k8s sidecar injection places istio-proxy in InitContainers
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "istio-proxy" {
			return true
		}
	}
	return false
}

func ownerKind(pod corev1.Pod) string {
	if len(pod.OwnerReferences) == 0 {
		return ""
	}
	ref := pod.OwnerReferences[0]
	return " (owner: " + ref.Kind + "/" + ref.Name + ")"
}
