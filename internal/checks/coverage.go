package checks

import (
	corev1 "k8s.io/api/core/v1"
	"github.com/n0rm4l-me/meshscan/internal/model"
)

// CheckSidecarCoverage finds Running pods that lack the istio-proxy sidecar.
func CheckSidecarCoverage(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, pod := range snap.Pods {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		// skip pods that opted out explicitly
		if pod.Annotations["sidecar.istio.io/inject"] == "false" {
			continue
		}
		if !hasSidecar(pod) {
			owner := ownerKind(pod)
			findings = append(findings, model.Finding{
				Severity:  model.SeverityHigh,
				Check:     "sidecar-coverage",
				Resource:  "Pod/" + pod.Name,
				Namespace: pod.Namespace,
				Message:   "running pod has no istio-proxy sidecar; traffic bypasses mesh policies" + owner,
				Fix:       "ensure namespace label istio-injection=enabled and pod is not annotated sidecar.istio.io/inject=false",
			})
		}
	}
	return findings
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
	for _, ref := range pod.OwnerReferences {
		return " (owner: " + ref.Kind + "/" + ref.Name + ")"
	}
	return ""
}
