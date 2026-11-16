package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// CheckEnvoyFilterScope flags EnvoyFilters without a workloadSelector or targetRefs.
// Without either, an EnvoyFilter applies to every pod in the namespace.
// An EnvoyFilter in istio-system without them applies to every pod in
// the entire mesh, making it CRITICAL.
func CheckEnvoyFilterScope(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, ef := range snap.EnvoyFilters {
		if len(ef.Spec.GetWorkloadSelector().GetLabels()) > 0 || len(ef.Spec.GetTargetRefs()) > 0 {
			continue
		}
		severity := model.SeverityHigh
		msg := "no workloadSelector; applies to all pods in namespace " + ef.Namespace + " (full namespace blast radius)"
		if ef.Namespace == rootNamespace {
			severity = model.SeverityCritical
			msg = "no workloadSelector in " + rootNamespace + "; applies to ALL pods in the mesh"
		}
		findings = append(findings, model.Finding{
			Severity:  severity,
			Check:     NameEnvoyFilterScope,
			Resource:  "EnvoyFilter/" + ef.Name,
			Namespace: ef.Namespace,
			Message:   msg,
			Fix:       "add spec.workloadSelector.labels (or spec.targetRefs) to restrict this EnvoyFilter to specific workloads",
		})
	}
	return findings
}
