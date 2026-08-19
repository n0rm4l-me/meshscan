package checks

import "github.com/n0rm4l-me/meshscan/internal/model"

// CheckEnvoyFilterScope flags EnvoyFilters without a workloadSelector.
// Without a selector, an EnvoyFilter applies to every pod in the namespace.
// An EnvoyFilter in istio-system without a selector applies to every pod in
// the entire mesh, making it CRITICAL.
func CheckEnvoyFilterScope(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, ef := range snap.EnvoyFilters {
		sel := ef.Spec.GetWorkloadSelector()
		if sel != nil && len(sel.GetLabels()) > 0 {
			continue
		}
		severity := model.SeverityHigh
		msg := "no workloadSelector; applies to all pods in namespace " + ef.Namespace + " (full namespace blast radius)"
		if ef.Namespace == "istio-system" {
			severity = model.SeverityCritical
			msg = "no workloadSelector in istio-system; applies to ALL pods in the mesh"
		}
		findings = append(findings, model.Finding{
			Severity:  severity,
			Check:     "envoyfilter-scope",
			Resource:  "EnvoyFilter/" + ef.Name,
			Namespace: ef.Namespace,
			Message:   msg,
			Fix:       "add spec.workloadSelector.labels to restrict this EnvoyFilter to specific workloads",
		})
	}
	return findings
}
