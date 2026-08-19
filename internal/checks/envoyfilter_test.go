package checks

import (
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckEnvoyFilterScope(t *testing.T) {
	ef := func(name, ns string, labels map[string]string) *networkingv1alpha3.EnvoyFilter {
		var sel *istiov1alpha3.WorkloadSelector
		if labels != nil {
			sel = &istiov1alpha3.WorkloadSelector{Labels: labels}
		}
		return &networkingv1alpha3.EnvoyFilter{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec:       istiov1alpha3.EnvoyFilter{WorkloadSelector: sel},
		}
	}

	tests := []struct {
		name         string
		snap         *model.Snapshot
		wantFindings int
		wantSeverity model.Severity
	}{
		{
			name:         "EF with workloadSelector → no finding",
			snap:         &model.Snapshot{EnvoyFilters: []*networkingv1alpha3.EnvoyFilter{ef("scoped", "app", map[string]string{"app": "my-svc"})}},
			wantFindings: 0,
		},
		{
			name:         "EF without selector → HIGH finding",
			snap:         &model.Snapshot{EnvoyFilters: []*networkingv1alpha3.EnvoyFilter{ef("broad", "app", nil)}},
			wantFindings: 1,
			wantSeverity: model.SeverityHigh,
		},
		{
			name:         "EF in istio-system without selector → CRITICAL finding",
			snap:         &model.Snapshot{EnvoyFilters: []*networkingv1alpha3.EnvoyFilter{ef("mesh-wide", "istio-system", nil)}},
			wantFindings: 1,
			wantSeverity: model.SeverityCritical,
		},
		{
			name: "mixed: one scoped, one broad → one finding",
			snap: &model.Snapshot{EnvoyFilters: []*networkingv1alpha3.EnvoyFilter{
				ef("scoped", "app", map[string]string{"app": "svc"}),
				ef("broad", "app", nil),
			}},
			wantFindings: 1,
			wantSeverity: model.SeverityHigh,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckEnvoyFilterScope(tc.snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
			if tc.wantFindings > 0 && got[0].Severity != tc.wantSeverity {
				t.Errorf("got severity %s, want %s", got[0].Severity, tc.wantSeverity)
			}
		})
	}
}
