package checks

import (
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	typev1beta1 "istio.io/api/type/v1beta1"
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
	withTargetRef := func(e *networkingv1alpha3.EnvoyFilter) *networkingv1alpha3.EnvoyFilter {
		e.Spec.TargetRefs = []*typev1beta1.PolicyTargetReference{{Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "edge"}}
		return e
	}
	efs := func(e ...*networkingv1alpha3.EnvoyFilter) *model.Snapshot {
		return &model.Snapshot{EnvoyFilters: e}
	}

	tests := []struct {
		name string
		snap *model.Snapshot
		want []wantFinding
	}{
		{
			name: "workloadSelector set",
			snap: efs(ef("scoped", "app", map[string]string{"app": "my-svc"})),
		},
		{
			name: "no selector",
			snap: efs(ef("broad", "app", nil)),
			want: []wantFinding{{model.SeverityHigh, "EnvoyFilter/broad", "namespace app"}},
		},
		{
			name: "empty selector labels count as no selector",
			snap: efs(ef("empty", "app", map[string]string{})),
			want: []wantFinding{{model.SeverityHigh, "EnvoyFilter/empty", "no workloadSelector"}},
		},
		{
			name: "no selector in istio-system is mesh-wide",
			snap: efs(ef("mesh-wide", "istio-system", nil)),
			want: []wantFinding{{model.SeverityCritical, "EnvoyFilter/mesh-wide", "ALL pods in the mesh"}},
		},
		{
			name: "targetRefs scope the filter",
			snap: efs(withTargetRef(ef("gw-scoped", "app", nil))),
		},
		{
			name: "targetRefs scope the filter in istio-system",
			snap: efs(withTargetRef(ef("gw-scoped", "istio-system", nil))),
		},
		{
			name: "one scoped, one broad",
			snap: efs(ef("scoped", "app", map[string]string{"app": "svc"}), ef("broad", "app", nil)),
			want: []wantFinding{{model.SeverityHigh, "EnvoyFilter/broad", "no workloadSelector"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, NameEnvoyFilterScope, CheckEnvoyFilterScope(tc.snap), tc.want...)
		})
	}
}
