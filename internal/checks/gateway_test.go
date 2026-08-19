package checks

import (
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckMissingGateway(t *testing.T) {
	gw := func(name string) *networkingv1alpha3.Gateway {
		return &networkingv1alpha3.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
		}
	}
	vs := func(name string, gateways ...string) *networkingv1alpha3.VirtualService {
		return &networkingv1alpha3.VirtualService{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
			Spec:       istiov1alpha3.VirtualService{Gateways: gateways, Hosts: []string{"example.com"}},
		}
	}

	tests := []struct {
		name         string
		snap         *model.Snapshot
		wantFindings int
	}{
		{
			name: "VS references existing gateway → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs", "my-gateway")},
				Gateways:        []*networkingv1alpha3.Gateway{gw("my-gateway")},
			},
			wantFindings: 0,
		},
		{
			name: "VS references missing gateway → finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs", "missing-gateway")},
			},
			wantFindings: 1,
		},
		{
			name: "VS with mesh entry → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs", "mesh")},
			},
			wantFindings: 0,
		},
		{
			name: "VS with cross-namespace ref → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs", "istio-system/ingress-gateway")},
			},
			wantFindings: 0,
		},
		{
			name: "VS with no gateways field → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs")},
			},
			wantFindings: 0,
		},
		{
			name: "VS with mesh + missing → one finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("vs", "mesh", "missing-gw")},
			},
			wantFindings: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckMissingGateway(tc.snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
