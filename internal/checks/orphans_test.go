package checks

import (
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func vsForHost(host string) *networkingv1alpha3.VirtualService {
	return &networkingv1alpha3.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
		Spec: istiov1alpha3.VirtualService{
			Http: []*istiov1alpha3.HTTPRoute{{
				Route: []*istiov1alpha3.HTTPRouteDestination{{
					Destination: &istiov1alpha3.Destination{Host: host},
				}},
			}},
		},
	}
}

func drForHost(host string) *networkingv1alpha3.DestinationRule {
	return &networkingv1alpha3.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: host, Namespace: "app"},
		Spec:       istiov1alpha3.DestinationRule{Host: host},
	}
}

func TestCheckMissingDR(t *testing.T) {
	tests := []struct {
		name         string
		snap         *model.Snapshot
		wantFindings int
	}{
		{
			name: "VS host has a DR → no finding",
			snap: &model.Snapshot{
				VirtualServices:  []*networkingv1alpha3.VirtualService{vsForHost("svc")},
				DestinationRules: []*networkingv1alpha3.DestinationRule{drForHost("svc")},
			},
			wantFindings: 0,
		},
		{
			name: "VS internal host missing DR → finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vsForHost("svc")},
			},
			wantFindings: 1,
		},
		{
			name: "VS routes to external FQDN → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vsForHost("api.example.com")},
			},
			wantFindings: 0,
		},
		{
			name: "VS routes to wildcard host → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vsForHost("*.example.com")},
			},
			wantFindings: 0,
		},
		{
			name: "VS TCP route to internal host missing DR → finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{{
					ObjectMeta: metav1.ObjectMeta{Name: "vs-tcp", Namespace: "app"},
					Spec: istiov1alpha3.VirtualService{
						Tcp: []*istiov1alpha3.TCPRoute{{
							Route: []*istiov1alpha3.RouteDestination{{
								Destination: &istiov1alpha3.Destination{Host: "tcp-backend"},
							}},
						}},
					},
				}},
			},
			wantFindings: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckMissingDR(tc.snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
