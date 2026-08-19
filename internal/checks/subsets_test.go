package checks

import (
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckDeadSubsets(t *testing.T) {
	vs := func(host, subset string) *networkingv1alpha3.VirtualService {
		return &networkingv1alpha3.VirtualService{
			ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
			Spec: istiov1alpha3.VirtualService{
				Http: []*istiov1alpha3.HTTPRoute{{
					Route: []*istiov1alpha3.HTTPRouteDestination{{
						Destination: &istiov1alpha3.Destination{Host: host, Subset: subset},
					}},
				}},
			},
		}
	}

	dr := func(host string, subsets ...string) *networkingv1alpha3.DestinationRule {
		var ss []*istiov1alpha3.Subset
		for _, s := range subsets {
			ss = append(ss, &istiov1alpha3.Subset{Name: s})
		}
		return &networkingv1alpha3.DestinationRule{
			ObjectMeta: metav1.ObjectMeta{Name: host, Namespace: "app"},
			Spec:       istiov1alpha3.DestinationRule{Host: host, Subsets: ss},
		}
	}

	tests := []struct {
		name         string
		snap         *model.Snapshot
		wantFindings int
	}{
		{
			name: "VS routes to defined subset → no finding",
			snap: &model.Snapshot{
				VirtualServices:  []*networkingv1alpha3.VirtualService{vs("svc", "v1")},
				DestinationRules: []*networkingv1alpha3.DestinationRule{dr("svc", "v1")},
			},
			wantFindings: 0,
		},
		{
			name: "VS routes to undefined subset → finding",
			snap: &model.Snapshot{
				VirtualServices:  []*networkingv1alpha3.VirtualService{vs("svc", "v2")},
				DestinationRules: []*networkingv1alpha3.DestinationRule{dr("svc", "v1")},
			},
			wantFindings: 1,
		},
		{
			name: "VS routes to host with no DR at all → finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("missing-svc", "v1")},
			},
			wantFindings: 1,
		},
		{
			name: "VS routes without subset (no DR) → no finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{vs("svc", "")},
			},
			wantFindings: 0,
		},
		{
			name: "VS TCP route to host with no DR → finding",
			snap: &model.Snapshot{
				VirtualServices: []*networkingv1alpha3.VirtualService{{
					ObjectMeta: metav1.ObjectMeta{Name: "vs-tcp", Namespace: "app"},
					Spec: istiov1alpha3.VirtualService{
						Tcp: []*istiov1alpha3.TCPRoute{{
							Route: []*istiov1alpha3.RouteDestination{{
								Destination: &istiov1alpha3.Destination{Host: "tcp-svc", Subset: "v1"},
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
			got := CheckDeadSubsets(tc.snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
