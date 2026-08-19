package checks

import (
	"testing"
	"time"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	durationpb "google.golang.org/protobuf/types/known/durationpb"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckOutlierDetection(t *testing.T) {
	tests := []struct {
		name         string
		dr           *networkingv1alpha3.DestinationRule
		wantFindings int
	}{
		{
			name: "no traffic policy → finding",
			dr: &networkingv1alpha3.DestinationRule{
				ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "app"},
				Spec:       istiov1alpha3.DestinationRule{Host: "svc"},
			},
			wantFindings: 1,
		},
		{
			name: "traffic policy without outlier detection → finding",
			dr: &networkingv1alpha3.DestinationRule{
				ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "app"},
				Spec: istiov1alpha3.DestinationRule{
					Host:          "svc",
					TrafficPolicy: &istiov1alpha3.TrafficPolicy{},
				},
			},
			wantFindings: 1,
		},
		{
			name: "outlier detection configured → no finding",
			dr: &networkingv1alpha3.DestinationRule{
				ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "app"},
				Spec: istiov1alpha3.DestinationRule{
					Host: "svc",
					TrafficPolicy: &istiov1alpha3.TrafficPolicy{
						OutlierDetection: &istiov1alpha3.OutlierDetection{},
					},
				},
			},
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{DestinationRules: []*networkingv1alpha3.DestinationRule{tc.dr}}
			got := CheckOutlierDetection(snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}

func TestCheckRetryWithoutTimeout(t *testing.T) {
	tests := []struct {
		name         string
		vs           *networkingv1alpha3.VirtualService
		wantFindings int
	}{
		{
			name: "retries with no timeout → finding",
			vs: &networkingv1alpha3.VirtualService{
				ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
				Spec: istiov1alpha3.VirtualService{
					Http: []*istiov1alpha3.HTTPRoute{{
						Retries: &istiov1alpha3.HTTPRetry{Attempts: 3},
					}},
				},
			},
			wantFindings: 1,
		},
		{
			name: "retries with timeout → no finding",
			vs: &networkingv1alpha3.VirtualService{
				ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
				Spec: istiov1alpha3.VirtualService{
					Http: []*istiov1alpha3.HTTPRoute{{
						Retries: &istiov1alpha3.HTTPRetry{Attempts: 3},
						Timeout: durationpb.New(10 * time.Second),
					}},
				},
			},
			wantFindings: 0,
		},
		{
			name: "no retries → no finding",
			vs: &networkingv1alpha3.VirtualService{
				ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
				Spec: istiov1alpha3.VirtualService{
					Http: []*istiov1alpha3.HTTPRoute{{}},
				},
			},
			wantFindings: 0,
		},
		{
			name: "explicit Attempts:0 → no finding",
			vs: &networkingv1alpha3.VirtualService{
				ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: "app"},
				Spec: istiov1alpha3.VirtualService{
					Http: []*istiov1alpha3.HTTPRoute{{
						Retries: &istiov1alpha3.HTTPRetry{Attempts: 0},
					}},
				},
			},
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{VirtualServices: []*networkingv1alpha3.VirtualService{tc.vs}}
			got := CheckRetryWithoutTimeout(snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
