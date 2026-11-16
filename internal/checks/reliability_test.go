package checks

import (
	"testing"
	"time"

	durationpb "google.golang.org/protobuf/types/known/durationpb"
	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckOutlierDetection(t *testing.T) {
	outlier := &istiov1alpha3.TrafficPolicy{OutlierDetection: &istiov1alpha3.OutlierDetection{}}
	subset := func(name string, policy *istiov1alpha3.TrafficPolicy) *istiov1alpha3.Subset {
		return &istiov1alpha3.Subset{Name: name, TrafficPolicy: policy}
	}
	dr := func(policy *istiov1alpha3.TrafficPolicy, subsets ...*istiov1alpha3.Subset) *networkingv1alpha3.DestinationRule {
		return &networkingv1alpha3.DestinationRule{
			ObjectMeta: vsMeta("svc"),
			Spec:       istiov1alpha3.DestinationRule{Host: "svc", TrafficPolicy: policy, Subsets: subsets},
		}
	}

	wantOne := []wantFinding{{model.SeverityHigh, "DestinationRule/svc", "no outlier detection"}}

	tests := []struct {
		name string
		dr   *networkingv1alpha3.DestinationRule
		want []wantFinding
	}{
		{
			name: "no traffic policy",
			dr:   dr(nil),
			want: wantOne,
		},
		{
			name: "traffic policy without outlier detection",
			dr:   dr(&istiov1alpha3.TrafficPolicy{}),
			want: wantOne,
		},
		{
			name: "outlier detection configured",
			dr:   dr(outlier),
		},
		{
			name: "every subset has its own outlier detection",
			dr:   dr(nil, subset("v1", outlier), subset("v2", outlier)),
		},
		{
			name: "one subset lacks outlier detection",
			dr:   dr(nil, subset("v1", outlier), subset("v2", nil)),
			want: wantOne,
		},
		{
			name: "top-level outlier detection covers subsets without a policy",
			dr:   dr(outlier, subset("v1", nil)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{DestinationRules: drList(tc.dr)}
			assertFindings(t, NameOutlierDetection, CheckOutlierDetection(snap), tc.want...)
		})
	}
}

func TestCheckRetryWithoutTimeout(t *testing.T) {
	vs := func(rules ...*istiov1alpha3.HTTPRoute) *networkingv1alpha3.VirtualService {
		return &networkingv1alpha3.VirtualService{
			ObjectMeta: vsMeta("vs"),
			Spec:       istiov1alpha3.VirtualService{Http: rules},
		}
	}
	retries := func(n int32) *istiov1alpha3.HTTPRetry { return &istiov1alpha3.HTTPRetry{Attempts: n} }

	medium := model.SeverityMedium
	tests := []struct {
		name string
		vs   *networkingv1alpha3.VirtualService
		want []wantFinding
	}{
		{
			name: "retries with no timeout",
			vs:   vs(&istiov1alpha3.HTTPRoute{Retries: retries(3)}),
			want: []wantFinding{{medium, "VirtualService/vs", "http rule[0] has retries=3 but no timeout"}},
		},
		{
			name: "retries with timeout",
			vs:   vs(&istiov1alpha3.HTTPRoute{Retries: retries(3), Timeout: durationpb.New(10 * time.Second)}),
		},
		{
			name: "zero timeout disables the timeout",
			vs:   vs(&istiov1alpha3.HTTPRoute{Retries: retries(3), Timeout: durationpb.New(0)}),
			want: []wantFinding{{medium, "VirtualService/vs", "no timeout"}},
		},
		{
			name: "no retries",
			vs:   vs(&istiov1alpha3.HTTPRoute{}),
		},
		{
			name: "explicit attempts 0",
			vs:   vs(&istiov1alpha3.HTTPRoute{Retries: retries(0)}),
		},
		{
			name: "rule index identifies the offending rule",
			vs: vs(
				&istiov1alpha3.HTTPRoute{Retries: retries(2), Timeout: durationpb.New(5 * time.Second)},
				&istiov1alpha3.HTTPRoute{Retries: retries(2)},
			),
			want: []wantFinding{{medium, "VirtualService/vs", "http rule[1] has retries=2"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{VirtualServices: vsList(tc.vs)}
			assertFindings(t, NameRetryNoTimeout, CheckRetryWithoutTimeout(snap), tc.want...)
		})
	}
}
