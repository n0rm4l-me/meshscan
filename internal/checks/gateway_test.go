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
		return &networkingv1alpha3.Gateway{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS}}
	}
	vs := func(name string, gateways ...string) *networkingv1alpha3.VirtualService {
		return &networkingv1alpha3.VirtualService{
			ObjectMeta: vsMeta(name),
			Spec:       istiov1alpha3.VirtualService{Gateways: gateways, Hosts: []string{"example.com"}},
		}
	}
	gws := func(g ...*networkingv1alpha3.Gateway) []*networkingv1alpha3.Gateway { return g }

	high := model.SeverityHigh
	tests := []struct {
		name string
		snap *model.Snapshot
		want []wantFinding
	}{
		{
			name: "references existing gateway",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "my-gateway")), Gateways: gws(gw("my-gateway"))},
		},
		{
			name: "references missing gateway",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "missing-gateway"))},
			want: []wantFinding{{high, "VirtualService/vs", "Gateway/missing-gateway"}},
		},
		{
			name: "mesh entry is not a gateway",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "mesh"))},
		},
		{
			name: "cross-namespace reference cannot be verified",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "istio-system/ingress-gateway"))},
		},
		{
			name: "no gateways field",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs"))},
		},
		{
			name: "mesh plus a missing gateway",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "mesh", "missing-gw"))},
			want: []wantFinding{{high, "VirtualService/vs", "Gateway/missing-gw"}},
		},
		{
			name: "namespace/name form pointing at own namespace, missing",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "app/edge"))},
			want: []wantFinding{{high, "VirtualService/vs", "Gateway/edge"}},
		},
		{
			name: "namespace/name form pointing at own namespace, present",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "app/edge")), Gateways: gws(gw("edge"))},
		},
		{
			name: "dot namespace means the current namespace, missing",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "./edge"))},
			want: []wantFinding{{high, "VirtualService/vs", "Gateway/edge"}},
		},
		{
			name: "dot namespace means the current namespace, present",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "./edge")), Gateways: gws(gw("edge"))},
		},
		{
			name: "FQDN form in own namespace, present",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "edge.app.svc.cluster.local")), Gateways: gws(gw("edge"))},
		},
		{
			name: "FQDN form in own namespace, missing",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "edge.app.svc.cluster.local"))},
			want: []wantFinding{{high, "VirtualService/vs", "Gateway/edge"}},
		},
		{
			name: "FQDN form in another namespace cannot be verified",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "edge.other.svc.cluster.local"))},
		},
		{
			name: "every missing reference is reported",
			snap: &model.Snapshot{VirtualServices: vsList(vs("vs", "gw-a", "gw-b"))},
			want: []wantFinding{
				{high, "VirtualService/vs", "Gateway/gw-a"},
				{high, "VirtualService/vs", "Gateway/gw-b"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, NameGatewayMissing, CheckMissingGateway(tc.snap), tc.want...)
		})
	}
}
