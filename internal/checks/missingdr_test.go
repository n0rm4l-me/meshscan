package checks

import (
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckMissingDR(t *testing.T) {
	const msg = "but no DestinationRule"

	tests := []struct {
		name string
		snap *model.Snapshot
		want []wantFinding
	}{
		{
			name: "VS host has a DR",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "")), DestinationRules: drList(newDR("svc", "svc"))},
		},
		{
			name: "internal host missing DR",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", ""))},
			want: []wantFinding{{model.SeverityMedium, "VirtualService/vs", msg}},
		},
		{
			name: "external FQDN is skipped",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "api.example.com", ""))},
		},
		{
			name: "wildcard host is skipped",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "*.example.com", ""))},
		},
		{
			name: "TCP route to internal host missing DR",
			snap: &model.Snapshot{VirtualServices: vsList(tcpVS("vs-tcp", "tcp-backend", ""))},
			want: []wantFinding{{model.SeverityMedium, "VirtualService/vs-tcp", msg}},
		},
		{
			name: "TLS route to internal host missing DR",
			snap: &model.Snapshot{VirtualServices: vsList(tlsVS("vs-tls", "tls-backend", ""))},
			want: []wantFinding{{model.SeverityMedium, "VirtualService/vs-tls", msg}},
		},
		{
			name: "same-namespace FQDN missing DR",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.app.svc.cluster.local", ""))},
			want: []wantFinding{{model.SeverityMedium, "VirtualService/vs", msg}},
		},
		{
			name: "same-namespace FQDN matches short DR host",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.app.svc.cluster.local", "")), DestinationRules: drList(newDR("dr", "svc"))},
		},
		{
			name: "short VS host matches FQDN DR host",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "")), DestinationRules: drList(newDR("dr", "svc.app.svc.cluster.local"))},
		},
		{
			name: "other-namespace FQDN cannot be judged",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.other.svc.cluster.local", ""))},
		},
		{
			name: "wildcard DR covers the host",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "")), DestinationRules: drList(newDR("dr", "*.app.svc.cluster.local"))},
		},
		{
			name: "every VS missing the DR is reported",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs-a", "svc", ""), httpVS("vs-b", "svc", ""))},
			want: []wantFinding{
				{model.SeverityMedium, "VirtualService/vs-a", msg},
				{model.SeverityMedium, "VirtualService/vs-b", msg},
			},
		},
		{
			name: "one VS routing twice to the same host is reported once",
			snap: func() *model.Snapshot {
				vs := httpVS("vs", "svc", "")
				vs.Spec.Http = append(vs.Spec.Http, vs.Spec.Http[0])
				return &model.Snapshot{VirtualServices: vsList(vs)}
			}(),
			want: []wantFinding{{model.SeverityMedium, "VirtualService/vs", msg}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, NameMissingDR, CheckMissingDR(tc.snap), tc.want...)
		})
	}
}
