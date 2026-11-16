package checks

import (
	"testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestCheckDeadSubsets(t *testing.T) {
	const noDR = "but no DestinationRule exists"
	const notDefined = "does not define that subset"

	tests := []struct {
		name string
		snap *model.Snapshot
		want []wantFinding
	}{
		{
			name: "VS routes to defined subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "v1")), DestinationRules: drList(newDR("svc", "svc", "v1"))},
		},
		{
			name: "VS routes to undefined subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "v2")), DestinationRules: drList(newDR("svc-dr", "svc", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs", notDefined}},
		},
		{
			name: "VS routes to host with no DR at all",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "missing-svc", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs", noDR}},
		},
		{
			name: "VS routes without subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", ""))},
		},
		{
			name: "TCP route to host with no DR",
			snap: &model.Snapshot{VirtualServices: vsList(tcpVS("vs-tcp", "tcp-svc", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs-tcp", noDR}},
		},
		{
			name: "TLS route to host with no DR",
			snap: &model.Snapshot{VirtualServices: vsList(tlsVS("vs-tls", "tls-svc", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs-tls", noDR}},
		},
		{
			name: "FQDN in VS matches short host in DR",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.app.svc.cluster.local", "v1")), DestinationRules: drList(newDR("dr", "svc", "v1"))},
		},
		{
			name: "short host in VS matches FQDN in DR",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc", "v1")), DestinationRules: drList(newDR("dr", "svc.app.svc.cluster.local", "v1"))},
		},
		{
			name: "host matching is case-insensitive",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "Svc", "v1")), DestinationRules: drList(newDR("dr", "svc", "v1"))},
		},
		{
			name: "other-namespace service without a visible DR cannot be judged",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.other.svc.cluster.local", "v1"))},
		},
		{
			name: "other-namespace service with a visible DR missing the subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.other.svc.cluster.local", "v2")), DestinationRules: drList(newDR("dr", "svc.other.svc.cluster.local", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs", notDefined}},
		},
		{
			name: "external host without a DR cannot be judged",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "api.example.com", "v1"))},
		},
		{
			name: "external host with a DR missing the subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "api.example.com", "v2")), DestinationRules: drList(newDR("dr", "api.example.com", "v1"))},
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs", notDefined}},
		},
		{
			name: "subsets of several DRs for one host are merged",
			snap: &model.Snapshot{
				VirtualServices:  vsList(httpVS("vs", "svc", "v2")),
				DestinationRules: drList(newDR("dr-a", "svc", "v1"), newDR("dr-b", "svc", "v2")),
			},
		},
		{
			name: "wildcard DR defines the subset",
			snap: &model.Snapshot{VirtualServices: vsList(httpVS("vs", "svc.other.svc.cluster.local", "v1")), DestinationRules: drList(newDR("dr", "*.other.svc.cluster.local", "v1"))},
		},
		{
			name: "same dead route reported once per VS",
			snap: func() *model.Snapshot {
				vs := httpVS("vs", "svc", "v9")
				vs.Spec.Http = append(vs.Spec.Http, vs.Spec.Http[0])
				return &model.Snapshot{VirtualServices: vsList(vs), DestinationRules: drList(newDR("dr", "svc", "v1"))}
			}(),
			want: []wantFinding{{model.SeverityHigh, "VirtualService/vs", notDefined}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, NameDeadSubsets, CheckDeadSubsets(tc.snap), tc.want...)
		})
	}
}

func TestCheckDeadSubsetsFixNamesTheRule(t *testing.T) {
	snap := &model.Snapshot{
		VirtualServices:  vsList(httpVS("vs", "svc", "v2")),
		DestinationRules: drList(newDR("svc-rule", "svc", "v1")),
	}
	got := CheckDeadSubsets(snap)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if want := "add subset v2 to DestinationRule/svc-rule"; got[0].Fix != want {
		t.Errorf("fix = %q, want %q", got[0].Fix, want)
	}
}
