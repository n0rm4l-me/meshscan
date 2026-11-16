package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestSuppress(t *testing.T) {
	ignore := func(v string) map[string]string { return map[string]string{IgnoreAnnotation: v} }

	vs := httpVS("vs", "svc", "")
	vs.Annotations = ignore("missing-dr, Retry-Without-Timeout")
	other := httpVS("other", "svc", "")
	dr := newDR("svc", "svc")
	dr.Annotations = ignore("*")
	pod := runningPod("bare", []string{"app"}, withAnnotations(ignore("sidecar-coverage")))

	snap := &model.Snapshot{
		Namespace:        testNS,
		VirtualServices:  vsList(vs, other),
		DestinationRules: drList(dr),
		Pods:             []corev1.Pod{pod},
	}

	findings := []model.Finding{
		{Check: NameMissingDR, Resource: "VirtualService/vs"},           // suppressed: listed
		{Check: NameRetryNoTimeout, Resource: "VirtualService/vs"},      // suppressed: listed, case and spaces ignored
		{Check: NameDeadSubsets, Resource: "VirtualService/vs"},         // kept: not listed
		{Check: NameMissingDR, Resource: "VirtualService/other"},        // kept: other resource has no annotation
		{Check: NameOutlierDetection, Resource: "DestinationRule/svc"},  // suppressed: wildcard
		{Check: NameSidecarCoverage, Resource: "Pod/bare"},              // suppressed: pod annotation
		{Check: NameMTLS, Resource: "PeerAuthentication"},               // kept: no resource, no namespace annotation
		{Check: NameGatewayMissing, Resource: "VirtualService/unknown"}, // kept: resource not in snapshot
	}

	kept, suppressed := Suppress(snap, findings)
	if suppressed != 4 {
		t.Errorf("suppressed = %d, want 4", suppressed)
	}
	wantKept := []string{NameDeadSubsets, NameMissingDR, NameMTLS, NameGatewayMissing}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept %d findings, want %d: %+v", len(kept), len(wantKept), kept)
	}
	for i, w := range wantKept {
		if kept[i].Check != w {
			t.Errorf("kept[%d].Check = %s, want %s", i, kept[i].Check, w)
		}
	}
}

func TestSuppressByNamespaceAnnotation(t *testing.T) {
	snap := &model.Snapshot{
		Namespace:            testNS,
		NamespaceAnnotations: map[string]string{IgnoreAnnotation: "mtls-enforcement,sidecar-coverage"},
	}
	findings := []model.Finding{
		{Check: NameMTLS, Resource: "PeerAuthentication"},
		{Check: NameSidecarCoverage, Resource: "Pod/anything"},
		{Check: NameMissingDR, Resource: "VirtualService/vs"},
	}
	kept, suppressed := Suppress(snap, findings)
	if suppressed != 2 || len(kept) != 1 || kept[0].Check != NameMissingDR {
		t.Errorf("kept=%+v suppressed=%d, want only missing-dr kept and 2 suppressed", kept, suppressed)
	}
}

func TestSuppressNamespaceWildcard(t *testing.T) {
	snap := &model.Snapshot{NamespaceAnnotations: map[string]string{IgnoreAnnotation: "all"}}
	kept, suppressed := Suppress(snap, []model.Finding{{Check: NameMTLS}, {Check: NameMissingDR}})
	if len(kept) != 0 || suppressed != 2 {
		t.Errorf("kept=%+v suppressed=%d, want nothing kept", kept, suppressed)
	}
}

func TestSuppressWithoutAnnotationsKeepsEverything(t *testing.T) {
	findings := []model.Finding{{Check: NameMTLS}, {Check: NameMissingDR}}
	kept, suppressed := Suppress(&model.Snapshot{}, findings)
	if len(kept) != 2 || suppressed != 0 {
		t.Errorf("kept=%+v suppressed=%d, want all kept", kept, suppressed)
	}
}

func TestSuppressNoFindings(t *testing.T) {
	kept, suppressed := Suppress(&model.Snapshot{}, nil)
	if kept != nil || suppressed != 0 {
		t.Errorf("kept=%+v suppressed=%d, want nil and 0", kept, suppressed)
	}
}
