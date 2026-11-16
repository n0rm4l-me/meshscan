package checks

import (
	"strings"
	"testing"
	"time"

	istiov1beta1 "istio.io/api/security/v1beta1"
	typev1beta1 "istio.io/api/type/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const (
	modeUnset      = istiov1beta1.PeerAuthentication_MutualTLS_UNSET
	modePermissive = istiov1beta1.PeerAuthentication_MutualTLS_PERMISSIVE
	modeStrict     = istiov1beta1.PeerAuthentication_MutualTLS_STRICT
	modeDisable    = istiov1beta1.PeerAuthentication_MutualTLS_DISABLE
)

func peerAuth(name, namespace string, mode istiov1beta1.PeerAuthentication_MutualTLS_Mode) *securityv1beta1.PeerAuthentication {
	return &securityv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: istiov1beta1.PeerAuthentication{
			Mtls: &istiov1beta1.PeerAuthentication_MutualTLS{Mode: mode},
		},
	}
}

// scopedPA is a workload-scoped PeerAuthentication (it has a selector).
func scopedPA(name, namespace string, mode istiov1beta1.PeerAuthentication_MutualTLS_Mode) *securityv1beta1.PeerAuthentication {
	pa := peerAuth(name, namespace, mode)
	pa.Spec.Selector = &typev1beta1.WorkloadSelector{MatchLabels: map[string]string{"app": "legacy"}}
	return pa
}

func createdAt(pa *securityv1beta1.PeerAuthentication, t time.Time) *securityv1beta1.PeerAuthentication {
	pa.CreationTimestamp = metav1.NewTime(t)
	return pa
}

func pas(p ...*securityv1beta1.PeerAuthentication) []*securityv1beta1.PeerAuthentication {
	return p
}

func TestCheckMTLS(t *testing.T) {
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := old.Add(24 * time.Hour)
	crit := model.SeverityCritical

	tests := []struct {
		name string
		snap *model.Snapshot
		want []wantFinding
	}{
		{
			name: "no PA anywhere",
			snap: &model.Snapshot{Namespace: "app"},
			want: []wantFinding{{crit, "PeerAuthentication", "no PeerAuthentication found"}},
		},
		{
			name: "no namespace PA but mesh-wide STRICT",
			snap: &model.Snapshot{Namespace: "app", SystemPeerAuths: pas(peerAuth("default", "istio-system", modeStrict))},
		},
		{
			name: "no namespace PA and mesh-wide PERMISSIVE",
			snap: &model.Snapshot{Namespace: "app", SystemPeerAuths: pas(peerAuth("default", "istio-system", modePermissive))},
			want: []wantFinding{{crit, "PeerAuthentication", "no PeerAuthentication found"}},
		},
		{
			name: "no namespace PA and mesh-wide UNSET falls back to PERMISSIVE",
			snap: &model.Snapshot{Namespace: "app", SystemPeerAuths: pas(peerAuth("default", "istio-system", modeUnset))},
			want: []wantFinding{{crit, "PeerAuthentication", "no PeerAuthentication found"}},
		},
		{
			name: "mesh-wide workload-scoped STRICT does not protect the mesh",
			snap: &model.Snapshot{Namespace: "app", SystemPeerAuths: pas(scopedPA("one-app", "istio-system", modeStrict))},
			want: []wantFinding{{crit, "PeerAuthentication", "no PeerAuthentication found"}},
		},
		{
			name: "namespace STRICT",
			snap: &model.Snapshot{Namespace: "app", PeerAuths: pas(peerAuth("default", "app", modeStrict))},
		},
		{
			name: "namespace PERMISSIVE",
			snap: &model.Snapshot{Namespace: "app", PeerAuths: pas(peerAuth("default", "app", modePermissive))},
			want: []wantFinding{{crit, "PeerAuthentication/default", "namespace-wide PeerAuthentication is PERMISSIVE"}},
		},
		{
			name: "namespace PERMISSIVE overrides mesh-wide STRICT",
			snap: &model.Snapshot{
				Namespace:       "app",
				PeerAuths:       pas(peerAuth("default", "app", modePermissive)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modeStrict)),
			},
			want: []wantFinding{{crit, "PeerAuthentication/default", "PERMISSIVE"}},
		},
		{
			name: "namespace DISABLE",
			snap: &model.Snapshot{Namespace: "app", PeerAuths: pas(peerAuth("default", "app", modeDisable))},
			want: []wantFinding{{crit, "PeerAuthentication/default", "is DISABLE"}},
		},
		{
			name: "namespace UNSET inherits mesh-wide STRICT",
			snap: &model.Snapshot{
				Namespace:       "app",
				PeerAuths:       pas(peerAuth("default", "app", modeUnset)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modeStrict)),
			},
		},
		{
			name: "namespace UNSET inherits the PERMISSIVE default",
			snap: &model.Snapshot{Namespace: "app", PeerAuths: pas(peerAuth("default", "app", modeUnset))},
			want: []wantFinding{{crit, "PeerAuthentication/default", "inherits PERMISSIVE"}},
		},
		{
			name: "only workload-scoped PAs and nothing above",
			snap: &model.Snapshot{Namespace: "app", PeerAuths: pas(scopedPA("legacy", "app", modeStrict))},
			want: []wantFinding{{crit, "PeerAuthentication", "only workload-scoped"}},
		},
		{
			name: "only workload-scoped PAs but mesh-wide STRICT",
			snap: &model.Snapshot{
				Namespace:       "app",
				PeerAuths:       pas(scopedPA("legacy", "app", modePermissive)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modeStrict)),
			},
		},
		{
			name: "workload-scoped PERMISSIVE next to namespace STRICT is not judged",
			snap: &model.Snapshot{
				Namespace: "app",
				PeerAuths: pas(peerAuth("default", "app", modeStrict), scopedPA("legacy", "app", modePermissive)),
			},
		},
		{
			name: "oldest namespace-wide PA wins: STRICT is oldest",
			snap: &model.Snapshot{
				Namespace: "app",
				PeerAuths: pas(
					createdAt(peerAuth("new", "app", modePermissive), recent),
					createdAt(peerAuth("old", "app", modeStrict), old),
				),
			},
		},
		{
			name: "oldest namespace-wide PA wins: PERMISSIVE is oldest",
			snap: &model.Snapshot{
				Namespace: "app",
				PeerAuths: pas(
					createdAt(peerAuth("new", "app", modeStrict), recent),
					createdAt(peerAuth("old", "app", modePermissive), old),
				),
			},
			want: []wantFinding{{crit, "PeerAuthentication/old", "PERMISSIVE"}},
		},
		{
			name: "istio-system STRICT mesh-wide PA",
			snap: &model.Snapshot{
				Namespace:       "istio-system",
				PeerAuths:       pas(peerAuth("default", "istio-system", modeStrict)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modeStrict)),
			},
		},
		{
			name: "istio-system PERMISSIVE mesh-wide PA",
			snap: &model.Snapshot{
				Namespace:       "istio-system",
				PeerAuths:       pas(peerAuth("default", "istio-system", modePermissive)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modePermissive)),
			},
			want: []wantFinding{{crit, "PeerAuthentication/default", "mesh-wide PeerAuthentication is PERMISSIVE"}},
		},
		{
			name: "istio-system UNSET has nothing above it",
			snap: &model.Snapshot{
				Namespace:       "istio-system",
				PeerAuths:       pas(peerAuth("default", "istio-system", modeUnset)),
				SystemPeerAuths: pas(peerAuth("default", "istio-system", modeUnset)),
			},
			want: []wantFinding{{crit, "PeerAuthentication/default", "inherits PERMISSIVE"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckMTLS(tc.snap)
			assertFindings(t, NameMTLS, got, tc.want...)
			for _, f := range got {
				if f.Namespace != tc.snap.Namespace {
					t.Errorf("finding namespace = %q, want %q", f.Namespace, tc.snap.Namespace)
				}
			}
		})
	}
}

func TestCheckMTLSFixIsApplicable(t *testing.T) {
	got := CheckMTLS(&model.Snapshot{Namespace: "payments"})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	for _, want := range []string{"kind: PeerAuthentication", "namespace: payments", "mode: STRICT"} {
		if !strings.Contains(got[0].Fix, want) {
			t.Errorf("fix does not contain %q:\n%s", want, got[0].Fix)
		}
	}
}
