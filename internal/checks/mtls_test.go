package checks

import (
	"testing"

	istiov1beta1 "istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func strictPA(name, namespace string) *securityv1beta1.PeerAuthentication {
	return &securityv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: istiov1beta1.PeerAuthentication{
			Mtls: &istiov1beta1.PeerAuthentication_MutualTLS{
				Mode: istiov1beta1.PeerAuthentication_MutualTLS_STRICT,
			},
		},
	}
}

func permissivePA(name, namespace string) *securityv1beta1.PeerAuthentication {
	return &securityv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: istiov1beta1.PeerAuthentication{
			Mtls: &istiov1beta1.PeerAuthentication_MutualTLS{
				Mode: istiov1beta1.PeerAuthentication_MutualTLS_PERMISSIVE,
			},
		},
	}
}

func TestCheckMTLS(t *testing.T) {
	tests := []struct {
		name         string
		snap         *model.Snapshot
		wantFindings int
	}{
		{
			name:         "no namespace PA and no system PA → CRITICAL",
			snap:         &model.Snapshot{Namespace: "app"},
			wantFindings: 1,
		},
		{
			name: "no namespace PA but system has STRICT PA → no finding",
			snap: &model.Snapshot{
				Namespace:       "app",
				SystemPeerAuths: []*securityv1beta1.PeerAuthentication{strictPA("default", "istio-system")},
			},
			wantFindings: 0,
		},
		{
			name: "namespace has STRICT PA → no finding",
			snap: &model.Snapshot{
				Namespace: "app",
				PeerAuths: []*securityv1beta1.PeerAuthentication{strictPA("default", "app")},
			},
			wantFindings: 0,
		},
		{
			name: "namespace has PERMISSIVE PA → CRITICAL",
			snap: &model.Snapshot{
				Namespace: "app",
				PeerAuths: []*securityv1beta1.PeerAuthentication{permissivePA("default", "app")},
			},
			wantFindings: 1,
		},
		{
			name: "no namespace PA and system only has PERMISSIVE PA → CRITICAL",
			snap: &model.Snapshot{
				Namespace:       "app",
				SystemPeerAuths: []*securityv1beta1.PeerAuthentication{permissivePA("default", "istio-system")},
			},
			wantFindings: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckMTLS(tc.snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
