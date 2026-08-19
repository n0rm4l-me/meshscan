package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func runningPod(name string, containers []string, annotations map[string]string) corev1.Pod {
	var cs []corev1.Container
	for _, c := range containers {
		cs = append(cs, corev1.Container{Name: c})
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "app",
			Annotations: annotations,
		},
		Spec:   corev1.PodSpec{Containers: cs},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestCheckSidecarCoverage(t *testing.T) {
	tests := []struct {
		name         string
		pod          corev1.Pod
		wantFindings int
	}{
		{
			name:         "running pod with istio-proxy → no finding",
			pod:          runningPod("ok", []string{"app", "istio-proxy"}, nil),
			wantFindings: 0,
		},
		{
			name:         "running pod without istio-proxy → finding",
			pod:          runningPod("no-sidecar", []string{"app"}, nil),
			wantFindings: 1,
		},
		{
			name:         "running pod opted out via annotation → no finding",
			pod:          runningPod("opt-out", []string{"app"}, map[string]string{"sidecar.istio.io/inject": "false"}),
			wantFindings: 0,
		},
		{
			name: "non-running pod without istio-proxy → no finding",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "app"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			},
			wantFindings: 0,
		},
		{
			name: "running pod with istio-proxy in InitContainers (native sidecar) → no finding",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "native-sidecar", Namespace: "app"},
				Spec: corev1.PodSpec{
					Containers:     []corev1.Container{{Name: "app"}},
					InitContainers: []corev1.Container{{Name: "istio-proxy"}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			},
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{Namespace: "app", Pods: []corev1.Pod{tc.pod}}
			got := CheckSidecarCoverage(snap)
			if len(got) != tc.wantFindings {
				t.Errorf("got %d findings, want %d", len(got), tc.wantFindings)
			}
		})
	}
}
