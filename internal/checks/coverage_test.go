package checks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

type podOpt func(*corev1.Pod)

func withAnnotations(a map[string]string) podOpt { return func(p *corev1.Pod) { p.Annotations = a } }
func withLabels(l map[string]string) podOpt      { return func(p *corev1.Pod) { p.Labels = l } }
func withHostNetwork() podOpt                    { return func(p *corev1.Pod) { p.Spec.HostNetwork = true } }
func withOwner(kind, name string) podOpt {
	return func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: name}}
	}
}

func runningPod(name string, containers []string, opts ...podOpt) corev1.Pod {
	var cs []corev1.Container
	for _, c := range containers {
		cs = append(cs, corev1.Container{Name: c})
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS},
		Spec:       corev1.PodSpec{Containers: cs},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, o := range opts {
		o(&pod)
	}
	return pod
}

func TestCheckSidecarCoverage(t *testing.T) {
	high := model.SeverityHigh
	const noSidecar = "no istio-proxy sidecar"
	ambientNS := map[string]string{"istio.io/dataplane-mode": "ambient"}

	tests := []struct {
		name     string
		pod      corev1.Pod
		nsLabels map[string]string
		want     []wantFinding
	}{
		{
			name: "running pod with istio-proxy",
			pod:  runningPod("ok", []string{"app", "istio-proxy"}),
		},
		{
			name: "running pod without istio-proxy",
			pod:  runningPod("no-sidecar", []string{"app"}),
			want: []wantFinding{{high, "Pod/no-sidecar", noSidecar}},
		},
		{
			name: "opted out via annotation",
			pod:  runningPod("opt-out", []string{"app"}, withAnnotations(map[string]string{"sidecar.istio.io/inject": "false"})),
		},
		{
			name: "opted out via label",
			pod:  runningPod("opt-out", []string{"app"}, withLabels(map[string]string{"sidecar.istio.io/inject": "false"})),
		},
		{
			name: "inject=true annotation does not hide a missing sidecar",
			pod:  runningPod("wants-sidecar", []string{"app"}, withAnnotations(map[string]string{"sidecar.istio.io/inject": "true"})),
			want: []wantFinding{{high, "Pod/wants-sidecar", noSidecar}},
		},
		{
			name: "non-running pod",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: testNS},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			},
		},
		{
			name: "istio-proxy in InitContainers (native sidecar)",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "native-sidecar", Namespace: testNS},
				Spec: corev1.PodSpec{
					Containers:     []corev1.Container{{Name: "app"}},
					InitContainers: []corev1.Container{{Name: "istio-proxy"}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			},
		},
		{
			name: "host network pod cannot be injected",
			pod:  runningPod("node-agent", []string{"agent"}, withHostNetwork()),
		},
		{
			name:     "namespace enrolled in ambient mode",
			pod:      runningPod("ambient", []string{"app"}),
			nsLabels: ambientNS,
		},
		{
			name: "pod enrolled in ambient mode",
			pod:  runningPod("ambient", []string{"app"}, withLabels(map[string]string{"istio.io/dataplane-mode": "ambient"})),
		},
		{
			name:     "pod excluded from the mesh in an ambient namespace",
			pod:      runningPod("excluded", []string{"app"}, withLabels(map[string]string{"istio.io/dataplane-mode": "none"})),
			nsLabels: ambientNS,
		},
		{
			name:     "unrelated namespace labels do not hide a missing sidecar",
			pod:      runningPod("no-sidecar", []string{"app"}),
			nsLabels: map[string]string{"istio-injection": "enabled"},
			want:     []wantFinding{{high, "Pod/no-sidecar", noSidecar}},
		},
		{
			name: "owner is named in the message",
			pod:  runningPod("web-1", []string{"app"}, withOwner("ReplicaSet", "web")),
			want: []wantFinding{{high, "Pod/web-1", "(owner: ReplicaSet/web)"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := &model.Snapshot{Namespace: testNS, NamespaceLabels: tc.nsLabels, Pods: []corev1.Pod{tc.pod}}
			got := CheckSidecarCoverage(snap)
			assertFindings(t, NameSidecarCoverage, got, tc.want...)
			for _, f := range got {
				if f.Namespace != testNS {
					t.Errorf("finding namespace = %q, want %q", f.Namespace, testNS)
				}
			}
		})
	}
}
