package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	istiosecurity "istio.io/api/security/v1beta1"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func meta(name, ns string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: ns} }

// newFixture builds fake clients holding resources in "app", a little noise in
// "other", and a mesh-wide STRICT PeerAuthentication in istio-system.
func newFixture() (*k8sfake.Clientset, *istiofake.Clientset) {
	k8s := k8sfake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "zeta", Labels: map[string]string{"team": "z"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:        "app",
			Labels:      map[string]string{"istio-injection": "enabled"},
			Annotations: map[string]string{"meshscan.io/ignore": "missing-dr"},
		}},
		&corev1.Pod{ObjectMeta: meta("app-pod", "app")},
		&corev1.Pod{ObjectMeta: meta("other-pod", "other")},
	)
	istio := istiofake.NewSimpleClientset(
		&networkingv1alpha3.VirtualService{ObjectMeta: meta("app-vs", "app"), Spec: istiov1alpha3.VirtualService{Hosts: []string{"a"}}},
		&networkingv1alpha3.VirtualService{ObjectMeta: meta("other-vs", "other")},
		&networkingv1alpha3.DestinationRule{ObjectMeta: meta("app-dr", "app")},
		&networkingv1alpha3.EnvoyFilter{ObjectMeta: meta("app-ef", "app")},
		&securityv1beta1.PeerAuthentication{ObjectMeta: meta("app-pa", "app")},
		&securityv1beta1.PeerAuthentication{
			ObjectMeta: meta("default", "istio-system"),
			Spec: istiosecurity.PeerAuthentication{
				Mtls: &istiosecurity.PeerAuthentication_MutualTLS{Mode: istiosecurity.PeerAuthentication_MutualTLS_STRICT},
			},
		},
	)
	// The fake tracker guesses resource names from kinds and turns Gateway into
	// "gatewaies", so register the Gateway under its real resource name.
	gateways := schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "gateways"}
	if err := istio.Tracker().Create(gateways, &networkingv1alpha3.Gateway{ObjectMeta: meta("app-gw", "app")}, "app"); err != nil {
		panic(err)
	}
	return k8s, istio
}

func newTestCollector(k8s *k8sfake.Clientset, istio *istiofake.Clientset) (*Collector, *bytes.Buffer) {
	warn := &bytes.Buffer{}
	return NewWithClients(k8s, istio, 0, warn), warn
}

func countSystemPAListCalls(istio *istiofake.Clientset) int {
	n := 0
	for _, a := range istio.Actions() {
		if a.Matches("list", "peerauthentications") && a.GetNamespace() == "istio-system" {
			n++
		}
	}
	return n
}

func forbidden(resource string) error {
	return k8serrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("rbac: access denied"))
}

func TestCollectGathersOnlyTheRequestedNamespace(t *testing.T) {
	k8s, istio := newFixture()
	c, warn := newTestCollector(k8s, istio)

	ns := model.Namespace{Name: "app", Labels: map[string]string{"istio-injection": "enabled"}, Annotations: map[string]string{"a": "b"}}
	snap, err := c.Collect(context.Background(), ns)
	if err != nil {
		t.Fatal(err)
	}

	if snap.Namespace != "app" {
		t.Errorf("Namespace = %q", snap.Namespace)
	}
	if snap.NamespaceLabels["istio-injection"] != "enabled" || snap.NamespaceAnnotations["a"] != "b" {
		t.Errorf("namespace metadata not carried over: %v %v", snap.NamespaceLabels, snap.NamespaceAnnotations)
	}
	counts := map[string][2]int{
		"VirtualServices":  {len(snap.VirtualServices), 1},
		"DestinationRules": {len(snap.DestinationRules), 1},
		"Gateways":         {len(snap.Gateways), 1},
		"EnvoyFilters":     {len(snap.EnvoyFilters), 1},
		"PeerAuths":        {len(snap.PeerAuths), 1},
		"Pods":             {len(snap.Pods), 1},
		"SystemPeerAuths":  {len(snap.SystemPeerAuths), 1},
	}
	for what, n := range counts {
		if n[0] != n[1] {
			t.Errorf("%s: got %d, want %d", what, n[0], n[1])
		}
	}
	if snap.VirtualServices[0].Name != "app-vs" || snap.Pods[0].Name != "app-pod" {
		t.Errorf("collected resources from the wrong namespace: %s, %s", snap.VirtualServices[0].Name, snap.Pods[0].Name)
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warnings: %q", warn.String())
	}
}

func TestSystemPeerAuthsAreFetchedOnceAndShared(t *testing.T) {
	k8s, istio := newFixture()
	c, _ := newTestCollector(k8s, istio)

	a, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Collect(context.Background(), model.Namespace{Name: "other"})
	if err != nil {
		t.Fatal(err)
	}

	if n := countSystemPAListCalls(istio); n != 1 {
		t.Errorf("istio-system PeerAuthentications listed %d times, want 1", n)
	}
	if len(a.SystemPeerAuths) != 1 || len(b.SystemPeerAuths) != 1 {
		t.Errorf("system PAs missing: %d and %d", len(a.SystemPeerAuths), len(b.SystemPeerAuths))
	}
}

func TestSystemPeerAuthsForbiddenWarnsOnceAndScanContinues(t *testing.T) {
	k8s, istio := newFixture()
	istio.PrependReactor("list", "peerauthentications", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "istio-system" {
			return true, nil, forbidden("peerauthentications")
		}
		return false, nil, nil
	})
	c, warn := newTestCollector(k8s, istio)

	for _, name := range []string{"app", "other"} {
		snap, err := c.Collect(context.Background(), model.Namespace{Name: name})
		if err != nil {
			t.Fatalf("Collect(%s): %v", name, err)
		}
		if len(snap.SystemPeerAuths) != 0 {
			t.Errorf("Collect(%s): system PAs should be empty, got %d", name, len(snap.SystemPeerAuths))
		}
	}

	if got := strings.Count(warn.String(), "no access to istio-system PeerAuthentications"); got != 1 {
		t.Errorf("warning printed %d times, want once; output: %q", got, warn.String())
	}
	if n := countSystemPAListCalls(istio); n != 1 {
		t.Errorf("forbidden result not cached: %d list calls", n)
	}
}

func TestSystemPeerAuthsTransientErrorIsNotCached(t *testing.T) {
	k8s, istio := newFixture()
	calls := 0
	istio.PrependReactor("list", "peerauthentications", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "istio-system" {
			return false, nil, nil
		}
		calls++
		if calls == 1 {
			return true, nil, errors.New("connection reset")
		}
		return false, nil, nil
	})
	c, _ := newTestCollector(k8s, istio)

	_, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
	if err == nil || !strings.Contains(err.Error(), "system PeerAuthentications") || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v, want a system PeerAuthentications error", err)
	}

	snap, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
	if err != nil {
		t.Fatalf("second Collect should retry and succeed: %v", err)
	}
	if len(snap.SystemPeerAuths) != 1 {
		t.Errorf("system PAs = %d, want 1", len(snap.SystemPeerAuths))
	}
}

func TestCollectErrorsNameTheFailingResource(t *testing.T) {
	for _, resource := range []string{"virtualservices", "destinationrules", "gateways", "envoyfilters", "peerauthentications", "pods"} {
		t.Run(resource, func(t *testing.T) {
			k8s, istio := newFixture()
			failing := &istio.Fake
			if resource == "pods" {
				failing = &k8s.Fake
			}
			failing.PrependReactor("list", resource, func(a k8stesting.Action) (bool, runtime.Object, error) {
				if a.GetNamespace() == "app" {
					return true, nil, forbidden(resource)
				}
				return false, nil, nil
			})
			c, _ := newTestCollector(k8s, istio)

			_, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), "list ") || !strings.Contains(err.Error(), "forbidden") {
				t.Errorf("error does not describe the failed list: %v", err)
			}
			if !k8serrors.IsForbidden(err) {
				t.Errorf("wrapped error lost its Forbidden reason: %v", err)
			}
		})
	}
}

func TestCollectMissingCRDGetsAHint(t *testing.T) {
	k8s, istio := newFixture()
	istio.PrependReactor("list", "virtualservices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewNotFound(schema.GroupResource{Group: "networking.istio.io", Resource: "virtualservices"}, "")
	})
	c, _ := newTestCollector(k8s, istio)

	_, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
	if err == nil || !strings.Contains(err.Error(), "is this resource type installed") {
		t.Errorf("err = %v, want a hint about missing CRDs", err)
	}
}

func TestListNamespacesIsSortedAndCarriesMetadata(t *testing.T) {
	k8s, istio := newFixture()
	c, _ := newTestCollector(k8s, istio)

	got, err := c.ListNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "app" || got[1].Name != "zeta" {
		t.Fatalf("namespaces = %+v, want [app zeta]", got)
	}
	if got[0].Labels["istio-injection"] != "enabled" || got[0].Annotations["meshscan.io/ignore"] != "missing-dr" {
		t.Errorf("metadata lost: %+v", got[0])
	}
}

func TestListNamespacesError(t *testing.T) {
	k8s, istio := newFixture()
	k8s.PrependReactor("list", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbidden("namespaces")
	})
	c, _ := newTestCollector(k8s, istio)

	if _, err := c.ListNamespaces(context.Background()); err == nil || !strings.Contains(err.Error(), "list namespaces") {
		t.Errorf("err = %v, want list namespaces error", err)
	}
}

func TestGetNamespace(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		k8s, istio := newFixture()
		c, _ := newTestCollector(k8s, istio)
		ns, err := c.GetNamespace(context.Background(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if ns.Name != "app" || ns.Labels["istio-injection"] != "enabled" {
			t.Errorf("ns = %+v", ns)
		}
	})

	t.Run("missing namespace is an error", func(t *testing.T) {
		k8s, istio := newFixture()
		c, _ := newTestCollector(k8s, istio)
		_, err := c.GetNamespace(context.Background(), "nope")
		if err == nil || !strings.Contains(err.Error(), `namespace "nope" not found`) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("forbidden degrades to a name-only result with a warning", func(t *testing.T) {
		k8s, istio := newFixture()
		k8s.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbidden("namespaces")
		})
		c, warn := newTestCollector(k8s, istio)
		ns, err := c.GetNamespace(context.Background(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if ns.Name != "app" || ns.Labels != nil {
			t.Errorf("ns = %+v, want name only", ns)
		}
		if !strings.Contains(warn.String(), "no permission to read namespace app") {
			t.Errorf("warning = %q", warn.String())
		}
	})

	t.Run("other errors are returned", func(t *testing.T) {
		k8s, istio := newFixture()
		k8s.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("boom")
		})
		c, _ := newTestCollector(k8s, istio)
		if _, err := c.GetNamespace(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestCallContextAppliesThePerCallTimeout(t *testing.T) {
	k8s, istio := newFixture()

	withTimeout := NewWithClients(k8s, istio, 50*time.Millisecond, &bytes.Buffer{})
	ctx, cancel := withTimeout.callContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 50*time.Millisecond {
		t.Errorf("deadline = %v (set: %v), want within 50ms", deadline, ok)
	}

	noTimeout := NewWithClients(k8s, istio, 0, &bytes.Buffer{})
	ctx, cancel = noTimeout.callContext(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("zero timeout must not set a deadline")
	}
}

func TestCallContextIsDerivedFromTheParent(t *testing.T) {
	// The fake clientsets ignore contexts, so assert on the wiring instead:
	// every per-call context must be canceled together with the caller's context.
	k8s, istio := newFixture()
	c := NewWithClients(k8s, istio, time.Minute, &bytes.Buffer{})

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, release := c.callContext(parent)
	defer release()
	if ctx.Err() == nil {
		t.Error("per-call context was not canceled with its parent")
	}
}

func TestCollectIsSafeForConcurrentUse(t *testing.T) {
	k8s, istio := newFixture()
	c, _ := newTestCollector(k8s, istio)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap, err := c.Collect(context.Background(), model.Namespace{Name: "app"})
			if err == nil && len(snap.SystemPeerAuths) != 1 {
				err = fmt.Errorf("system PAs = %d, want 1", len(snap.SystemPeerAuths))
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := countSystemPAListCalls(istio); n != 1 {
		t.Errorf("istio-system PeerAuthentications listed %d times under concurrency, want 1", n)
	}
}

// writeKubeconfig writes a minimal kubeconfig that points nowhere; building
// clients from it does not connect to anything.
func writeKubeconfig(t *testing.T) string {
	t.Helper()
	const content = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:1
users:
- name: test
  user: {}
contexts:
- name: ctx
  context:
    cluster: test
    user: test
current-context: ctx
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewBuildsAClientFromAKubeconfig(t *testing.T) {
	c, err := New(Config{Kubeconfig: writeKubeconfig(t), CallTimeout: time.Second, Warn: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if c.k8s == nil || c.istio == nil || c.callTimeout != time.Second {
		t.Errorf("collector not fully wired: %+v", c)
	}

	named, err := New(Config{Kubeconfig: writeKubeconfig(t), KubeContext: "ctx", QPS: 10, Burst: 20})
	if err != nil || named == nil {
		t.Errorf("explicit context: %v", err)
	}
}

func TestNewRejectsAnUnknownContext(t *testing.T) {
	_, err := New(Config{Kubeconfig: writeKubeconfig(t), KubeContext: "nope"})
	if err == nil || !strings.Contains(err.Error(), "kubeconfig") || !strings.Contains(err.Error(), "nope") {
		t.Errorf("err = %v, want a kubeconfig error naming the context", err)
	}
}

func TestNewRejectsAMissingKubeconfig(t *testing.T) {
	_, err := New(Config{Kubeconfig: filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil || !strings.Contains(err.Error(), "kubeconfig") {
		t.Errorf("err = %v, want a kubeconfig error", err)
	}
}

func TestNewWithClientsDefaultsWarningsToStderr(t *testing.T) {
	k8s, istio := newFixture()
	if c := NewWithClients(k8s, istio, 0, nil); c.warn != os.Stderr {
		t.Errorf("warn = %v, want os.Stderr", c.warn)
	}
}
