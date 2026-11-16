// Package collector reads Istio and Kubernetes resources into model snapshots.
package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const istioCPNamespace = "istio-system"

// Default client-side rate limits. client-go's own defaults (5 QPS, burst 10)
// make an all-namespaces scan of a large cluster take minutes.
const (
	defaultQPS   = 50
	defaultBurst = 100
)

// Config describes how to reach the cluster.
type Config struct {
	// KubeContext selects a kubeconfig context; empty means the current one.
	KubeContext string
	// Kubeconfig is an explicit kubeconfig path; empty means the default loading rules.
	Kubeconfig string
	// CallTimeout bounds every single Kubernetes API call; zero means no limit.
	CallTimeout time.Duration
	// QPS and Burst tune client-side rate limiting; zero selects the defaults.
	QPS   float32
	Burst int
	// Warn receives non-fatal warnings; nil means os.Stderr.
	Warn io.Writer
}

// Collector fetches snapshots. It is safe for concurrent use.
type Collector struct {
	k8s         kubernetes.Interface
	istio       versionedclient.Interface
	callTimeout time.Duration
	warn        io.Writer

	sysMu         sync.Mutex
	sysPAsFetched bool
	sysPAs        []*securityv1beta1.PeerAuthentication
}

// New builds a Collector from a kubeconfig.
func New(cfg Config) (*Collector, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.Kubeconfig != "" {
		rules.ExplicitPath = cfg.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if cfg.KubeContext != "" {
		overrides.CurrentContext = cfg.KubeContext
	}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	restCfg.QPS, restCfg.Burst = cfg.QPS, cfg.Burst
	if restCfg.QPS == 0 {
		restCfg.QPS = defaultQPS
	}
	if restCfg.Burst == 0 {
		restCfg.Burst = defaultBurst
	}

	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	istioClient, err := versionedclient.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("istio client: %w", err)
	}
	return NewWithClients(k8sClient, istioClient, cfg.CallTimeout, cfg.Warn), nil
}

// NewWithClients builds a Collector around existing clients. It exists mainly
// so tests can pass fake clientsets. A nil warn writes to os.Stderr.
func NewWithClients(k8s kubernetes.Interface, istio versionedclient.Interface, callTimeout time.Duration, warn io.Writer) *Collector {
	if warn == nil {
		warn = os.Stderr
	}
	return &Collector{k8s: k8s, istio: istio, callTimeout: callTimeout, warn: warn}
}

// callContext derives the context for one API call.
func (c *Collector) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.callTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.callTimeout)
}

func (c *Collector) warnf(format string, args ...any) {
	// A failed warning write must never fail the scan.
	_, _ = fmt.Fprintf(c.warn, "warning: "+format+"\n", args...)
}

func toNamespace(name string, labels, annotations map[string]string) model.Namespace {
	return model.Namespace{Name: name, Labels: labels, Annotations: annotations}
}

// ListNamespaces returns every namespace in the cluster, sorted by name.
func (c *Collector) ListNamespaces(ctx context.Context) ([]model.Namespace, error) {
	cctx, cancel := c.callContext(ctx)
	defer cancel()
	nsList, err := c.k8s.CoreV1().Namespaces().List(cctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	out := make([]model.Namespace, len(nsList.Items))
	for i, ns := range nsList.Items {
		out[i] = toNamespace(ns.Name, ns.Labels, ns.Annotations)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetNamespace reads one namespace. A missing namespace is an error. When the
// caller may not read Namespace objects, GetNamespace still succeeds with a
// name-only result and warns, because labels and annotations are optional input.
func (c *Collector) GetNamespace(ctx context.Context, name string) (model.Namespace, error) {
	cctx, cancel := c.callContext(ctx)
	defer cancel()
	ns, err := c.k8s.CoreV1().Namespaces().Get(cctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		return toNamespace(ns.Name, ns.Labels, ns.Annotations), nil
	case k8serrors.IsNotFound(err):
		return model.Namespace{}, fmt.Errorf("namespace %q not found", name)
	case k8serrors.IsForbidden(err):
		c.warnf("no permission to read namespace %s; ignoring its labels and annotations (ambient-mode detection and a namespace-level meshscan.io/ignore)", name)
		return model.Namespace{Name: name}, nil
	}
	return model.Namespace{}, fmt.Errorf("get namespace %s: %w", name, err)
}

// Collect gathers every resource meshscan audits in one namespace.
func (c *Collector) Collect(ctx context.Context, ns model.Namespace) (*model.Snapshot, error) {
	name := ns.Name
	snap := &model.Snapshot{
		Namespace:            name,
		NamespaceLabels:      ns.Labels,
		NamespaceAnnotations: ns.Annotations,
	}

	steps := []struct {
		what string
		run  func(ctx context.Context) error
	}{
		{"VirtualServices", func(ctx context.Context) error {
			l, err := c.istio.NetworkingV1alpha3().VirtualServices(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.VirtualServices = l.Items
			}
			return err
		}},
		{"DestinationRules", func(ctx context.Context) error {
			l, err := c.istio.NetworkingV1alpha3().DestinationRules(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.DestinationRules = l.Items
			}
			return err
		}},
		{"Gateways", func(ctx context.Context) error {
			l, err := c.istio.NetworkingV1alpha3().Gateways(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.Gateways = l.Items
			}
			return err
		}},
		{"EnvoyFilters", func(ctx context.Context) error {
			l, err := c.istio.NetworkingV1alpha3().EnvoyFilters(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.EnvoyFilters = l.Items
			}
			return err
		}},
		{"PeerAuthentications", func(ctx context.Context) error {
			l, err := c.istio.SecurityV1beta1().PeerAuthentications(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.PeerAuths = l.Items
			}
			return err
		}},
		{"Pods", func(ctx context.Context) error {
			l, err := c.k8s.CoreV1().Pods(name).List(ctx, metav1.ListOptions{})
			if err == nil {
				snap.Pods = l.Items
			}
			return err
		}},
	}
	for _, step := range steps {
		if err := c.call(ctx, step.what, step.run); err != nil {
			return nil, err
		}
	}

	sysPAs, err := c.systemPeerAuths(ctx)
	if err != nil {
		return nil, err
	}
	snap.SystemPeerAuths = sysPAs
	return snap, nil
}

// call runs one API call under the per-call timeout and labels its error.
func (c *Collector) call(ctx context.Context, what string, run func(context.Context) error) error {
	cctx, cancel := c.callContext(ctx)
	defer cancel()
	err := run(cctx)
	if err == nil {
		return nil
	}
	if k8serrors.IsNotFound(err) {
		return fmt.Errorf("list %s: %w (is this resource type installed in the cluster?)", what, err)
	}
	return fmt.Errorf("list %s: %w", what, err)
}

// systemPeerAuths returns the PeerAuthentications of the Istio root namespace.
// The result is fetched once and shared by all snapshots. Lacking access is not
// fatal: the mesh-wide policy is then unknown and the mTLS check may report a
// namespace that a mesh-wide STRICT policy actually protects.
func (c *Collector) systemPeerAuths(ctx context.Context) ([]*securityv1beta1.PeerAuthentication, error) {
	c.sysMu.Lock()
	defer c.sysMu.Unlock()
	if c.sysPAsFetched {
		return c.sysPAs, nil
	}

	var pas []*securityv1beta1.PeerAuthentication
	err := c.call(ctx, "system PeerAuthentications", func(ctx context.Context) error {
		l, err := c.istio.SecurityV1beta1().PeerAuthentications(istioCPNamespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			pas = l.Items
		}
		return err
	})
	if err != nil {
		if !isAccessProblem(err) {
			return nil, err
		}
		c.warnf("no access to %s PeerAuthentications; mtls check may miss mesh-wide policies", istioCPNamespace)
		pas = nil
	}
	c.sysPAs, c.sysPAsFetched = pas, true
	return c.sysPAs, nil
}

func isAccessProblem(err error) bool {
	return k8serrors.IsForbidden(err) || k8serrors.IsNotFound(err)
}
