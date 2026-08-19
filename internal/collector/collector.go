package collector

import (
	"context"
	"fmt"
	"os"

	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const istioCPNamespace = "istio-system"

type Collector struct {
	k8s           *kubernetes.Clientset
	istio         *versionedclient.Clientset
	sysPAsFetched bool
	sysPAs        []*securityv1beta1.PeerAuthentication
}

func New(kubecontext, kubeconfig string) (*Collector, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubecontext != "" {
		overrides.CurrentContext = kubecontext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	istioClient, err := versionedclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Collector{k8s: k8sClient, istio: istioClient}, nil
}

func (c *Collector) ListNamespaces(ctx context.Context) ([]string, error) {
	nsList, err := c.k8s.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	names := make([]string, len(nsList.Items))
	for i, ns := range nsList.Items {
		names[i] = ns.Name
	}
	return names, nil
}

func (c *Collector) Collect(ctx context.Context, namespace string) (*model.Snapshot, error) {
	snap := &model.Snapshot{Namespace: namespace}

	vsList, err := c.istio.NetworkingV1alpha3().VirtualServices(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list VirtualServices: %w", err)
	}
	snap.VirtualServices = append(snap.VirtualServices, vsList.Items...)

	drList, err := c.istio.NetworkingV1alpha3().DestinationRules(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list DestinationRules: %w", err)
	}
	snap.DestinationRules = append(snap.DestinationRules, drList.Items...)

	paList, err := c.istio.SecurityV1beta1().PeerAuthentications(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list PeerAuthentications: %w", err)
	}
	snap.PeerAuths = append(snap.PeerAuths, paList.Items...)

	// Fetch system PAs once; reuse the cached result on subsequent calls.
	if !c.sysPAsFetched {
		sysPAList, sysErr := c.istio.SecurityV1beta1().PeerAuthentications(istioCPNamespace).List(ctx, metav1.ListOptions{})
		if sysErr != nil {
			if !k8serrors.IsForbidden(sysErr) && !k8serrors.IsNotFound(sysErr) {
				return nil, fmt.Errorf("list system PeerAuthentications: %w", sysErr)
			}
			fmt.Fprintf(os.Stderr, "warning: no access to %s PeerAuthentications; mtls check may miss mesh-wide policies\n", istioCPNamespace)
		} else {
			c.sysPAs = append(c.sysPAs, sysPAList.Items...)
		}
		c.sysPAsFetched = true
	}
	snap.SystemPeerAuths = c.sysPAs

	podList, err := c.k8s.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Pods: %w", err)
	}
	snap.Pods = podList.Items

	return snap, nil
}
