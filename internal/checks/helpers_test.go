package checks

import (
	"strings"
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const testNS = "app"

// wantFinding describes one expected finding. Empty fields are not compared.
type wantFinding struct {
	severity model.Severity
	resource string
	contains string // substring of the message
}

// assertFindings checks the number of findings and, in order, their check
// name, severity, resource and message. Every finding must also carry a fix.
func assertFindings(t *testing.T, check string, got []model.Finding, want ...wantFinding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Check != check {
			t.Errorf("finding %d: check = %q, want %q", i, g.Check, check)
		}
		if g.Severity != w.severity {
			t.Errorf("finding %d: severity = %s, want %s", i, g.Severity, w.severity)
		}
		if w.resource != "" && g.Resource != w.resource {
			t.Errorf("finding %d: resource = %q, want %q", i, g.Resource, w.resource)
		}
		if !strings.Contains(g.Message, w.contains) {
			t.Errorf("finding %d: message %q does not contain %q", i, g.Message, w.contains)
		}
		if g.Fix == "" {
			t.Errorf("finding %d: empty fix", i)
		}
	}
}

func vsMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: testNS}
}

// httpVS builds a VirtualService with one HTTP route to host (and subset).
func httpVS(name, host, subset string) *networkingv1alpha3.VirtualService {
	return &networkingv1alpha3.VirtualService{
		ObjectMeta: vsMeta(name),
		Spec: istiov1alpha3.VirtualService{
			Http: []*istiov1alpha3.HTTPRoute{{
				Route: []*istiov1alpha3.HTTPRouteDestination{{
					Destination: &istiov1alpha3.Destination{Host: host, Subset: subset},
				}},
			}},
		},
	}
}

// tcpVS builds a VirtualService with one TCP route to host (and subset).
func tcpVS(name, host, subset string) *networkingv1alpha3.VirtualService {
	return &networkingv1alpha3.VirtualService{
		ObjectMeta: vsMeta(name),
		Spec: istiov1alpha3.VirtualService{
			Tcp: []*istiov1alpha3.TCPRoute{{
				Route: []*istiov1alpha3.RouteDestination{{
					Destination: &istiov1alpha3.Destination{Host: host, Subset: subset},
				}},
			}},
		},
	}
}

// tlsVS builds a VirtualService with one TLS route to host (and subset).
func tlsVS(name, host, subset string) *networkingv1alpha3.VirtualService {
	return &networkingv1alpha3.VirtualService{
		ObjectMeta: vsMeta(name),
		Spec: istiov1alpha3.VirtualService{
			Tls: []*istiov1alpha3.TLSRoute{{
				Route: []*istiov1alpha3.RouteDestination{{
					Destination: &istiov1alpha3.Destination{Host: host, Subset: subset},
				}},
			}},
		},
	}
}

// newDR builds a DestinationRule for host that defines the given subsets.
func newDR(name, host string, subsets ...string) *networkingv1alpha3.DestinationRule {
	var ss []*istiov1alpha3.Subset
	for _, s := range subsets {
		ss = append(ss, &istiov1alpha3.Subset{Name: s})
	}
	return &networkingv1alpha3.DestinationRule{
		ObjectMeta: vsMeta(name),
		Spec:       istiov1alpha3.DestinationRule{Host: host, Subsets: ss},
	}
}

func vsList(vs ...*networkingv1alpha3.VirtualService) []*networkingv1alpha3.VirtualService {
	return vs
}

func drList(dr ...*networkingv1alpha3.DestinationRule) []*networkingv1alpha3.DestinationRule {
	return dr
}
