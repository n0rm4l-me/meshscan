package checks

import (
	"sort"
	"strings"
	"testing"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

func TestAllChecksAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if c.Name == "" || c.Description == "" || c.Run == nil {
			t.Errorf("incomplete check registration: %+v", c.Name)
		}
		if seen[c.Name] {
			t.Errorf("duplicate check name %q", c.Name)
		}
		seen[c.Name] = true
		if strings.ToLower(c.Name) != c.Name || strings.ContainsAny(c.Name, " ,") {
			t.Errorf("check name %q must be lower-case kebab-case without spaces or commas", c.Name)
		}
	}
	if len(seen) != 8 {
		t.Errorf("registered %d checks, want 8 (update README if this changed on purpose)", len(seen))
	}
}

// dirtySnapshot trips every registered check at least once.
func dirtySnapshot() *model.Snapshot {
	vs := httpVS("vs", "svc", "v9")
	vs.Spec.Gateways = []string{"missing-gw"}
	vs.Spec.Http[0].Retries = &istiov1alpha3.HTTPRetry{Attempts: 3}
	return &model.Snapshot{
		Namespace:        testNS,
		VirtualServices:  vsList(vs, httpVS("vs-nodr", "nodr", "")),
		DestinationRules: drList(newDR("svc", "svc", "v1")),
		EnvoyFilters: []*networkingv1alpha3.EnvoyFilter{{
			ObjectMeta: metav1.ObjectMeta{Name: "ef", Namespace: testNS},
		}},
		Pods: []corev1.Pod{runningPod("bare", []string{"app"})},
	}
}

func TestEveryCheckReportsUnderItsOwnName(t *testing.T) {
	for _, c := range All() {
		t.Run(c.Name, func(t *testing.T) {
			got := c.Run(dirtySnapshot())
			if len(got) == 0 {
				t.Fatalf("check %s found nothing in the dirty snapshot", c.Name)
			}
			for _, f := range got {
				if f.Check != c.Name {
					t.Errorf("finding reports check %q, registered as %q", f.Check, c.Name)
				}
				if f.Severity < c.Severity {
					t.Errorf("finding severity %s is more severe than the registered maximum %s", f.Severity, c.Severity)
				}
			}
		})
	}
}

func TestNames(t *testing.T) {
	names := Names()
	if !sort.StringsAreSorted(names) {
		t.Errorf("Names() not sorted: %v", names)
	}
	if len(names) != len(All()) {
		t.Errorf("Names() returned %d names for %d checks", len(names), len(All()))
	}
}

func checkNames(cs []Check) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name
	}
	return out
}

func TestSelect(t *testing.T) {
	all := checkNames(All())
	var withoutMTLS []string
	for _, n := range all {
		if n != NameMTLS {
			withoutMTLS = append(withoutMTLS, n)
		}
	}

	tests := []struct {
		name    string
		only    []string
		skip    []string
		want    []string
		wantErr string
	}{
		{name: "no filters selects everything", want: all},
		{name: "only keeps registry order", only: []string{NameMissingDR, NameMTLS}, want: []string{NameMTLS, NameMissingDR}},
		{name: "skip", skip: []string{NameMTLS}, want: withoutMTLS},
		{name: "only and skip combine", only: []string{NameMTLS, NameMissingDR}, skip: []string{NameMTLS}, want: []string{NameMissingDR}},
		{name: "unknown in only", only: []string{"nope"}, wantErr: `unknown check "nope" in --checks`},
		{name: "unknown in skip", skip: []string{"nope"}, wantErr: `unknown check "nope" in --skip-checks`},
		{name: "everything skipped", only: []string{NameMTLS}, skip: []string{NameMTLS}, wantErr: "no checks selected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Select(tc.only, tc.skip)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotNames := checkNames(got); strings.Join(gotNames, ",") != strings.Join(tc.want, ",") {
				t.Errorf("selected %v, want %v", gotNames, tc.want)
			}
		})
	}
}

func TestSelectListsAvailableChecksInError(t *testing.T) {
	_, err := Select([]string{"nope"}, nil)
	if err == nil {
		t.Fatal("want error")
	}
	for _, n := range Names() {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("error does not list %q: %v", n, err)
		}
	}
}
