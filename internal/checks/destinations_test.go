package checks

import "testing"

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		host      string
		wantFQDN  string
		wantLocal bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"svc", "svc.app.svc.cluster.local", true},
		{"Svc", "svc.app.svc.cluster.local", true},
		{"svc.app.svc.cluster.local", "svc.app.svc.cluster.local", true},
		{"SVC.APP.SVC.CLUSTER.LOCAL", "svc.app.svc.cluster.local", true},
		{"svc.other.svc.cluster.local", "svc.other.svc.cluster.local", false},
		{"pod-0.headless.app.svc.cluster.local", "pod-0.headless.app.svc.cluster.local", true},
		{".svc.cluster.local", ".svc.cluster.local", false},
		{"api.example.com", "api.example.com", false},
		{"svc.other-ns", "svc.other-ns", false},
		{"*.example.com", "*.example.com", false},
		{"*", "*", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			fqdn, local := classifyHost(tc.host, "app")
			if fqdn != tc.wantFQDN || local != tc.wantLocal {
				t.Errorf("classifyHost(%q) = (%q, %v), want (%q, %v)", tc.host, fqdn, local, tc.wantFQDN, tc.wantLocal)
			}
		})
	}
}

func TestDRLookupMostSpecificWildcardWins(t *testing.T) {
	l := newDRLookup(drList(
		newDR("broad", "*.svc.cluster.local", "a"),
		newDR("narrow", "*.other.svc.cluster.local", "b"),
		newDR("exact", "svc.other.svc.cluster.local", "c"),
	))

	tests := []struct {
		fqdn     string
		wantName string
	}{
		{"svc.other.svc.cluster.local", "exact"},
		{"x.other.svc.cluster.local", "narrow"},
		{"x.third.svc.cluster.local", "broad"},
	}
	for _, tc := range tests {
		e, ok := l.find(tc.fqdn)
		if !ok {
			t.Fatalf("find(%q): no entry", tc.fqdn)
		}
		if e.names[0] != tc.wantName {
			t.Errorf("find(%q) = %s, want %s", tc.fqdn, e.names[0], tc.wantName)
		}
	}

	if _, ok := l.find("api.example.com"); ok {
		t.Error("find(api.example.com): unexpected entry")
	}
}

func TestDRLookupIgnoresRulesWithoutHost(t *testing.T) {
	l := newDRLookup(drList(newDR("no-host", "")))
	if len(l.exact) != 0 || len(l.wild) != 0 {
		t.Errorf("rule without host was indexed: %+v", l)
	}
}
