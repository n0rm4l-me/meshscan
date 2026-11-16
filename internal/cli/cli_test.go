package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	istiosecurity "istio.io/api/security/v1beta1"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/n0rm4l-me/meshscan/internal/checks"
	"github.com/n0rm4l-me/meshscan/internal/collector"
	"github.com/n0rm4l-me/meshscan/internal/model"
)

// fakeSource is an in-memory Source.
type fakeSource struct {
	namespaces []model.Namespace
	snapshots  map[string]*model.Snapshot
	collectErr map[string]error
	listErr    error
	delay      time.Duration

	mu        sync.Mutex
	collected []string
	inflight  int
	peak      int
}

func (f *fakeSource) ListNamespaces(context.Context) ([]model.Namespace, error) {
	return f.namespaces, f.listErr
}

func (f *fakeSource) GetNamespace(_ context.Context, name string) (model.Namespace, error) {
	for _, ns := range f.namespaces {
		if ns.Name == name {
			return ns, nil
		}
	}
	return model.Namespace{}, fmt.Errorf("namespace %q not found", name)
}

func (f *fakeSource) Collect(_ context.Context, ns model.Namespace) (*model.Snapshot, error) {
	f.mu.Lock()
	f.collected = append(f.collected, ns.Name)
	f.inflight++
	if f.inflight > f.peak {
		f.peak = f.inflight
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()

	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if err := f.collectErr[ns.Name]; err != nil {
		return nil, err
	}
	snap := f.snapshots[ns.Name]
	snap.NamespaceLabels, snap.NamespaceAnnotations = ns.Labels, ns.Annotations
	return snap, nil
}

func strictPA(ns string) *securityv1beta1.PeerAuthentication {
	return &securityv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns},
		Spec: istiosecurity.PeerAuthentication{
			Mtls: &istiosecurity.PeerAuthentication_MutualTLS{Mode: istiosecurity.PeerAuthentication_MutualTLS_STRICT},
		},
	}
}

// cleanSnap has no findings.
func cleanSnap(ns string) *model.Snapshot {
	return &model.Snapshot{Namespace: ns, PeerAuths: []*securityv1beta1.PeerAuthentication{strictPA(ns)}}
}

// critSnap has exactly one CRITICAL finding (mtls-enforcement).
func critSnap(ns string) *model.Snapshot {
	return &model.Snapshot{Namespace: ns}
}

// medSnap has exactly one MEDIUM finding (retry-without-timeout).
func medSnap(ns string) *model.Snapshot {
	snap := cleanSnap(ns)
	snap.VirtualServices = []*networkingv1alpha3.VirtualService{{
		ObjectMeta: metav1.ObjectMeta{Name: "vs", Namespace: ns},
		Spec: istiov1alpha3.VirtualService{
			Http: []*istiov1alpha3.HTTPRoute{{Retries: &istiov1alpha3.HTTPRetry{Attempts: 3}}},
		},
	}}
	return snap
}

func newFakeSource() *fakeSource {
	names := []string{"clean", "crit", "kube-system", "med"}
	f := &fakeSource{snapshots: map[string]*model.Snapshot{}, collectErr: map[string]error{}}
	for _, n := range names {
		f.namespaces = append(f.namespaces, model.Namespace{Name: n})
	}
	f.snapshots["clean"] = cleanSnap("clean")
	f.snapshots["crit"] = critSnap("crit")
	f.snapshots["kube-system"] = critSnap("kube-system")
	f.snapshots["med"] = medSnap("med")
	return f
}

type outcome struct {
	code      int
	stdout    string
	stderr    string
	src       *fakeSource
	cfg       collector.Config
	connected bool
}

type envOpt func(*Env)

func withTerminal() envOpt { return func(e *Env) { e.StdoutIsTerminal = true } }
func withEnvVar(k, v string) envOpt {
	return func(e *Env) {
		prev := e.Getenv
		e.Getenv = func(key string) string {
			if key == k {
				return v
			}
			return prev(key)
		}
	}
}

func execute(t *testing.T, src *fakeSource, args []string, opts ...envOpt) outcome {
	return executeCtx(t, context.Background(), src, args, opts...)
}

func executeCtx(t *testing.T, ctx context.Context, src *fakeSource, args []string, opts ...envOpt) outcome {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := outcome{src: src}
	env := Env{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Getenv:  func(string) string { return "" },
		Version: "1.2.3 (commit abc, go1.test)",
		NewSource: func(cfg collector.Config) (Source, error) {
			out.connected = true
			out.cfg = cfg
			return src, nil
		},
	}
	for _, o := range opts {
		o(&env)
	}
	out.code = Execute(ctx, args, env)
	out.stdout, out.stderr = stdout.String(), stderr.String()
	return out
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean namespace", []string{"-n", "clean"}, ExitOK},
		{"namespace with findings", []string{"-n", "crit"}, ExitFindings},
		{"json output with findings still exits 1", []string{"-n", "crit", "--json"}, ExitFindings},
		{"-o json with findings exits 1", []string{"-n", "crit", "-o", "json"}, ExitFindings},
		{"sarif with findings exits 1", []string{"-n", "crit", "-o", "sarif"}, ExitFindings},
		{"json output without findings exits 0", []string{"-n", "clean", "--json"}, ExitOK},
		{"all namespaces with findings", []string{"-A"}, ExitFindings},
		{"missing namespace", []string{"-n", "nope"}, ExitError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := execute(t, newFakeSource(), tc.args).code; got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFailOnThreshold(t *testing.T) {
	tests := []struct {
		ns, failOn string
		want       int
	}{
		{"crit", "critical", ExitFindings},
		{"med", "critical", ExitOK},
		{"med", "high", ExitOK},
		{"med", "medium", ExitFindings},
		{"med", "low", ExitFindings},
		{"med", "MEDIUM", ExitFindings},
		{"crit", "none", ExitOK},
		{"med", "none", ExitOK},
	}
	for _, tc := range tests {
		t.Run(tc.ns+"/"+tc.failOn, func(t *testing.T) {
			out := execute(t, newFakeSource(), []string{"-n", tc.ns, "--fail-on", tc.failOn})
			if out.code != tc.want {
				t.Errorf("exit code = %d, want %d", out.code, tc.want)
			}
			if tc.ns != "clean" && !strings.Contains(out.stdout, "[") {
				t.Errorf("findings must be reported regardless of --fail-on; stdout: %q", out.stdout)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no namespace", nil, "--namespace / -n is required"},
		{"namespace and all", []string{"-n", "x", "-A"}, "mutually exclusive"},
		{"json and output", []string{"-n", "x", "--json", "-o", "json"}, "--json and --output are mutually exclusive"},
		{"unknown output", []string{"-n", "x", "-o", "xml"}, `unknown --output "xml"`},
		{"unknown color", []string{"-n", "x", "--color", "rainbow"}, `unknown --color "rainbow"`},
		{"unknown fail-on", []string{"-n", "x", "--fail-on", "fatal"}, `invalid --fail-on "fatal"`},
		{"negative timeout", []string{"-n", "x", "--timeout", "-1s"}, "--timeout must not be negative"},
		{"zero concurrency", []string{"-n", "x", "--concurrency", "0"}, "--concurrency must be between"},
		{"huge concurrency", []string{"-n", "x", "--concurrency", "999"}, "--concurrency must be between"},
		{"exclude without -A", []string{"-n", "x", "--exclude-namespace", "kube-*"}, "requires --all-namespaces"},
		{"bad exclude pattern", []string{"-A", "--exclude-namespace", "[bad"}, `invalid --exclude-namespace pattern "[bad"`},
		{"unknown check", []string{"-n", "x", "--checks", "nope"}, `unknown check "nope"`},
		{"unknown skipped check", []string{"-n", "x", "--skip-checks", "nope"}, `unknown check "nope"`},
		{"nothing left to run", []string{"-n", "x", "--checks", "missing-dr", "--skip-checks", "missing-dr"}, "no checks selected"},
		{"unknown flag", []string{"--bogus"}, "unknown flag: --bogus"},
		{"positional argument", []string{"-n", "x", "extra"}, `unexpected argument "extra"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := execute(t, newFakeSource(), tc.args)
			if out.code != ExitError {
				t.Errorf("exit code = %d, want %d", out.code, ExitError)
			}
			if !strings.Contains(out.stderr, tc.want) {
				t.Errorf("stderr = %q, want containing %q", out.stderr, tc.want)
			}
			if !strings.Contains(out.stderr, "meshscan --help") {
				t.Errorf("usage errors should point at --help; stderr = %q", out.stderr)
			}
			if out.stdout != "" {
				t.Errorf("stdout must stay empty on usage errors, got %q", out.stdout)
			}
			if out.connected {
				t.Error("usage errors must be reported before connecting to the cluster")
			}
		})
	}
}

func TestHumanReport(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-n", "crit"})
	for _, want := range []string{"meshscan report: namespace crit", "1 issues: 1 critical", "[CRITICAL] PeerAuthentication", "check: mtls-enforcement", "fix: kubectl apply"} {
		if !strings.Contains(out.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.stdout)
		}
	}

	clean := execute(t, newFakeSource(), []string{"-n", "clean"})
	if clean.stdout != "✓ no issues found in namespace clean\n" {
		t.Errorf("stdout = %q", clean.stdout)
	}
}

func TestJSONReportIsValidAndSorted(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-A", "-o", "json"})
	var got []struct{ Severity, Check, Resource, Namespace string }
	if err := json.Unmarshal([]byte(out.stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.stdout)
	}
	want := []string{"CRITICAL crit", "CRITICAL kube-system", "MEDIUM med"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if have := got[i].Severity + " " + got[i].Namespace; have != w {
			t.Errorf("finding %d = %q, want %q (severity, then namespace)", i, have, w)
		}
	}
	if out.stderr != "" {
		t.Errorf("stderr should be empty, got %q", out.stderr)
	}
}

func TestSARIFReport(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-A", "-o", "sarif", "--checks", "mtls-enforcement"})
	var doc struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string
					Version string
					Rules   []struct{ ID string }
				}
			}
			Results []struct{ RuleID, Level string }
		}
	}
	if err := json.Unmarshal([]byte(out.stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.stdout)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "meshscan" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "mtls-enforcement" {
		t.Errorf("rule catalog must list only the selected checks: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 2 || run.Results[0].Level != "error" {
		t.Errorf("results = %+v", run.Results)
	}
}

func TestAllNamespacesReport(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-A"})
	for _, want := range []string{"meshscan report: all namespaces", "3 issues: 2 critical, 0 high, 1 medium", "crit/PeerAuthentication", "med/VirtualService/vs"} {
		if !strings.Contains(out.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.stdout)
		}
	}
}

func TestExcludeNamespace(t *testing.T) {
	src := newFakeSource()
	out := execute(t, src, []string{"-A", "--exclude-namespace", "kube-*", "--exclude-namespace", "crit"})

	if strings.Contains(out.stdout, "kube-system") || strings.Contains(out.stdout, "crit/") {
		t.Errorf("excluded namespaces leaked into the report:\n%s", out.stdout)
	}
	for _, n := range src.collected {
		if n == "kube-system" || n == "crit" {
			t.Errorf("excluded namespace %s was collected", n)
		}
	}
	if len(src.collected) != 2 {
		t.Errorf("collected %v, want clean and med", src.collected)
	}
}

func TestExcludeEverythingIsAnError(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-A", "--exclude-namespace", "*"})
	if out.code != ExitError || !strings.Contains(out.stderr, "all 4 namespaces are excluded") {
		t.Errorf("code=%d stderr=%q", out.code, out.stderr)
	}
}

func TestCheckSelection(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"only mtls sees the CRITICAL", []string{"-n", "crit", "--checks", "mtls-enforcement"}, ExitFindings},
		{"only mtls ignores the MEDIUM", []string{"-n", "med", "--checks", "mtls-enforcement"}, ExitOK},
		{"skipping mtls hides the CRITICAL", []string{"-n", "crit", "--skip-checks", "mtls-enforcement"}, ExitOK},
		{"skipping an unrelated check keeps it", []string{"-n", "crit", "--skip-checks", "missing-dr"}, ExitFindings},
		{"comma separated and case-insensitive", []string{"-n", "med", "--checks", "MTLS-enforcement,retry-without-timeout"}, ExitFindings},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := execute(t, newFakeSource(), tc.args).code; got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSuppressionAnnotations(t *testing.T) {
	newSrc := func() *fakeSource {
		src := newFakeSource()
		src.namespaces[1].Annotations = map[string]string{checks.IgnoreAnnotation: "mtls-enforcement"} // crit
		return src
	}

	out := execute(t, newSrc(), []string{"-n", "crit"})
	if out.code != ExitOK {
		t.Errorf("suppressed namespace should pass, exit = %d\n%s", out.code, out.stdout)
	}
	if !strings.Contains(out.stderr, "1 finding(s) suppressed") || !strings.Contains(out.stderr, "--no-suppress") {
		t.Errorf("stderr should report the suppression, got %q", out.stderr)
	}

	out = execute(t, newSrc(), []string{"-n", "crit", "--no-suppress"})
	if out.code != ExitFindings || strings.Contains(out.stderr, "suppressed") {
		t.Errorf("--no-suppress must report everything silently: exit=%d stderr=%q", out.code, out.stderr)
	}
}

func TestSingleNamespaceCollectionFailureIsFatal(t *testing.T) {
	src := newFakeSource()
	src.collectErr["crit"] = errors.New("list Pods: forbidden")
	out := execute(t, src, []string{"-n", "crit"})

	if out.code != ExitError {
		t.Errorf("exit code = %d, want %d", out.code, ExitError)
	}
	if !strings.Contains(out.stderr, "namespace crit: list Pods: forbidden") {
		t.Errorf("stderr = %q", out.stderr)
	}
	if out.stdout != "" {
		t.Errorf("no report may be printed when the only namespace failed, got %q", out.stdout)
	}
}

func TestIncompleteScanStillReportsAndFails(t *testing.T) {
	src := newFakeSource()
	src.collectErr["kube-system"] = errors.New("list Pods: forbidden")
	out := execute(t, src, []string{"-A", "-o", "json"})

	if out.code != ExitError {
		t.Errorf("an incomplete scan must exit %d, got %d", ExitError, out.code)
	}
	if !strings.Contains(out.stdout, `"namespace": "crit"`) {
		t.Errorf("findings from readable namespaces must still be printed:\n%s", out.stdout)
	}
	for _, want := range []string{"warning: skipped namespace kube-system: list Pods: forbidden", "scan incomplete: 1 of 4 namespaces could not be read"} {
		if !strings.Contains(out.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, out.stderr)
		}
	}
}

func TestIncompleteScanWithoutFindingsIsNotClean(t *testing.T) {
	src := newFakeSource()
	src.collectErr["med"] = errors.New("timeout")
	out := execute(t, src, []string{"-A", "--exclude-namespace", "crit", "--exclude-namespace", "kube-system"})
	if out.code != ExitError {
		t.Errorf("exit code = %d, want %d: a scan that missed a namespace cannot claim success", out.code, ExitError)
	}
}

func TestEveryNamespaceFailing(t *testing.T) {
	src := newFakeSource()
	for _, ns := range src.namespaces {
		src.collectErr[ns.Name] = errors.New("api down")
	}
	out := execute(t, src, []string{"-A"})
	if out.code != ExitError || !strings.Contains(out.stderr, "no namespace could be scanned") || out.stdout != "" {
		t.Errorf("code=%d stdout=%q stderr=%q", out.code, out.stdout, out.stderr)
	}
}

func TestListNamespacesFailure(t *testing.T) {
	src := newFakeSource()
	src.listErr = errors.New("list namespaces: forbidden")
	out := execute(t, src, []string{"-A"})
	if out.code != ExitError || !strings.Contains(out.stderr, "list namespaces: forbidden") {
		t.Errorf("code=%d stderr=%q", out.code, out.stderr)
	}
}

func TestConnectionFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{"-n", "x"}, Env{
		Stdout: &bytes.Buffer{},
		Stderr: &stderr,
		NewSource: func(collector.Config) (Source, error) {
			return nil, errors.New("kubeconfig: no such file")
		},
	})
	if code != ExitError || !strings.Contains(stderr.String(), "connect to cluster: kubeconfig: no such file") {
		t.Errorf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestConnectionSettingsAreForwarded(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"-n", "clean", "--context", "staging", "--kubeconfig", "/tmp/kc", "--timeout", "45s"})
	if out.cfg.KubeContext != "staging" || out.cfg.Kubeconfig != "/tmp/kc" || out.cfg.CallTimeout != 45*time.Second {
		t.Errorf("cfg = %+v", out.cfg)
	}
}

func TestCanceledContextAbortsTheScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := newFakeSource()
	out := executeCtx(t, ctx, src, []string{"-A"})
	if out.code != ExitError {
		t.Errorf("exit code = %d, want %d", out.code, ExitError)
	}
	if len(src.collected) != 0 {
		t.Errorf("a canceled scan must not start collecting: %v", src.collected)
	}
}

func TestConcurrencyIsBoundedAndOutputIsDeterministic(t *testing.T) {
	build := func() *fakeSource {
		f := &fakeSource{snapshots: map[string]*model.Snapshot{}, collectErr: map[string]error{}, delay: 5 * time.Millisecond}
		for i := 0; i < 12; i++ {
			name := fmt.Sprintf("ns-%02d", i)
			f.namespaces = append(f.namespaces, model.Namespace{Name: name})
			f.snapshots[name] = critSnap(name)
		}
		return f
	}

	serial := execute(t, build(), []string{"-A", "--concurrency", "1", "-o", "json"})
	src := build()
	parallel := execute(t, src, []string{"-A", "--concurrency", "3", "-o", "json"})

	if serial.stdout != parallel.stdout {
		t.Error("output differs between --concurrency 1 and 3")
	}
	if src.peak > 3 {
		t.Errorf("peak concurrency = %d, want at most 3", src.peak)
	}
	if len(src.collected) != 12 {
		t.Errorf("collected %d namespaces, want 12", len(src.collected))
	}
}

func TestListChecks(t *testing.T) {
	src := newFakeSource()
	out := execute(t, src, []string{"--list-checks"})
	if out.code != ExitOK || out.connected {
		t.Errorf("code=%d connected=%v: --list-checks must work offline", out.code, out.connected)
	}
	if !strings.HasPrefix(out.stdout, "CHECK") {
		t.Errorf("missing header:\n%s", out.stdout)
	}
	for _, c := range checks.All() {
		if !strings.Contains(out.stdout, c.Name) || !strings.Contains(out.stdout, c.Severity.String()) {
			t.Errorf("--list-checks lacks %s / %s:\n%s", c.Name, c.Severity, out.stdout)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	out := execute(t, newFakeSource(), []string{"--version"})
	if out.code != ExitOK || out.stdout != "meshscan 1.2.3 (commit abc, go1.test)\n" {
		t.Errorf("code=%d stdout=%q", out.code, out.stdout)
	}

	out = execute(t, newFakeSource(), []string{"--help"})
	if out.code != ExitOK {
		t.Errorf("--help exit code = %d", out.code)
	}
	for _, want := range []string{"--fail-on", "--exclude-namespace", "--list-checks", "Exit codes:", "meshscan.io/ignore", "-o, --output"} {
		if !strings.Contains(out.stdout, want) {
			t.Errorf("--help lacks %q", want)
		}
	}
}

func TestColor(t *testing.T) {
	const esc = "\033["
	tests := []struct {
		name string
		args []string
		opts []envOpt
		want bool
	}{
		{"auto, not a terminal", []string{"-n", "crit"}, nil, false},
		{"auto, terminal", []string{"-n", "crit"}, []envOpt{withTerminal()}, true},
		{"auto, terminal, NO_COLOR", []string{"-n", "crit"}, []envOpt{withTerminal(), withEnvVar("NO_COLOR", "1")}, false},
		{"auto, terminal, dumb TERM", []string{"-n", "crit"}, []envOpt{withTerminal(), withEnvVar("TERM", "dumb")}, false},
		{"always", []string{"-n", "crit", "--color", "always"}, nil, true},
		{"never on a terminal", []string{"-n", "crit", "--color", "never"}, []envOpt{withTerminal()}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := execute(t, newFakeSource(), tc.args, tc.opts...)
			if got := strings.Contains(out.stdout, esc); got != tc.want {
				t.Errorf("colored = %v, want %v: %q", got, tc.want, out.stdout)
			}
		})
	}
}

func TestToolVersion(t *testing.T) {
	tests := map[string]string{
		"1.2.3 (commit abc, go1.26)": "1.2.3",
		"dev (go1.26)":               "dev",
		"v0.4.0":                     "v0.4.0",
		"":                           "",
		"   ":                        "",
	}
	for in, want := range tests {
		if got := toolVersion(in); got != want {
			t.Errorf("toolVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
