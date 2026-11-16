package cli

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/n0rm4l-me/meshscan/internal/checks"
	"github.com/n0rm4l-me/meshscan/internal/collector"
	"github.com/n0rm4l-me/meshscan/internal/model"
	"github.com/n0rm4l-me/meshscan/internal/output"
)

const (
	formatHuman = "human"
	formatJSON  = "json"
	formatSARIF = "sarif"

	maxConcurrency = 32
)

// plan is the validated form of the command line.
type plan struct {
	format    string
	color     bool
	failOn    model.Severity
	failOnSet bool // false for --fail-on none
	selected  []checks.Check
}

func (o *options) validate(env Env) (plan, error) {
	var p plan

	switch {
	case o.allNamespaces && o.namespace != "":
		return p, usagef("--namespace and --all-namespaces are mutually exclusive")
	case !o.allNamespaces && o.namespace == "":
		return p, usagef("--namespace / -n is required (or use --all-namespaces / -A)")
	case len(o.excludeNamespaces) > 0 && !o.allNamespaces:
		return p, usagef("--exclude-namespace requires --all-namespaces / -A")
	}
	for _, pattern := range o.excludeNamespaces {
		if _, err := path.Match(pattern, ""); err != nil {
			return p, usagef("invalid --exclude-namespace pattern %q: %v", pattern, err)
		}
	}

	if o.jsonOut && o.output != "" {
		return p, usagef("--json and --output are mutually exclusive")
	}
	p.format = strings.ToLower(o.output)
	if o.jsonOut {
		p.format = formatJSON
	}
	switch p.format {
	case "":
		p.format = formatHuman
	case formatHuman, formatJSON, formatSARIF:
	default:
		return p, usagef("unknown --output %q (want human, json or sarif)", o.output)
	}

	switch strings.ToLower(o.color) {
	case "auto":
		p.color = env.StdoutIsTerminal && env.Getenv("NO_COLOR") == "" && env.Getenv("TERM") != "dumb"
	case "always":
		p.color = true
	case "never":
		p.color = false
	default:
		return p, usagef("unknown --color %q (want auto, always or never)", o.color)
	}

	if strings.EqualFold(strings.TrimSpace(o.failOn), "none") {
		p.failOnSet = false
	} else {
		sev, err := model.ParseSeverity(o.failOn)
		if err != nil {
			return p, usagef("invalid --fail-on %q (want critical, high, medium, low or none)", o.failOn)
		}
		p.failOn, p.failOnSet = sev, true
	}

	if o.timeout < 0 {
		return p, usagef("--timeout must not be negative")
	}
	if o.concurrency < 1 || o.concurrency > maxConcurrency {
		return p, usagef("--concurrency must be between 1 and %d", maxConcurrency)
	}

	selected, err := checks.Select(lowerAll(o.checks), lowerAll(o.skipChecks))
	if err != nil {
		return p, usageError{err}
	}
	p.selected = selected
	return p, nil
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// run executes one audit. It returns the exit code for a completed scan; a
// non-nil error means meshscan could not do its job and maps to ExitError.
func run(ctx context.Context, o *options, env Env) (int, error) {
	if o.listChecks {
		return ExitOK, printChecks(env.Stdout)
	}
	p, err := o.validate(env)
	if err != nil {
		return ExitOK, err
	}

	src, err := env.NewSource(collector.Config{
		KubeContext: o.kubeContext,
		Kubeconfig:  o.kubeconfig,
		CallTimeout: o.timeout,
		Warn:        env.Stderr,
	})
	if err != nil {
		return ExitOK, fmt.Errorf("connect to cluster: %w", err)
	}

	targets, err := resolveNamespaces(ctx, src, o)
	if err != nil {
		return ExitOK, err
	}

	results := scanAll(ctx, src, targets, p.selected, !o.noSuppress, o.concurrency)

	var (
		findings   []model.Finding
		suppressed int
		failed     []nsResult
	)
	for _, r := range results {
		if r.err != nil {
			failed = append(failed, r)
			continue
		}
		findings = append(findings, r.findings...)
		suppressed += r.suppressed
	}

	// A single explicitly requested namespace that cannot be read is a plain error.
	if len(targets) == 1 && len(failed) == 1 {
		return ExitOK, failed[0].err
	}
	if len(failed) == len(targets) {
		return ExitOK, fmt.Errorf("no namespace could be scanned: %w", failed[0].err)
	}

	sortFindings(findings)

	if err := writeReport(env.Stdout, p, findings, o.namespace, toolVersion(env.Version)); err != nil {
		return ExitOK, fmt.Errorf("write report: %w", err)
	}
	if suppressed > 0 {
		fmt.Fprintf(env.Stderr, "note: %d finding(s) suppressed by %s annotations (use --no-suppress to show them)\n", suppressed, checks.IgnoreAnnotation)
	}

	if len(failed) > 0 {
		for _, r := range failed {
			fmt.Fprintf(env.Stderr, "warning: skipped %v\n", r.err)
		}
		return ExitOK, fmt.Errorf("scan incomplete: %d of %d namespaces could not be read", len(failed), len(targets))
	}

	if p.failOnSet {
		for _, f := range findings {
			if f.Severity.AtLeast(p.failOn) {
				return ExitFindings, nil
			}
		}
	}
	return ExitOK, nil
}

// resolveNamespaces lists the namespaces to scan.
func resolveNamespaces(ctx context.Context, src Source, o *options) ([]model.Namespace, error) {
	if !o.allNamespaces {
		ns, err := src.GetNamespace(ctx, o.namespace)
		if err != nil {
			return nil, err
		}
		return []model.Namespace{ns}, nil
	}

	all, err := src.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	var targets []model.Namespace
	for _, ns := range all {
		if !excluded(ns.Name, o.excludeNamespaces) {
			targets = append(targets, ns)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no namespaces to scan: all %d namespaces are excluded", len(all))
	}
	return targets, nil
}

func excluded(name string, patterns []string) bool {
	for _, pattern := range patterns {
		// Patterns were validated; Match only errors on malformed ones.
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

type nsResult struct {
	findings   []model.Finding
	suppressed int
	err        error
}

// scanAll collects and checks namespaces with bounded parallelism. Results are
// returned in the order of targets, so output does not depend on timing.
func scanAll(ctx context.Context, src Source, targets []model.Namespace, selected []checks.Check, suppress bool, concurrency int) []nsResult {
	results := make([]nsResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, ns := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = scanNamespace(ctx, src, ns, selected, suppress)
		}()
	}
	wg.Wait()
	return results
}

func scanNamespace(ctx context.Context, src Source, ns model.Namespace, selected []checks.Check, suppress bool) nsResult {
	if err := ctx.Err(); err != nil {
		return nsResult{err: fmt.Errorf("namespace %s: %w", ns.Name, err)}
	}
	snap, err := src.Collect(ctx, ns)
	if err != nil {
		return nsResult{err: fmt.Errorf("namespace %s: %w", ns.Name, err)}
	}

	var findings []model.Finding
	for _, c := range selected {
		findings = append(findings, c.Run(snap)...)
	}
	var suppressed int
	if suppress {
		findings, suppressed = checks.Suppress(snap, findings)
	}
	return nsResult{findings: findings, suppressed: suppressed}
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity < b.Severity
		case a.Check != b.Check:
			return a.Check < b.Check
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Resource < b.Resource
	})
}

func writeReport(w io.Writer, p plan, findings []model.Finding, namespace, toolVersion string) error {
	switch p.format {
	case formatJSON:
		return output.JSON(w, findings)
	case formatSARIF:
		rules := make([]output.Rule, len(p.selected))
		for i, c := range p.selected {
			rules[i] = output.Rule{ID: c.Name, Description: c.Description, Severity: c.Severity}
		}
		return output.SARIF(w, findings, rules, toolVersion)
	}
	output.Human(w, findings, namespace, p.color)
	return nil
}

// toolVersion extracts the bare version from the one-line build summary
// ("1.2.3 (commit abc, go1.26)" becomes "1.2.3").
func toolVersion(summary string) string {
	if fields := strings.Fields(summary); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func printChecks(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tMAX SEVERITY\tDESCRIPTION")
	for _, c := range checks.All() {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Severity, c.Description)
	}
	return tw.Flush()
}
