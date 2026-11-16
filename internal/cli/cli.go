// Package cli implements the meshscan command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/n0rm4l-me/meshscan/internal/collector"
	"github.com/n0rm4l-me/meshscan/internal/model"
)

// Exit codes. CI pipelines can tell "the mesh has problems" (1) from
// "meshscan could not do its job" (2).
const (
	ExitOK       = 0 // no findings at or above --fail-on
	ExitFindings = 1 // findings at or above --fail-on
	ExitError    = 2 // usage error, cluster error, or an incomplete scan
)

// Source supplies the data meshscan audits. *collector.Collector implements it.
type Source interface {
	ListNamespaces(ctx context.Context) ([]model.Namespace, error)
	GetNamespace(ctx context.Context, name string) (model.Namespace, error)
	Collect(ctx context.Context, ns model.Namespace) (*model.Snapshot, error)
}

// SourceFactory builds a Source from connection settings.
type SourceFactory func(cfg collector.Config) (Source, error)

// Env is everything the command line needs from the outside world.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	// Getenv reads environment variables (NO_COLOR, TERM).
	Getenv func(string) string
	// StdoutIsTerminal tells whether Stdout is an interactive terminal.
	StdoutIsTerminal bool
	// Version is the one-line build description shown by --version.
	Version string
	// NewSource connects to the cluster. nil selects the real collector.
	NewSource SourceFactory
}

func (e Env) withDefaults() Env {
	if e.Stdout == nil {
		e.Stdout = os.Stdout
	}
	if e.Stderr == nil {
		e.Stderr = os.Stderr
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Version == "" {
		e.Version = "dev"
	}
	if e.NewSource == nil {
		e.NewSource = func(cfg collector.Config) (Source, error) {
			c, err := collector.New(cfg)
			if err != nil {
				return nil, err
			}
			return c, nil
		}
	}
	return e
}

// usageError marks mistakes in how meshscan was invoked.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// options holds the parsed command line.
type options struct {
	namespace         string
	allNamespaces     bool
	kubeContext       string
	kubeconfig        string
	output            string
	jsonOut           bool
	failOn            string
	timeout           time.Duration
	concurrency       int
	checks            []string
	skipChecks        []string
	excludeNamespaces []string
	noSuppress        bool
	color             string
	listChecks        bool
}

const longHelp = `meshscan reads the Istio resources and pods of a cluster and reports
configurations that are syntactically valid but break traffic or weaken
security at runtime.

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage error, cluster error, or an incomplete scan (a namespace could not be read)

Acknowledge a finding on its resource (or on the namespace) with the annotation
  meshscan.io/ignore: "check-a, check-b"   # or "*" for every check`

const examples = `  # Audit one namespace
  meshscan -n production

  # Audit the whole cluster, fail the pipeline only on HIGH and above
  meshscan -A --fail-on high

  # Skip infrastructure namespaces and write SARIF
  meshscan -A --exclude-namespace 'kube-*' --exclude-namespace 'gke-*' -o sarif > meshscan.sarif`

func newRootCmd(env Env, exitCode *int) *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:     "meshscan [flags]",
		Short:   "Audit Istio service mesh configuration for common misconfigurations",
		Long:    longHelp,
		Example: examples,
		Version: env.Version,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unexpected argument %q (meshscan takes flags only)", args[0])
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code, err := run(cmd.Context(), o, env)
			*exitCode = code
			return err
		},
	}
	cmd.SetVersionTemplate("meshscan {{.Version}}\n")
	cmd.SetOut(env.Stdout)
	cmd.SetErr(env.Stderr)
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	f := cmd.Flags()
	f.StringVarP(&o.namespace, "namespace", "n", "", "namespace to audit")
	f.BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "audit all namespaces")
	f.StringSliceVar(&o.excludeNamespaces, "exclude-namespace", nil, "skip namespaces matching this glob, e.g. 'kube-*' (repeatable; with -A only)")
	f.StringVar(&o.kubeContext, "context", "", "kubeconfig context (default: current context)")
	f.StringVar(&o.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: standard loading rules)")
	f.StringVarP(&o.output, "output", "o", "", "output format: human, json or sarif (default human)")
	f.BoolVar(&o.jsonOut, "json", false, "output findings as JSON (same as -o json)")
	f.StringVar(&o.failOn, "fail-on", "low", "exit with code 1 when a finding is at least this severe: critical, high, medium, low or none")
	f.StringSliceVar(&o.checks, "checks", nil, "run only these checks (comma-separated, see --list-checks)")
	f.StringSliceVar(&o.skipChecks, "skip-checks", nil, "do not run these checks (comma-separated)")
	f.BoolVar(&o.noSuppress, "no-suppress", false, "ignore meshscan.io/ignore annotations and report everything")
	f.DurationVar(&o.timeout, "timeout", 30*time.Second, "timeout for each Kubernetes API call (0 = no limit)")
	f.IntVar(&o.concurrency, "concurrency", 4, "namespaces collected in parallel (1-32)")
	f.StringVar(&o.color, "color", "auto", "colorize human output: auto, always or never (auto honors NO_COLOR)")
	f.BoolVar(&o.listChecks, "list-checks", false, "list the available checks and exit")
	return cmd
}

// Execute runs meshscan with args and returns the process exit code.
func Execute(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	if ctx == nil {
		ctx = context.Background()
	}

	if args == nil {
		args = []string{} // cobra treats nil as "use os.Args"
	}
	exitCode := ExitOK
	cmd := newRootCmd(env, &exitCode)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(env.Stderr, "meshscan: %v\n", err)
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(env.Stderr, "Run 'meshscan --help' for usage.")
		}
		return ExitError
	}
	return exitCode
}
