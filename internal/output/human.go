package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// Human writes a human-readable report to w, with ANSI colors when color is true.
// When namespace is empty, the report covers multiple namespaces and each
// finding is prefixed with its namespace.
func Human(w io.Writer, findings []model.Finding, namespace string, color bool) {
	reset, bold, gray := "", "", ""
	if color {
		reset, bold, gray = colorReset, colorBold, colorGray
	}

	scope := "all namespaces"
	if namespace != "" {
		scope = "namespace " + namespace
	}

	if len(findings) == 0 {
		fmt.Fprintf(w, "%s✓ no issues found in %s%s\n", bold, scope, reset)
		return
	}

	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Fprintf(w, "%smeshscan report: %s%s\n", bold, scope, reset)
	fmt.Fprintf(w, "%s%d issues: %d critical, %d high, %d medium, %d low%s\n\n",
		gray,
		len(findings),
		counts[model.SeverityCritical],
		counts[model.SeverityHigh],
		counts[model.SeverityMedium],
		counts[model.SeverityLow],
		reset,
	)

	for _, f := range findings {
		resource := f.Resource
		if namespace == "" {
			resource = f.Namespace + "/" + f.Resource
		}
		fmt.Fprintf(w, "%s[%s]%s %s%s%s\n", severityColor(f.Severity, color), f.Severity, reset, bold, resource, reset)
		fmt.Fprintf(w, "  check: %s\n", f.Check)
		fmt.Fprintf(w, "  %s\n", f.Message)
		if f.Fix != "" {
			fixIndented := strings.ReplaceAll(f.Fix, "\n", "\n  ")
			fmt.Fprintf(w, "  %sfix:%s %s\n", gray, reset, fixIndented)
		}
		fmt.Fprintln(w)
	}
}

func severityColor(s model.Severity, color bool) string {
	if !color {
		return ""
	}
	switch s {
	case model.SeverityCritical:
		return colorRed + colorBold
	case model.SeverityHigh:
		return colorRed
	case model.SeverityMedium:
		return colorYellow
	}
	return colorCyan
}
