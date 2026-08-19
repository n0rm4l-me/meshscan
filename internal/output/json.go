package output

import (
	"encoding/json"
	"io"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

type jsonFinding struct {
	Severity  string `json:"severity"`
	Check     string `json:"check"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Message   string `json:"message"`
	Fix       string `json:"fix,omitempty"`
}

func JSON(w io.Writer, findings []model.Finding) error {
	out := make([]jsonFinding, len(findings))
	for i, f := range findings {
		out[i] = jsonFinding{
			Severity:  f.Severity.String(),
			Check:     f.Check,
			Resource:  f.Resource,
			Namespace: f.Namespace,
			Message:   f.Message,
			Fix:       f.Fix,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
