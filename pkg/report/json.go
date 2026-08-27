package report

import (
	"encoding/json"
	"io"

	"pentol/pkg/model"
)

// JSONReporter formats ScanResult into formatted JSON.
type JSONReporter struct {
	Indent bool
}

// NewJSONReporter creates a new JSONReporter.
func NewJSONReporter(indent bool) *JSONReporter {
	return &JSONReporter{Indent: indent}
}

func (r *JSONReporter) FormatName() string {
	return "json"
}

func (r *JSONReporter) Render(w io.Writer, res *model.ScanResult) error {
	encoder := json.NewEncoder(w)
	if r.Indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(res)
}
