package report

import (
	"io"

	"pentol/pkg/model"
)

// Reporter is the interface implemented by all Pentol output formatters.
type Reporter interface {
	// FormatName returns the name of the format (e.g. "terminal", "json", "markdown", "html")
	FormatName() string

	// Render writes the formatted ScanResult to the provided io.Writer.
	Render(w io.Writer, result *model.ScanResult) error
}
