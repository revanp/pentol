package report

import (
	"fmt"
	"io"
	"strings"

	"pentol/pkg/model"
)

// ANSI Color Codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	bgRed        = "\033[41m\033[37m\033[1m"
	bgYellow     = "\033[43m\033[30m\033[1m"
	bgBlue       = "\033[44m\033[37m\033[1m"
	bgMagenta    = "\033[45m\033[37m\033[1m"
	bgCyan       = "\033[46m\033[30m\033[1m"
)

// TerminalReporter renders human-readable colored terminal output.
type TerminalReporter struct {
	NoColor bool
}

// NewTerminalReporter creates a new TerminalReporter.
func NewTerminalReporter(noColor bool) *TerminalReporter {
	return &TerminalReporter{NoColor: noColor}
}

func (r *TerminalReporter) FormatName() string {
	return "terminal"
}

func (r *TerminalReporter) Render(w io.Writer, res *model.ScanResult) error {
	divider := strings.Repeat("─", 78)

	// Banner & Target Information
	fmt.Fprintf(w, "\n%s%sPentol Security Assessment Summary%s\n", r.c(colorBold+colorCyan), "● ", r.c(colorReset))
	fmt.Fprintf(w, "%s\n", divider)
	fmt.Fprintf(w, "  %sTarget:%s     %s\n", r.c(colorBold), r.c(colorReset), res.Target.URL)
	fmt.Fprintf(w, "  %sDuration:%s   %s (Started: %s)\n", r.c(colorBold), r.c(colorReset), res.Duration, res.StartTime.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "  %sScanners:%s   %s\n", r.c(colorBold), r.c(colorReset), strings.Join(res.ScannersRun, ", "))
	fmt.Fprintf(w, "%s\n", divider)

	// Severity Summary Counts
	fmt.Fprintf(w, "  %sFindings Breakdown:%s\n", r.c(colorBold), r.c(colorReset))
	fmt.Fprintf(w, "    CRITICAL: %s%d%s  |  HIGH: %s%d%s  |  MEDIUM: %s%d%s  |  LOW: %s%d%s  |  INFO: %s%d%s  |  TOTAL: %s%d%s\n",
		r.c(colorRed+colorBold), res.Summary.Critical, r.c(colorReset),
		r.c(colorMagenta+colorBold), res.Summary.High, r.c(colorReset),
		r.c(colorYellow+colorBold), res.Summary.Medium, r.c(colorReset),
		r.c(colorCyan), res.Summary.Low, r.c(colorReset),
		r.c(colorBlue), res.Summary.Info, r.c(colorReset),
		r.c(colorBold), res.Summary.Total, r.c(colorReset),
	)
	fmt.Fprintf(w, "%s\n\n", divider)

	if len(res.Findings) == 0 {
		fmt.Fprintf(w, "  %s✓ No security findings detected.%s\n\n", r.c(colorGreen+colorBold), r.c(colorReset))
		return nil
	}

	// List Findings
	for idx, f := range res.Findings {
		badge := r.severityBadge(f.Severity)
		fmt.Fprintf(w, " [%d] %s %s%s%s (%s%s%s)\n",
			idx+1,
			badge,
			r.c(colorBold), f.Title, r.c(colorReset),
			r.c(colorDim), f.ID, r.c(colorReset),
		)
		fmt.Fprintf(w, "     %sEndpoint:%s    %s\n", r.c(colorDim), r.c(colorReset), f.Endpoint)
		fmt.Fprintf(w, "     %sScanner:%s     %s\n", r.c(colorDim), r.c(colorReset), f.Scanner)
		fmt.Fprintf(w, "     %sDescription:%s %s\n", r.c(colorDim), r.c(colorReset), f.Description)
		if f.Evidence != "" {
			fmt.Fprintf(w, "     %sEvidence:%s    %s\n", r.c(colorDim), r.c(colorReset), indent(f.Evidence, "       "))
		}
		if f.Impact != "" {
			fmt.Fprintf(w, "     %sImpact:%s      %s\n", r.c(colorDim), r.c(colorReset), f.Impact)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "     %sFix:%s         %s%s%s\n", r.c(colorGreen+colorBold), r.c(colorReset), r.c(colorGreen), f.Remediation, r.c(colorReset))
		}
		if len(f.References) > 0 {
			fmt.Fprintf(w, "     %sReferences:%s  %s\n", r.c(colorDim), r.c(colorReset), strings.Join(f.References, ", "))
		}
		fmt.Fprintf(w, "\n")
	}

	return nil
}

func (r *TerminalReporter) severityBadge(s model.Severity) string {
	if r.NoColor {
		return fmt.Sprintf("[%s]", s)
	}
	switch s {
	case model.SeverityCritical:
		return fmt.Sprintf("%s CRITICAL %s", bgRed, colorReset)
	case model.SeverityHigh:
		return fmt.Sprintf("%s HIGH %s", bgMagenta, colorReset)
	case model.SeverityMedium:
		return fmt.Sprintf("%s MEDIUM %s", bgYellow, colorReset)
	case model.SeverityLow:
		return fmt.Sprintf("%s LOW %s", bgCyan, colorReset)
	case model.SeverityInfo:
		return fmt.Sprintf("%s INFO %s", bgBlue, colorReset)
	default:
		return fmt.Sprintf("[%s]", s)
	}
}

func (r *TerminalReporter) c(code string) string {
	if r.NoColor {
		return ""
	}
	return code
}

func indent(text, pad string) string {
	lines := strings.Split(text, "\n")
	if len(lines) == 1 {
		return text
	}
	return strings.Join(lines, "\n"+pad)
}
