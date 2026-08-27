package report

import (
	"fmt"
	"io"
	"strings"

	"pentol/pkg/model"
)

// MarkdownReporter formats ScanResult into GitHub Flavored Markdown.
type MarkdownReporter struct{}

// NewMarkdownReporter creates a new MarkdownReporter.
func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

func (r *MarkdownReporter) FormatName() string {
	return "markdown"
}

func (r *MarkdownReporter) Render(w io.Writer, res *model.ScanResult) error {
	fmt.Fprintf(w, "# Pentol Security Assessment Report\n\n")

	// Target & Metadata Table
	fmt.Fprintf(w, "## 🎯 Assessment Overview\n\n")
	fmt.Fprintf(w, "| Field | Value |\n")
	fmt.Fprintf(w, "| :--- | :--- |\n")
	fmt.Fprintf(w, "| **Target URL** | `%s` |\n", res.Target.URL)
	fmt.Fprintf(w, "| **Hostname** | `%s` |\n", res.Target.Hostname)
	fmt.Fprintf(w, "| **Scan Start** | `%s` |\n", res.StartTime.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "| **Duration** | `%s` |\n", res.Duration)
	fmt.Fprintf(w, "| **Pentol Version** | `%s` |\n", res.PentolVersion)
	fmt.Fprintf(w, "| **Scanners Run** | %s |\n\n", strings.Join(res.ScannersRun, ", "))

	// Severity Summary Table
	fmt.Fprintf(w, "## 📊 Severity Summary\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "| :--- | :--- |\n")
	fmt.Fprintf(w, "| 🔴 **CRITICAL** | %d |\n", res.Summary.Critical)
	fmt.Fprintf(w, "| 🟠 **HIGH** | %d |\n", res.Summary.High)
	fmt.Fprintf(w, "| 🟡 **MEDIUM** | %d |\n", res.Summary.Medium)
	fmt.Fprintf(w, "| 🔵 **LOW** | %d |\n", res.Summary.Low)
	fmt.Fprintf(w, "| ⚪ **INFO** | %d |\n", res.Summary.Info)
	fmt.Fprintf(w, "| **Total Findings** | **%d** |\n\n", res.Summary.Total)

	// Findings Section
	fmt.Fprintf(w, "## 🛡️ Detailed Findings\n\n")

	if len(res.Findings) == 0 {
		fmt.Fprintf(w, "> [!NOTE]\n> No security findings were identified for this target.\n\n")
		return nil
	}

	for idx, f := range res.Findings {
		icon := severityIcon(f.Severity)
		fmt.Fprintf(w, "### %d. %s [%s] %s\n\n", idx+1, icon, f.Severity, f.Title)
		fmt.Fprintf(w, "- **Finding ID**: `%s`\n", f.ID)
		fmt.Fprintf(w, "- **Scanner**: `%s`\n", f.Scanner)
		fmt.Fprintf(w, "- **Target**: `%s`\n", f.Target)
		fmt.Fprintf(w, "- **Endpoint**: `%s`\n", f.Endpoint)
		fmt.Fprintf(w, "- **Status**: `%s`\n\n", f.Status)

		fmt.Fprintf(w, "#### Description\n%s\n\n", f.Description)

		if f.Evidence != "" {
			fmt.Fprintf(w, "#### Evidence\n```text\n%s\n```\n\n", f.Evidence)
		}

		if f.Impact != "" {
			fmt.Fprintf(w, "#### Impact\n%s\n\n", f.Impact)
		}

		if f.Remediation != "" {
			fmt.Fprintf(w, "#### Remediation\n> [!TIP]\n> %s\n\n", f.Remediation)
		}

		if len(f.References) > 0 {
			fmt.Fprintf(w, "#### References\n")
			for _, ref := range f.References {
				fmt.Fprintf(w, "- <%s>\n", ref)
			}
			fmt.Fprintf(w, "\n")
		}

		fmt.Fprintf(w, "---\n\n")
	}

	return nil
}

func severityIcon(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🔵"
	case model.SeverityInfo:
		return "⚪"
	default:
		return "▫️"
	}
}
