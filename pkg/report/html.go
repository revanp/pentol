package report

import (
	"html/template"
	"io"
	"strings"

	"pentol/pkg/model"
)

// HTMLReporter renders a self-contained HTML assessment report.
type HTMLReporter struct{}

// NewHTMLReporter creates a new HTMLReporter.
func NewHTMLReporter() *HTMLReporter {
	return &HTMLReporter{}
}

func (r *HTMLReporter) FormatName() string {
	return "html"
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentol Security Assessment Report — {{.Target.URL}}</title>
<style>
  :root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --border: #334155;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --info: #06b6d4;
    --success: #10b981;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--font-sans);
    background-color: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem 1rem;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  header {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
  }
  .header-title { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
  .header-title h1 { font-size: 1.75rem; font-weight: 700; color: var(--text-primary); }
  .badge-version { background: #3b82f620; color: #60a5fa; border: 1px solid #3b82f640; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-family: var(--font-mono); }
  .grid-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
  .meta-item { background: #0f172a80; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }
  .meta-item .label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }
  .meta-item .value { font-size: 1rem; font-weight: 600; margin-top: 0.25rem; word-break: break-all; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .summary-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem;
    text-align: center;
  }
  .summary-card .count { font-size: 2rem; font-weight: 800; font-family: var(--font-mono); }
  .summary-card .sev-name { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; margin-top: 0.25rem; }
  .card-critical .count, .card-critical .sev-name { color: var(--critical); }
  .card-high .count, .card-high .sev-name { color: var(--high); }
  .card-medium .count, .card-medium .sev-name { color: var(--medium); }
  .card-low .count, .card-low .sev-name { color: var(--low); }
  .card-info .count, .card-info .sev-name { color: var(--info); }
  .card-total .count, .card-total .sev-name { color: var(--text-primary); }

  .section-title { font-size: 1.35rem; font-weight: 700; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
  .finding-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 1.25rem;
    overflow: hidden;
  }
  .finding-header {
    padding: 1.25rem 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    border-bottom: 1px solid var(--border);
    background: #1e293b60;
  }
  .finding-title-group { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .sev-pill {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    text-transform: uppercase;
    font-family: var(--font-mono);
  }
  .pill-CRITICAL { background: #ef444420; color: var(--critical); border: 1px solid #ef444450; }
  .pill-HIGH { background: #f9731620; color: var(--high); border: 1px solid #f9731650; }
  .pill-MEDIUM { background: #eab30820; color: var(--medium); border: 1px solid #eab30850; }
  .pill-LOW { background: #3b82f620; color: var(--low); border: 1px solid #3b82f650; }
  .pill-INFO { background: #06b6d420; color: var(--info); border: 1px solid #06b6d450; }

  .finding-id { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary); }
  .finding-title { font-size: 1.05rem; font-weight: 600; }
  .finding-body { padding: 1.5rem; }
  .field-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); font-weight: 700; margin-bottom: 0.35rem; margin-top: 1rem; }
  .field-label:first-child { margin-top: 0; }
  .field-content { color: #e2e8f0; font-size: 0.95rem; }
  .field-box { background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; font-family: var(--font-mono); font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: 0.25rem; }
  .remediation-box { background: #10b98115; border: 1px solid #10b98140; color: #34d399; border-radius: 8px; padding: 1rem; margin-top: 0.5rem; font-size: 0.95rem; }
  .ref-list { list-style: none; margin-top: 0.25rem; }
  .ref-list li { margin-bottom: 0.25rem; }
  .ref-list a { color: #60a5fa; text-decoration: none; word-break: break-all; font-size: 0.9rem; }
  .ref-list a:hover { text-decoration: underline; }
  footer { text-align: center; margin-top: 3rem; color: var(--text-secondary); font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-title">
      <h1>🛡️ Pentol Security Assessment Report</h1>
      <span class="badge-version">v{{.PentolVersion}}</span>
    </div>
    <div class="grid-meta">
      <div class="meta-item">
        <div class="label">Target</div>
        <div class="value">{{.Target.URL}}</div>
      </div>
      <div class="meta-item">
        <div class="label">Duration</div>
        <div class="value">{{.Duration}}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scan Date</div>
        <div class="value">{{.StartTime.Format "2006-01-02 15:04:05 UTC"}}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scanners Executed</div>
        <div class="value">{{join .ScannersRun ", "}}</div>
      </div>
    </div>
  </header>

  <div class="summary-grid">
    <div class="summary-card card-critical">
      <div class="count">{{.Summary.Critical}}</div>
      <div class="sev-name">Critical</div>
    </div>
    <div class="summary-card card-high">
      <div class="count">{{.Summary.High}}</div>
      <div class="sev-name">High</div>
    </div>
    <div class="summary-card card-medium">
      <div class="count">{{.Summary.Medium}}</div>
      <div class="sev-name">Medium</div>
    </div>
    <div class="summary-card card-low">
      <div class="count">{{.Summary.Low}}</div>
      <div class="sev-name">Low</div>
    </div>
    <div class="summary-card card-info">
      <div class="count">{{.Summary.Info}}</div>
      <div class="sev-name">Info</div>
    </div>
    <div class="summary-card card-total">
      <div class="count">{{.Summary.Total}}</div>
      <div class="sev-name">Total</div>
    </div>
  </div>

  <div class="section-title">Findings ({{len .Findings}})</div>

  {{range .Findings}}
  <div class="finding-card">
    <div class="finding-header">
      <div class="finding-title-group">
        <span class="sev-pill pill-{{.Severity}}">{{.Severity}}</span>
        <span class="finding-title">{{.Title}}</span>
      </div>
      <span class="finding-id">{{.ID}}</span>
    </div>
    <div class="finding-body">
      <div class="field-label">Scanner & Endpoint</div>
      <div class="field-content"><code>{{.Scanner}}</code> &bull; <code>{{.Endpoint}}</code></div>

      <div class="field-label">Description</div>
      <div class="field-content">{{.Description}}</div>

      {{if .Evidence}}
      <div class="field-label">Evidence</div>
      <div class="field-box">{{.Evidence}}</div>
      {{end}}

      {{if .Impact}}
      <div class="field-label">Impact</div>
      <div class="field-content">{{.Impact}}</div>
      {{end}}

      {{if .Remediation}}
      <div class="field-label">Remediation</div>
      <div class="remediation-box">{{.Remediation}}</div>
      {{end}}

      {{if .References}}
      <div class="field-label">References</div>
      <ul class="ref-list">
        {{range .References}}
        <li><a href="{{.}}" target="_blank" rel="noopener noreferrer">{{.}}</a></li>
        {{end}}
      </ul>
      {{end}}
    </div>
  </div>
  {{else}}
  <div class="meta-item" style="text-align:center; padding: 2rem;">
    ✓ No vulnerabilities or security misconfigurations detected.
  </div>
  {{end}}

  <footer>
    Generated by <strong>Pentol Security Toolkit</strong> &bull; Safe & Authorized Penetration Testing
  </footer>
</div>
</body>
</html>`

func (r *HTMLReporter) Render(w io.Writer, res *model.ScanResult) error {
	funcMap := template.FuncMap{
		"join": strings.Join,
	}
	tmpl, err := template.New("pentol_report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, res)
}
