package report_test

import (
	"bytes"
	"strings"
	"testing"

	"pentol/pkg/model"
	"pentol/pkg/report"
)

func createSampleResult() *model.ScanResult {
	target, _ := model.ParseTarget("https://staging.example.com")
	res := model.NewScanResult("1.0.0", target)
	res.ScannersRun = []string{"http-scanner", "tls-scanner", "recon-scanner"}

	f := model.NewFinding(
		"http-scanner",
		"Missing HSTS Header",
		model.SeverityMedium,
		target.URL,
		"/",
		"HSTS header missing.",
		"Strict-Transport-Security header is absent.",
		"MitM downgrade attacks possible.",
		"Add HSTS header.",
		[]string{"https://example.com/hsts"},
	)
	res.AddFinding(f)
	res.Finalize()
	return res
}

func TestTerminalReporter(t *testing.T) {
	res := createSampleResult()
	rep := report.NewTerminalReporter(true)

	var buf bytes.Buffer
	if err := rep.Render(&buf, res); err != nil {
		t.Fatalf("terminal render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Pentol Security Assessment Summary") {
		t.Errorf("missing summary banner in terminal output")
	}
	if !strings.Contains(out, "Missing HSTS Header") {
		t.Errorf("missing finding title in terminal output")
	}
}

func TestJSONReporter(t *testing.T) {
	res := createSampleResult()
	rep := report.NewJSONReporter(true)

	var buf bytes.Buffer
	if err := rep.Render(&buf, res); err != nil {
		t.Fatalf("json render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"pentol_version": "1.0.0"`) {
		t.Errorf("invalid json output: %s", out)
	}
	if !strings.Contains(out, `"severity": "MEDIUM"`) {
		t.Errorf("missing severity in json output")
	}
}

func TestMarkdownReporter(t *testing.T) {
	res := createSampleResult()
	rep := report.NewMarkdownReporter()

	var buf bytes.Buffer
	if err := rep.Render(&buf, res); err != nil {
		t.Fatalf("markdown render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "# Pentol Security Assessment Report") {
		t.Errorf("missing title in markdown output")
	}
	if !strings.Contains(out, "Missing HSTS Header") {
		t.Errorf("missing finding in markdown output")
	}
}

func TestHTMLReporter(t *testing.T) {
	res := createSampleResult()
	rep := report.NewHTMLReporter()

	var buf bytes.Buffer
	if err := rep.Render(&buf, res); err != nil {
		t.Fatalf("html render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Errorf("missing doctype in html output")
	}
	if !strings.Contains(out, "Missing HSTS Header") {
		t.Errorf("missing finding in html output")
	}
}
