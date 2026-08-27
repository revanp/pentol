package tests

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pentol/pkg/engine"
	"pentol/pkg/model"
	"pentol/pkg/report"
)

func TestFullOrchestratorPipeline(t *testing.T) {
	// Setup test mock HTTP server simulating common security flaws
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /backup\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<urlset><url><loc>https://example.com/</loc></url></urlset>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Set-Cookie", "session=xyz987; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Index of /secret</title></head><body><h1>Index of /secret</h1></body></html>"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	target, err := model.ParseTarget(server.URL)
	if err != nil {
		t.Fatalf("target parse error: %v", err)
	}

	cfg := engine.NewDefaultConfig(target)
	cfg.EnableTLS = false // Standalone HTTP mock server

	orc, err := engine.NewOrchestrator(cfg, "0.1.0-v1")
	if err != nil {
		t.Fatalf("orchestrator init error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := orc.Execute(ctx, nil)
	if err != nil {
		t.Fatalf("scan execution error: %v", err)
	}

	if result.Summary.Total == 0 {
		t.Errorf("expected findings from simulated vulnerable server, got 0")
	}

	// Test Terminal Rendering
	var termBuf bytes.Buffer
	termRep := report.NewTerminalReporter(true)
	if err := termRep.Render(&termBuf, result); err != nil {
		t.Errorf("terminal render error: %v", err)
	}
	if !strings.Contains(termBuf.String(), "Pentol Security Assessment Summary") {
		t.Errorf("terminal output missing summary header")
	}

	// Test JSON Rendering
	var jsonBuf bytes.Buffer
	jsonRep := report.NewJSONReporter(true)
	if err := jsonRep.Render(&jsonBuf, result); err != nil {
		t.Errorf("json render error: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"pentol_version": "0.1.0-v1"`) {
		t.Errorf("json output missing pentol_version")
	}

	// Test Markdown Rendering
	var mdBuf bytes.Buffer
	mdRep := report.NewMarkdownReporter()
	if err := mdRep.Render(&mdBuf, result); err != nil {
		t.Errorf("markdown render error: %v", err)
	}
	if !strings.Contains(mdBuf.String(), "# Pentol Security Assessment Report") {
		t.Errorf("markdown output missing title")
	}

	// Test HTML Rendering
	var htmlBuf bytes.Buffer
	htmlRep := report.NewHTMLReporter()
	if err := htmlRep.Render(&htmlBuf, result); err != nil {
		t.Errorf("html render error: %v", err)
	}
	if !strings.Contains(htmlBuf.String(), "<!DOCTYPE html>") {
		t.Errorf("html output missing DOCTYPE")
	}
}

func TestScopeEnforcement(t *testing.T) {
	target, _ := model.ParseTarget("https://internal.evil.com")
	cfg := engine.NewDefaultConfig(target)
	cfg.Scope.AllowedHosts = []string{"authorized.local"}

	orc, _ := engine.NewOrchestrator(cfg, "0.1.0-v1")
	ctx := context.Background()

	_, err := orc.Execute(ctx, nil)
	if err == nil {
		t.Errorf("expected scope violation error, got nil")
	}
}
