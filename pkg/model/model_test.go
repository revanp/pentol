package model_test

import (
	"testing"

	"pentol/pkg/model"
)

func TestFindingModelValidation(t *testing.T) {
	finding := model.NewFinding(
		"http-scanner",
		"Missing Content-Security-Policy Header",
		model.SeverityMedium,
		"https://example.com",
		"/",
		"The server response did not include a Content-Security-Policy header.",
		"Headers received: Server: nginx",
		"Increased risk of Cross-Site Scripting (XSS) attacks.",
		"Configure a robust Content-Security-Policy header.",
		[]string{"https://owasp.org/www-project-secure-headers/"},
	)

	if err := finding.Validate(); err != nil {
		t.Fatalf("expected valid finding, got: %v", err)
	}

	if finding.Status != model.StatusOpen {
		t.Errorf("expected StatusOpen, got: %s", finding.Status)
	}

	if finding.ID == "" {
		t.Errorf("expected non-empty deterministic finding ID")
	}

	// Deterministic ID check
	id2 := model.GenerateFindingID("http-scanner", "https://example.com", "/", "Missing Content-Security-Policy Header")
	if finding.ID != id2 {
		t.Errorf("expected deterministic IDs to match: %s != %s", finding.ID, id2)
	}
}

func TestTargetParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		isHTTPS  bool
		port     int
	}{
		{"example.com", "https://example.com", true, 443},
		{"http://test.local:8080/api", "http://test.local:8080/api", false, 8080},
		{"https://staging.internal.net", "https://staging.internal.net", true, 443},
	}

	for _, tt := range tests {
		target, err := model.ParseTarget(tt.input)
		if err != nil {
			t.Fatalf("unexpected error parsing %s: %v", tt.input, err)
		}
		if target.URL != tt.expected {
			t.Errorf("for input %s, expected URL %s, got %s", tt.input, tt.expected, target.URL)
		}
		if target.IsHTTPS != tt.isHTTPS {
			t.Errorf("for input %s, expected isHTTPS=%v, got %v", tt.input, tt.isHTTPS, target.IsHTTPS)
		}
		if target.Port != tt.port {
			t.Errorf("for input %s, expected port=%d, got %d", tt.input, tt.port, target.Port)
		}
	}
}

func TestScopeFiltering(t *testing.T) {
	target, err := model.ParseTarget("https://app.example.com")
	if err != nil {
		t.Fatalf("target parse failed: %v", err)
	}

	scope := model.NewDefaultScope(target)
	scope.AllowSubdomains = true
	scope.ExcludedHosts = []string{"admin.example.com"}

	inScope, _ := scope.IsInScope("app.example.com")
	if !inScope {
		t.Errorf("expected app.example.com to be in scope")
	}

	inScopeSub, _ := scope.IsInScope("api.app.example.com")
	if !inScopeSub {
		t.Errorf("expected api.app.example.com to be in scope with subdomains allowed")
	}

	inScopeExcluded, reason := scope.IsInScope("admin.example.com")
	if inScopeExcluded {
		t.Errorf("expected admin.example.com to be excluded, reason: %s", reason)
	}

	inScopeOut, _ := scope.IsInScope("evil.com")
	if inScopeOut {
		t.Errorf("expected evil.com to be out of scope")
	}
}

func TestScanResultAggregation(t *testing.T) {
	target, _ := model.ParseTarget("https://example.com")
	result := model.NewScanResult("1.0.0", target)

	f1 := model.NewFinding("tls", "Expired Certificate", model.SeverityCritical, target.URL, "", "Cert expired", "expired 2 days ago", "Broken trust", "Renew cert", nil)
	f2 := model.NewFinding("http", "Missing CSP", model.SeverityMedium, target.URL, "/", "Missing CSP", "None", "XSS risk", "Add CSP", nil)
	f3 := model.NewFinding("recon", "Robots Disallow", model.SeverityInfo, target.URL, "/robots.txt", "Disallow entry found", "Disallow: /admin", "Info leak", "Verify paths", nil)

	result.AddFinding(f1)
	result.AddFinding(f2)
	result.AddFinding(f3)
	result.Finalize()

	if result.Summary.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Summary.Total)
	}
	if result.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", result.Summary.Critical)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", result.Summary.Medium)
	}
	if result.Summary.Info != 1 {
		t.Errorf("expected 1 info, got %d", result.Summary.Info)
	}

	// Verify sorting: Critical should be first
	if result.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("expected first finding to be Critical, got %s", result.Findings[0].Severity)
	}
}
