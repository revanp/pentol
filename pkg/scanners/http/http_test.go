package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pentol/pkg/model"
	httpScanner "pentol/pkg/scanners/http"
)

func TestHTTPScannerMissingSecurityHeaders(t *testing.T) {
	// Create mock server without security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Set-Cookie", "session_id=secret123; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Hello Pentol</body></html>"))
	}))
	defer server.Close()

	target, err := model.ParseTarget(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test target: %v", err)
	}

	scope := model.NewDefaultScope(target)
	scanner := httpScanner.NewHTTPScanner()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := scanner.Run(ctx, target, scope)
	if err != nil {
		t.Fatalf("scanner run failed: %v", err)
	}

	// Verify we detected missing headers and disclosures
	foundCSP := false
	foundXFO := false
	foundServerVersion := false
	foundPoweredBy := false
	foundInsecureCookie := false

	for _, f := range findings {
		if strings.Contains(f.Title, "Content-Security-Policy") {
			foundCSP = true
		}
		if strings.Contains(f.Title, "X-Frame-Options") {
			foundXFO = true
		}
		if strings.Contains(f.Title, "Server Version") {
			foundServerVersion = true
		}
		if strings.Contains(f.Title, "X-Powered-By") {
			foundPoweredBy = true
		}
		if strings.Contains(f.Title, "session_id") {
			foundInsecureCookie = true
		}
	}

	if !foundCSP {
		t.Errorf("expected finding for missing CSP")
	}
	if !foundXFO {
		t.Errorf("expected finding for missing X-Frame-Options")
	}
	if !foundServerVersion {
		t.Errorf("expected finding for Server version disclosure")
	}
	if !foundPoweredBy {
		t.Errorf("expected finding for X-Powered-By disclosure")
	}
	if !foundInsecureCookie {
		t.Errorf("expected finding for insecure session cookie")
	}
}

func TestHTTPScannerDirectoryListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1></body></html>"))
	}))
	defer server.Close()

	target, _ := model.ParseTarget(server.URL)
	scope := model.NewDefaultScope(target)
	scanner := httpScanner.NewHTTPScanner()

	ctx := context.Background()
	findings, err := scanner.Run(ctx, target, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundDirList := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Directory Listing") {
			foundDirList = true
		}
	}

	if !foundDirList {
		t.Errorf("expected Directory Listing finding")
	}
}
