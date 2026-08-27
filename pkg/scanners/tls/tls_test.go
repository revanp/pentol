package tls_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pentol/pkg/model"
	tlsScanner "pentol/pkg/scanners/tls"
)

func TestTLSScannerSelfSignedCert(t *testing.T) {
	// Create TLS test server (generates a self-signed certificate)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	target, err := model.ParseTarget(server.URL)
	if err != nil {
		t.Fatalf("failed to parse target: %v", err)
	}

	scope := model.NewDefaultScope(target)
	scanner := tlsScanner.NewTLSScanner(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := scanner.Run(ctx, target, scope)
	if err != nil {
		t.Fatalf("TLS scanner failed: %v", err)
	}

	// Self-signed certificate should trigger an untrusted certificate finding
	foundUntrusted := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Untrusted") || strings.Contains(f.Title, "Certificate") {
			foundUntrusted = true
		}
	}

	if !foundUntrusted {
		t.Errorf("expected finding for untrusted / self-signed certificate on httptest TLS server")
	}
}
