package recon_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pentol/pkg/model"
	reconScanner "pentol/pkg/scanners/recon"
)

func TestReconScannerRobotsAndSitemap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nDisallow: /.env\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<urlset><url><loc>https://example.com/page1</loc></url><url><loc>https://example.com/page2</loc></url></urlset>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><div id="__next">Hello Next</div></body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	target, err := model.ParseTarget(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test target: %v", err)
	}

	scope := model.NewDefaultScope(target)
	scanner := reconScanner.NewReconScanner()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := scanner.Run(ctx, target, scope)
	if err != nil {
		t.Fatalf("recon scanner failed: %v", err)
	}

	foundRobots := false
	foundSensitivePaths := false
	foundSitemap := false
	foundTech := false

	for _, f := range findings {
		if strings.Contains(f.Title, "robots.txt File Discovered") {
			foundRobots = true
		}
		if strings.Contains(f.Title, "Sensitive Paths Disclosed") {
			foundSensitivePaths = true
		}
		if strings.Contains(f.Title, "sitemap.xml") {
			foundSitemap = true
		}
		if strings.Contains(f.Title, "Technology Stack Fingerprinted") {
			foundTech = true
		}
	}

	if !foundRobots {
		t.Errorf("expected robots.txt finding")
	}
	if !foundSensitivePaths {
		t.Errorf("expected sensitive disallowed paths finding")
	}
	if !foundSitemap {
		t.Errorf("expected sitemap.xml finding")
	}
	if !foundTech {
		t.Errorf("expected technology fingerprinting finding")
	}
}
