package recon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"pentol/pkg/model"
	"pentol/pkg/scanners"
)

// Ensure ReconScanner implements scanners.Scanner
var _ scanners.Scanner = (*ReconScanner)(nil)

// ReconScanner performs passive, low-risk reconnaissance.
type ReconScanner struct {
	client    *http.Client
	userAgent string
}

// Option configures ReconScanner.
type Option func(*ReconScanner)

// WithUserAgent sets a custom User-Agent for recon requests.
func WithUserAgent(ua string) Option {
	return func(s *ReconScanner) {
		s.userAgent = ua
	}
}

// WithRequestTimeout sets the per-request HTTP client timeout.
func WithRequestTimeout(d time.Duration) Option {
	return func(s *ReconScanner) {
		if d > 0 {
			s.client.Timeout = d
		}
	}
}

// NewReconScanner creates a new ReconScanner with optional configuration.
func NewReconScanner(opts ...Option) *ReconScanner {
	s := &ReconScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		userAgent: "Pentol-Security-Scanner/1.0",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *ReconScanner) Name() string {
	return "recon-scanner"
}

func (s *ReconScanner) Description() string {
	return "Performs DNS resolution, technology fingerprinting, robots.txt inspection, and sitemap.xml discovery."
}

// Run executes the reconnaissance checks.
func (s *ReconScanner) Run(ctx context.Context, target *model.Target, scope *model.ScopeConfig) ([]*model.Finding, error) {
	var findings []*model.Finding

	// Verify scope
	if inScope, reason := scope.IsInScope(target.URL); !inScope {
		return nil, fmt.Errorf("target %s out of scope: %s", target.URL, reason)
	}

	// 1. DNS Reconnaissance (skip if target is a raw IP)
	if !target.IsIP {
		dnsFindings := s.checkDNS(ctx, target)
		findings = append(findings, dnsFindings...)
	}

	// 2. Robots.txt Analysis
	robotsFindings := s.checkRobotsTxt(ctx, target)
	findings = append(findings, robotsFindings...)

	// 3. Sitemap.xml Analysis
	sitemapFindings := s.checkSitemapXml(ctx, target)
	findings = append(findings, sitemapFindings...)

	// 4. Technology Fingerprinting
	techFindings := s.checkTechnologyFingerprint(ctx, target)
	findings = append(findings, techFindings...)

	return findings, nil
}

// checkDNS resolves A, AAAA, CNAME, MX, TXT, and NS records.
func (s *ReconScanner) checkDNS(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding
	host := target.Hostname

	resolver := net.DefaultResolver

	var evidenceList []string

	// A / AAAA
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ips) > 0 {
		var ipStrs []string
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		evidenceList = append(evidenceList, fmt.Sprintf("IP Addresses (A/AAAA): %s", strings.Join(ipStrs, ", ")))
	}

	// CNAME
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" && cname != host+"." && cname != host {
		evidenceList = append(evidenceList, fmt.Sprintf("CNAME: %s", cname))
	}

	// MX
	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil && len(mxRecords) > 0 {
		var mxStrs []string
		for _, mx := range mxRecords {
			mxStrs = append(mxStrs, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
		}
		evidenceList = append(evidenceList, fmt.Sprintf("MX Records: %s", strings.Join(mxStrs, ", ")))
	}

	// TXT (Check for SPF, DKIM, verification tokens)
	txtRecords, err := resolver.LookupTXT(ctx, host)
	if err == nil && len(txtRecords) > 0 {
		evidenceList = append(evidenceList, fmt.Sprintf("TXT Records: %s", strings.Join(txtRecords, "; ")))

		// Check for missing SPF record
		hasSPF := false
		for _, txt := range txtRecords {
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				hasSPF = true
				break
			}
		}
		if !hasSPF {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"Missing Sender Policy Framework (SPF) DNS Record",
				model.SeverityLow,
				target.URL,
				host,
				"The domain does not publish an SPF record to restrict authorized email senders.",
				fmt.Sprintf("TXT records found for %s do not contain v=spf1.", host),
				"Attackers can easily forge phishing emails impersonating this domain.",
				"Publish a TXT record with SPF policy (e.g. 'v=spf1 include:_spf.example.com ~all').",
				[]string{"https://www.rfc-editor.org/rfc/rfc7208"},
			))
		}
	}

	// NS
	nsRecords, err := resolver.LookupNS(ctx, host)
	if err == nil && len(nsRecords) > 0 {
		var nsStrs []string
		for _, ns := range nsRecords {
			nsStrs = append(nsStrs, ns.Host)
		}
		evidenceList = append(evidenceList, fmt.Sprintf("Name Servers: %s", strings.Join(nsStrs, ", ")))
	}

	if len(evidenceList) > 0 {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"DNS Resolution and Infrastructure Records",
			model.SeverityInfo,
			target.URL,
			host,
			"Discovered active DNS infrastructure and network records for the target host.",
			strings.Join(evidenceList, "\n"),
			"Information disclosure regarding domain routing, mail infrastructure, and hosting providers.",
			"Ensure DNS records do not expose internal non-public hosts or dangling CNAME pointers.",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"},
		))
	}

	return findings
}

// checkRobotsTxt fetches and inspects /robots.txt for sensitive endpoints.
func (s *ReconScanner) checkRobotsTxt(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	robotsURL := fmt.Sprintf("%s/robots.txt", target.BaseURL())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*64))
		body := string(bodyBytes)

		// Check if it's a real robots.txt (not a 404 disguised as 200 HTML page)
		if strings.Contains(strings.ToLower(body), "user-agent:") || strings.Contains(strings.ToLower(body), "disallow:") {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"robots.txt File Discovered",
				model.SeverityInfo,
				target.URL,
				"/robots.txt",
				"A valid robots.txt file was found at the root of the web application.",
				fmt.Sprintf("robots.txt content:\n%s", truncateString(body, 500)),
				"Search engine crawlers and security researchers use robots.txt to discover hidden paths.",
				"Review robots.txt to ensure sensitive administrative or internal URLs are not listed.",
				[]string{"https://developers.google.com/search/docs/crawling-indexing/robots/intro"},
			))

			// Check for sensitive paths in Disallow
			sensitiveKeywords := []string{
				"admin", "backup", "db", "database", "secret", "private", "api", "internal",
				".env", "config", "staging", "test", "root", "portal", "wp-admin", "cgi-bin",
			}

			lines := strings.Split(body, "\n")
			var exposedSensitivePaths []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "disallow:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						path := strings.TrimSpace(parts[1])
						for _, kw := range sensitiveKeywords {
							if strings.Contains(strings.ToLower(path), kw) {
								exposedSensitivePaths = append(exposedSensitivePaths, path)
								break
							}
						}
					}
				}
			}

			if len(exposedSensitivePaths) > 0 {
				findings = append(findings, model.NewFinding(
					s.Name(),
					"Sensitive Paths Disclosed in robots.txt",
					model.SeverityLow,
					target.URL,
					"/robots.txt",
					"robots.txt contains Disallow directives pointing to administrative or sensitive directories.",
					fmt.Sprintf("Potentially sensitive disallowed paths:\n- %s", strings.Join(exposedSensitivePaths, "\n- ")),
					"Adversaries specifically parse robots.txt Disallow entries to locate administrative portals, backup files, and internal endpoints.",
					"Do not rely on robots.txt for security. Protect sensitive endpoints with strong authentication and authorization controls.",
					[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"},
				))
			}
		}
	}

	return findings
}

// checkSitemapXml checks for /sitemap.xml.
func (s *ReconScanner) checkSitemapXml(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	sitemapURL := fmt.Sprintf("%s/sitemap.xml", target.BaseURL())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*64))
		body := string(bodyBytes)

		if strings.Contains(body, "<urlset") || strings.Contains(body, "<sitemapindex") {
			// Count total URLs
			urlCount := strings.Count(body, "<loc>")
			findings = append(findings, model.NewFinding(
				s.Name(),
				"sitemap.xml File Discovered",
				model.SeverityInfo,
				target.URL,
				"/sitemap.xml",
				"A public sitemap.xml file was detected on the target server.",
				fmt.Sprintf("sitemap.xml contains %d mapped URL entries.", urlCount),
				"Provides a roadmap of public application routes, content architecture, and published endpoints.",
				"Verify that non-public, staging, or administrative pages are excluded from sitemaps.",
				[]string{"https://www.sitemaps.org/protocol.html"},
			))
		}
	}

	return findings
}

// checkTechnologyFingerprint identifies frontend and backend frameworks from responses.
func (s *ReconScanner) checkTechnologyFingerprint(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*256))
	body := string(bodyBytes)

	var detectedTech []string

	// Check meta generator
	genRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	matches := genRegex.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			detectedTech = append(detectedTech, fmt.Sprintf("Meta Generator: %s", m[1]))
		}
	}

	// Frontend Framework Signatures
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "__next") || strings.Contains(lowerBody, "/_next/static/") {
		detectedTech = append(detectedTech, "Next.js (React Framework)")
	}
	if strings.Contains(lowerBody, "__nuxt") || strings.Contains(lowerBody, "/_nuxt/") {
		detectedTech = append(detectedTech, "Nuxt.js (Vue Framework)")
	}
	if strings.Contains(lowerBody, "ng-version=") || strings.Contains(lowerBody, "ng-app=") {
		detectedTech = append(detectedTech, "Angular")
	}
	if strings.Contains(lowerBody, "react-root") || strings.Contains(lowerBody, "data-reactroot") {
		detectedTech = append(detectedTech, "React")
	}
	if strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-includes") {
		detectedTech = append(detectedTech, "WordPress CMS")
	}
	if strings.Contains(lowerBody, "drupal.js") || strings.Contains(lowerBody, "drupalsettings") {
		detectedTech = append(detectedTech, "Drupal CMS")
	}
	if strings.Contains(lowerBody, "laravel") || strings.Contains(resp.Header.Get("Set-Cookie"), "laravel_session") {
		detectedTech = append(detectedTech, "Laravel PHP Framework")
	}

	if len(detectedTech) > 0 {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Web Technology Stack Fingerprinted",
			model.SeverityInfo,
			target.URL,
			target.Path,
			"Identified application frameworks and content management systems from passive inspection.",
			fmt.Sprintf("Detected technologies:\n- %s", strings.Join(detectedTech, "\n- ")),
			"Assists penetration testers and security teams in mapping out technology stack attack surfaces.",
			"Keep all identified libraries, frameworks, and CMS engines patched and updated to the latest security releases.",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		))
	}

	return findings
}

func truncateString(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen] + "\n... [TRUNCATED]"
}
