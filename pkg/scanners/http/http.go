package http

import (
	"context"
	"crypto/tls"
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

// Ensure HTTPScanner implements scanners.Scanner
var _ scanners.Scanner = (*HTTPScanner)(nil)

// HTTPScanner performs passive and low-risk HTTP security checks.
type HTTPScanner struct {
	client    *http.Client
	userAgent string
	delay     time.Duration
}

// Option configures HTTPScanner.
type Option func(*HTTPScanner)

// WithUserAgent sets a custom User-Agent.
func WithUserAgent(ua string) Option {
	return func(s *HTTPScanner) {
		s.userAgent = ua
	}
}

// WithRateLimitDelay sets delay between requests.
func WithRateLimitDelay(d time.Duration) Option {
	return func(s *HTTPScanner) {
		s.delay = d
	}
}

// WithRequestTimeout sets the per-request HTTP client timeout.
func WithRequestTimeout(d time.Duration) Option {
	return func(s *HTTPScanner) {
		if d > 0 {
			s.client.Timeout = d
		}
	}
}

// WithInsecureTLS configures client to skip certificate verification if testing broken TLS endpoints.
// Only the InsecureSkipVerify field is changed; MinVersion and other settings are preserved.
func WithInsecureTLS(insecure bool) Option {
	return func(s *HTTPScanner) {
		if transport, ok := s.client.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.InsecureSkipVerify = insecure //nolint:gosec
		}
	}
}

// NewHTTPScanner creates a new HTTP security scanner.
func NewHTTPScanner(opts ...Option) *HTTPScanner {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	scanner := &HTTPScanner{
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects automatically so we can inspect redirect headers and status
				return http.ErrUseLastResponse
			},
		},
		userAgent: "Pentol-Security-Scanner/1.0",
		delay:     100 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func (s *HTTPScanner) Name() string {
	return "http-scanner"
}

func (s *HTTPScanner) Description() string {
	return "Analyzes HTTP headers, cookie security, HTTP-to-HTTPS redirect, dangerous methods, and information disclosure."
}

// Run executes all HTTP security checks against the target.
func (s *HTTPScanner) Run(ctx context.Context, target *model.Target, scope *model.ScopeConfig) ([]*model.Finding, error) {
	var findings []*model.Finding

	// Verify scope
	if inScope, reason := scope.IsInScope(target.URL); !inScope {
		return nil, fmt.Errorf("target %s out of scope: %s", target.URL, reason)
	}

	// 1. Check HTTP to HTTPS redirection (if scheme is HTTP or domain provided)
	httpsRedirectFindings := s.checkHTTPSRedirection(ctx, target)
	findings = append(findings, httpsRedirectFindings...)

	// 2. Fetch baseline response from target URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return findings, fmt.Errorf("failed to create baseline request: %w", err)
	}
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		// Target might be unreachable or TLS error
		return findings, fmt.Errorf("HTTP request to %s failed: %w", target.URL, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*512)) // Max 512KB for passive inspection
	bodyStr := string(bodyBytes)

	// 3. Security Headers Analysis
	headerFindings := s.checkSecurityHeaders(target, resp)
	findings = append(findings, headerFindings...)

	// 4. Cookie Security Analysis
	cookieFindings := s.checkCookies(target, resp)
	findings = append(findings, cookieFindings...)

	// 5. Server & Tech Disclosure in headers
	disclosureFindings := s.checkInfoDisclosure(target, resp, bodyStr)
	findings = append(findings, disclosureFindings...)

	// 6. Dangerous HTTP Methods
	time.Sleep(s.delay)
	methodFindings := s.checkHTTPMethods(ctx, target)
	findings = append(findings, methodFindings...)

	// 7. Directory Listing / Passive Body Checks
	bodyFindings := s.checkResponseBody(target, resp.StatusCode, bodyStr)
	findings = append(findings, bodyFindings...)

	return findings, nil
}

// checkHTTPSRedirection tests if http://<host> redirects to https://
func (s *HTTPScanner) checkHTTPSRedirection(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	httpURL := fmt.Sprintf("http://%s", target.Host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		// HTTP port may be closed or filtered, which is common if HTTPS-only is enforced at network level
		return findings
	}
	defer resp.Body.Close()

	// Check if status is a redirect (301, 302, 307, 308)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if !strings.HasPrefix(strings.ToLower(location), "https://") {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"HTTP Does Not Redirect to HTTPS Securely",
				model.SeverityMedium,
				target.URL,
				"/",
				"The unencrypted HTTP service redirected to a non-HTTPS destination, exposing initial traffic to interception.",
				fmt.Sprintf("HTTP %d response redirected to Location: %s", resp.StatusCode, location),
				"Attackers performing Man-in-the-Middle (MitM) attacks can intercept plaintext credentials, tokens, or modify content.",
				"Ensure all HTTP traffic issues an immediate 301 Permanent Redirect to https://.",
				[]string{
					"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
				},
			))
		}
	} else if resp.StatusCode == 200 && !target.IsHTTPS {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Unencrypted HTTP Service Accessible Without Redirection",
			model.SeverityHigh,
			target.URL,
			"/",
			"The web application accepts unencrypted plaintext HTTP connections without enforcing a redirect to HTTPS.",
			fmt.Sprintf("HTTP %s returned status %d OK over plaintext HTTP.", httpURL, resp.StatusCode),
			"Cleartext communication allows network eavesdropping, session hijacking, and content tampering via MitM.",
			"Enforce strict HTTPS redirection and implement HTTP Strict Transport Security (HSTS).",
			[]string{
				"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
			},
		))
	}

	return findings
}

// checkSecurityHeaders checks presence and adequacy of key defensive headers.
func (s *HTTPScanner) checkSecurityHeaders(target *model.Target, resp *http.Response) []*model.Finding {
	var findings []*model.Finding
	h := resp.Header

	// 1. Strict-Transport-Security (HSTS) - relevant for HTTPS targets
	hsts := h.Get("Strict-Transport-Security")
	if target.IsHTTPS || strings.HasPrefix(target.URL, "https://") {
		if hsts == "" {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"Missing HTTP Strict Transport Security (HSTS) Header",
				model.SeverityMedium,
				target.URL,
				target.Path,
				"The response does not include the Strict-Transport-Security header.",
				"Strict-Transport-Security header is absent.",
				"Allows SSL-stripping attacks where an attacker downgrades user connections to plaintext HTTP.",
				"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
				[]string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
					"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts",
				},
			))
		} else {
			if !strings.Contains(strings.ToLower(hsts), "max-age") {
				findings = append(findings, model.NewFinding(
					s.Name(),
					"Malformed Strict-Transport-Security Header",
					model.SeverityLow,
					target.URL,
					target.Path,
					"The Strict-Transport-Security header exists but lacks a valid max-age directive.",
					fmt.Sprintf("Header value: %s", hsts),
					"Browsers may ignore an invalid HSTS directive, failing to enforce HTTPS.",
					"Specify a valid max-age directive (e.g., max-age=31536000).",
					[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
				))
			}
		}
	}

	// 2. Content-Security-Policy (CSP)
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Missing Content-Security-Policy (CSP) Header",
			model.SeverityMedium,
			target.URL,
			target.Path,
			"The response does not include a Content-Security-Policy header.",
			"Content-Security-Policy header is absent.",
			"Without CSP, the application lacks defense-in-depth protection against Cross-Site Scripting (XSS) and data injection attacks.",
			"Define and enforce a restrictive Content-Security-Policy header.",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
				"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
			},
		))
	} else {
		// Check for dangerous directives like 'unsafe-inline' or 'unsafe-eval'
		lowerCSP := strings.ToLower(csp)
		if strings.Contains(lowerCSP, "'unsafe-inline'") || strings.Contains(lowerCSP, "'unsafe-eval'") {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"Weak Content-Security-Policy Directives Detected",
				model.SeverityLow,
				target.URL,
				target.Path,
				"The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval' which weakens XSS protections.",
				fmt.Sprintf("CSP: %s", csp),
				"Attackers may execute injected scripts if input validation fails elsewhere.",
				"Refactor inline scripts to external scripts and use cryptographic nonces or hashes instead of 'unsafe-inline'.",
				[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"},
			))
		}
	}

	// 3. X-Frame-Options / frame-ancestors
	xfo := h.Get("X-Frame-Options")
	if xfo == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Missing Anti-Clickjacking Header (X-Frame-Options)",
			model.SeverityMedium,
			target.URL,
			target.Path,
			"Neither X-Frame-Options nor CSP 'frame-ancestors' directive is present.",
			"X-Frame-Options is absent and CSP frame-ancestors is not configured.",
			"The application can be embedded in an <iframe> on an attacker-controlled website, enabling Clickjacking attacks.",
			"Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or configure CSP 'frame-ancestors' directive.",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
				"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
			},
		))
	}

	// 4. X-Content-Type-Options
	xcto := h.Get("X-Content-Type-Options")
	if !strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Missing X-Content-Type-Options Header",
			model.SeverityLow,
			target.URL,
			target.Path,
			"The response is missing 'X-Content-Type-Options: nosniff'.",
			fmt.Sprintf("X-Content-Type-Options: %q", xcto),
			"Browsers may attempt MIME-type sniffing on responses, potentially interpreting non-executable types (like images or text) as executable HTML/JavaScript.",
			"Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
		))
	}

	// 5. Referrer-Policy
	rp := h.Get("Referrer-Policy")
	if rp == "" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Missing Referrer-Policy Header",
			model.SeverityLow,
			target.URL,
			target.Path,
			"The Referrer-Policy header is not configured on the response.",
			"Referrer-Policy header is absent.",
			"User browsing history, sensitive URL parameters, or tokens in query strings may leak to third-party domains via the Referer header.",
			"Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"},
		))
	}

	// 6. Permissions-Policy
	pp := h.Get("Permissions-Policy")
	if pp == "" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Missing Permissions-Policy Header",
			model.SeverityInfo,
			target.URL,
			target.Path,
			"The Permissions-Policy header is not defined.",
			"Permissions-Policy header is absent.",
			"The browser will allow standard web features (camera, microphone, geolocation) unless explicitly restricted.",
			"Define a Permissions-Policy header disabling unused browser APIs (e.g., 'camera=(), microphone=(), geolocation=()').",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"},
		))
	}

	// 7. Overly Permissive CORS (Access-Control-Allow-Origin: *)
	acao := h.Get("Access-Control-Allow-Origin")
	acac := h.Get("Access-Control-Allow-Credentials")
	if acao == "*" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Wildcard Cross-Origin Resource Sharing (CORS) Header",
			model.SeverityLow,
			target.URL,
			target.Path,
			"The server returns 'Access-Control-Allow-Origin: *', allowing any external domain to read responses.",
			fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acao, acac),
			"Any origin in the browser can execute cross-origin requests and read resources. If sensitive data is exposed on this endpoint, it is accessible to all sites.",
			"Specify explicit trusted origins instead of wildcard '*' for sensitive resources.",
			[]string{"https://portswigger.net/web-security/cors"},
		))
	}

	return findings
}

// checkCookies inspects cookie security flags (Secure, HttpOnly, SameSite).
func (s *HTTPScanner) checkCookies(target *model.Target, resp *http.Response) []*model.Finding {
	var findings []*model.Finding

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		// 1. Secure flag
		if target.IsHTTPS && !cookie.Secure {
			findings = append(findings, model.NewFinding(
				s.Name(),
				fmt.Sprintf("Cookie %q Missing 'Secure' Attribute", cookie.Name),
				model.SeverityMedium,
				target.URL,
				target.Path,
				fmt.Sprintf("The cookie %q was set over HTTPS without the Secure flag.", cookie.Name),
				fmt.Sprintf("Set-Cookie: %s=%s; Path=%s", cookie.Name, "[REDACTED]", cookie.Path),
				"The cookie can be transmitted over unencrypted HTTP connections, allowing network attackers to intercept it.",
				"Add the '; Secure' attribute to all cookies transmitted over HTTPS.",
				[]string{"https://owasp.org/www-community/controls/SecureFlag"},
			))
		}

		// 2. HttpOnly flag
		if !cookie.HttpOnly {
			// If cookie looks like a session/auth token
			isAuthToken := isPotentialAuthCookie(cookie.Name)
			sev := model.SeverityLow
			if isAuthToken {
				sev = model.SeverityMedium
			}
			findings = append(findings, model.NewFinding(
				s.Name(),
				fmt.Sprintf("Cookie %q Missing 'HttpOnly' Attribute", cookie.Name),
				sev,
				target.URL,
				target.Path,
				fmt.Sprintf("The cookie %q does not have the HttpOnly flag enabled.", cookie.Name),
				fmt.Sprintf("Set-Cookie: %s=%s; Path=%s", cookie.Name, "[REDACTED]", cookie.Path),
				"Client-side scripts (e.g., via XSS) can access the cookie value, increasing the risk of session hijacking.",
				"Add the '; HttpOnly' attribute to prevent JavaScript access to sensitive cookies.",
				[]string{"https://owasp.org/www-community/HttpOnly"},
			))
		}

		// 3. SameSite flag
		if cookie.SameSite == http.SameSiteDefaultMode {
			findings = append(findings, model.NewFinding(
				s.Name(),
				fmt.Sprintf("Cookie %q Missing 'SameSite' Attribute", cookie.Name),
				model.SeverityLow,
				target.URL,
				target.Path,
				fmt.Sprintf("The cookie %q does not explicitly define a SameSite policy (Lax, Strict, or None).", cookie.Name),
				fmt.Sprintf("Set-Cookie: %s=%s", cookie.Name, "[REDACTED]"),
				"Leaving SameSite undefined increases vulnerability to Cross-Site Request Forgery (CSRF) on older browsers.",
				"Explicitly configure '; SameSite=Lax' or '; SameSite=Strict' for the cookie.",
				[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"},
			))
		} else if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			findings = append(findings, model.NewFinding(
				s.Name(),
				fmt.Sprintf("Cookie %q Has SameSite=None Without Secure Attribute", cookie.Name),
				model.SeverityMedium,
				target.URL,
				target.Path,
				fmt.Sprintf("The cookie %q sets SameSite=None without the Secure attribute.", cookie.Name),
				fmt.Sprintf("Set-Cookie: %s=%s", cookie.Name, "[REDACTED]"),
				"Modern browsers reject SameSite=None cookies that lack the Secure attribute, causing unexpected session loss or insecure transmission.",
				"Ensure any cookie configured with SameSite=None also includes the Secure flag.",
				[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"},
			))
		}
	}

	return findings
}

// checkInfoDisclosure checks for detailed server banners, technology stack headers, and framework indicators.
func (s *HTTPScanner) checkInfoDisclosure(target *model.Target, resp *http.Response, body string) []*model.Finding {
	var findings []*model.Finding
	h := resp.Header

	// Check Server banner
	server := h.Get("Server")
	if server != "" {
		// Look for version numbers in server banner (e.g. Apache/2.4.41, nginx/1.18.0)
		hasVersion, _ := regexp.MatchString(`[0-9]+\.[0-9]+`, server)
		if hasVersion {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"Server Version Information Disclosure",
				model.SeverityLow,
				target.URL,
				target.Path,
				"The HTTP Server response header exposes exact software and version information.",
				fmt.Sprintf("Server: %s", server),
				"Attackers can use version information to search for known CVEs and tailored exploits for the exact server version.",
				"Configure the web server to suppress or tokenize the Server header (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx).",
				[]string{"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server"},
			))
		} else {
			findings = append(findings, model.NewFinding(
				s.Name(),
				"Server Banner Header Disclosed",
				model.SeverityInfo,
				target.URL,
				target.Path,
				"The HTTP Server header discloses the underlying server technology.",
				fmt.Sprintf("Server: %s", server),
				"Provides reconnaissance intelligence to external observers.",
				"Remove or generalize the Server header if not required.",
				[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"},
			))
		}
	}

	// Check X-Powered-By
	poweredBy := h.Get("X-Powered-By")
	if poweredBy != "" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Technology Stack Disclosure via X-Powered-By Header",
			model.SeverityLow,
			target.URL,
			target.Path,
			"The response includes an X-Powered-By header revealing backend frameworks or languages.",
			fmt.Sprintf("X-Powered-By: %s", poweredBy),
			"Reveals framework identities (e.g. Express, PHP, ASP.NET) helping adversaries target framework-specific vulnerabilities.",
			"Disable the X-Powered-By header in your application framework configuration (e.g. app.disable('x-powered-by') in Express, expose_php = Off in php.ini).",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		))
	}

	// Check X-AspNet-Version or X-AspNetMvc-Version
	aspnetVer := h.Get("X-AspNet-Version")
	if aspnetVer != "" {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"ASP.NET Version Disclosure",
			model.SeverityLow,
			target.URL,
			target.Path,
			"The server returns the X-AspNet-Version header exposing the .NET runtime version.",
			fmt.Sprintf("X-AspNet-Version: %s", aspnetVer),
			"Allows targeted exploits for ASP.NET framework bugs.",
			"Set <httpRuntime enableVersionHeader=\"false\" /> in web.config.",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		))
	}

	return findings
}

// checkHTTPMethods checks OPTIONS / TRACE methods.
func (s *HTTPScanner) checkHTTPMethods(ctx context.Context, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	// 1. Check TRACE method (Cross-Site Tracing)
	traceReq, err := http.NewRequestWithContext(ctx, "TRACE", target.URL, nil)
	if err == nil {
		traceReq.Header.Set("User-Agent", s.userAgent)
		traceReq.Header.Set("X-Pentol-Check", "test")
		traceResp, err := s.client.Do(traceReq)
		if err == nil {
			// Read body and close immediately — do NOT defer inside a non-loop function that closes early.
			bodyBytes, _ := io.ReadAll(io.LimitReader(traceResp.Body, 1024))
			traceResp.Body.Close()

			if traceResp.StatusCode == http.StatusOK && strings.Contains(string(bodyBytes), "X-Pentol-Check") {
				findings = append(findings, model.NewFinding(
					s.Name(),
					"HTTP TRACE / TRACK Method Enabled (XST Risk)",
					model.SeverityHigh,
					target.URL,
					"/",
					"The web server responds to HTTP TRACE requests by echoing request headers.",
					fmt.Sprintf("TRACE request returned HTTP %d echoing headers.", traceResp.StatusCode),
					"Can be leveraged in Cross-Site Tracing (XST) attacks to steal HttpOnly cookies and authorization tokens.",
					"Disable TRACE and TRACK methods on the web server (e.g., 'TraceEnable off' in Apache).",
					[]string{"https://owasp.org/www-community/attacks/Cross_Site_Tracing"},
				))
			}
		}
	}

	// 2. Check OPTIONS method to see allowed methods
	optionsReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, target.URL, nil)
	if err == nil {
		optionsReq.Header.Set("User-Agent", s.userAgent)
		optionsResp, err := s.client.Do(optionsReq)
		if err == nil {
			allow := optionsResp.Header.Get("Allow")
			optionsResp.Body.Close() // close immediately; headers already read

			if allow != "" {
				upperAllow := strings.ToUpper(allow)
				if strings.Contains(upperAllow, "PUT") || strings.Contains(upperAllow, "DELETE") {
					findings = append(findings, model.NewFinding(
						s.Name(),
						"Potentially Risky HTTP Methods Advertised in OPTIONS Allow Header",
						model.SeverityLow,
						target.URL,
						"/",
						"The server's Allow header advertises state-modifying methods (PUT, DELETE).",
						fmt.Sprintf("Allow: %s", allow),
						"If unauthenticated or misconfigured, arbitrary file modification or resource deletion may be possible.",
						"Verify that PUT and DELETE endpoints require strict authentication and authorization.",
						[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"},
					))
				}
			}
		}
	}

	return findings
}

// checkResponseBody inspects response body for directory listings or sensitive keywords.
func (s *HTTPScanner) checkResponseBody(target *model.Target, statusCode int, body string) []*model.Finding {
	var findings []*model.Finding

	lowerBody := strings.ToLower(body)

	// Check directory listing
	if strings.Contains(lowerBody, "<title>index of /") || strings.Contains(lowerBody, "<h1>index of /") || strings.Contains(lowerBody, "directory listing for /") {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Directory Listing Enabled",
			model.SeverityMedium,
			target.URL,
			target.Path,
			"The web server displays directory indexes allowing visitors to browse server directory contents.",
			"Response body contains directory index title ('Index of /').",
			"Exposes sensitive files, source code backups, hidden directories, and internal file paths to attackers.",
			"Disable directory browsing / indexing in web server configuration (e.g. 'Options -Indexes' in Apache, 'autoindex off;' in Nginx).",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Directory_Browsing"},
		))
	}

	return findings
}

func isPotentialAuthCookie(name string) bool {
	lower := strings.ToLower(name)
	authKeywords := []string{"session", "sess", "token", "jwt", "auth", "id", "sid", "connect.sid", "phpsessid", "jsessionid"}
	for _, kw := range authKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
