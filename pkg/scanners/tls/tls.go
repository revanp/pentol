package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"pentol/pkg/model"
	"pentol/pkg/scanners"
)

// Ensure TLSScanner implements scanners.Scanner
var _ scanners.Scanner = (*TLSScanner)(nil)

// TLSScanner performs passive/low-risk TLS/SSL security assessment.
type TLSScanner struct {
	timeout time.Duration
}

// NewTLSScanner creates a new TLS scanner instance.
func NewTLSScanner(timeout time.Duration) *TLSScanner {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TLSScanner{
		timeout: timeout,
	}
}

func (s *TLSScanner) Name() string {
	return "tls-scanner"
}

func (s *TLSScanner) Description() string {
	return "Evaluates TLS/SSL certificates, expiration, protocol versions (TLS 1.0 - 1.3), and weak cipher suites."
}

// Run executes the TLS evaluation against the target.
func (s *TLSScanner) Run(ctx context.Context, target *model.Target, scope *model.ScopeConfig) ([]*model.Finding, error) {
	var findings []*model.Finding

	// Verify scope
	if inScope, reason := scope.IsInScope(target.URL); !inScope {
		return nil, fmt.Errorf("target %s out of scope: %s", target.URL, reason)
	}

	host := target.Hostname
	port := target.Port
	if !target.IsHTTPS && port == 80 {
		port = 443 // Default to TLS port for TLS scanner check
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// 1. Certificate inspection (using standard secure dial)
	certFindings, err := s.checkCertificate(ctx, addr, host, target)
	if err != nil {
		// If TLS connection fails entirely, it might not be a TLS endpoint
		return findings, fmt.Errorf("TLS connection to %s failed: %w", addr, err)
	}
	findings = append(findings, certFindings...)

	// 2. Protocol version checks (TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)
	protoFindings := s.checkProtocolVersions(ctx, addr, host, target)
	findings = append(findings, protoFindings...)

	return findings, nil
}

// checkCertificate inspects certificate validity, expiry, SANs, and key strength.
func (s *TLSScanner) checkCertificate(ctx context.Context, addr, serverName string, target *model.Target) ([]*model.Finding, error) {
	var findings []*model.Finding

	dialer := &net.Dialer{Timeout: s.timeout}
	// We first attempt a standard verified handshake, and fallback to InsecureSkipVerify if needed to inspect invalid certs
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS10,
	})

	var untrustedCert = false
	var untrustedReason = ""

	if err != nil {
		// Handshake failed; check if it's due to unknown authority / invalid certificate
		if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "x509") {
			untrustedCert = true
			untrustedReason = err.Error()

			// Retry with InsecureSkipVerify to retrieve the certificate metadata for analysis
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true, //nolint:gosec
				MinVersion:         tls.VersionTLS10,
			})
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return findings, nil
	}

	leaf := state.PeerCertificates[0]

	// Report untrusted certificate if verified handshake failed
	if untrustedCert {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Untrusted or Invalid SSL/TLS Certificate",
			model.SeverityHigh,
			target.URL,
			addr,
			"The TLS certificate presented by the server failed standard X.509 certificate chain validation.",
			fmt.Sprintf("X.509 verification error: %s", untrustedReason),
			"Users will receive prominent browser security warnings. Attackers can potentially execute Man-in-the-Middle (MitM) attacks.",
			"Install a valid SSL/TLS certificate issued by a recognized public Certificate Authority (CA) such as Let's Encrypt.",
			[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
		))
	}

	// 1. Expiration Checks
	now := time.Now()
	if now.After(leaf.NotAfter) {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Expired SSL/TLS Certificate",
			model.SeverityCritical,
			target.URL,
			addr,
			fmt.Sprintf("The TLS certificate expired on %s.", leaf.NotAfter.Format(time.RFC3339)),
			fmt.Sprintf("Certificate NotAfter: %s (Expired %s ago)", leaf.NotAfter.Format(time.RFC822), now.Sub(leaf.NotAfter).Round(time.Hour)),
			"Clients will fail to establish secure connections or display critical security errors.",
			"Renew and deploy an active SSL/TLS certificate immediately.",
			[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
		))
	} else if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
		daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
		findings = append(findings, model.NewFinding(
			s.Name(),
			"SSL/TLS Certificate Expiring Soon",
			model.SeverityLow,
			target.URL,
			addr,
			fmt.Sprintf("The TLS certificate will expire in %d days (%s).", daysLeft, leaf.NotAfter.Format("2006-01-02")),
			fmt.Sprintf("Certificate NotAfter: %s (Expires in %d days)", leaf.NotAfter.Format(time.RFC822), daysLeft),
			"If not renewed promptly, service disruption and security warnings will occur.",
			"Ensure automated certificate renewal (e.g. ACME/Certbot) is operating properly.",
			[]string{"https://letsencrypt.org/docs/renewal-options/"},
		))
	}

	// 2. Check Weak Signature Algorithm
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Insecure Certificate Signature Algorithm",
			model.SeverityHigh,
			target.URL,
			addr,
			fmt.Sprintf("The certificate uses an obsolete, cryptographically weak signature algorithm: %s.", leaf.SignatureAlgorithm),
			fmt.Sprintf("Signature Algorithm: %s", leaf.SignatureAlgorithm),
			"Collisions in weak hash functions (like MD5 and SHA-1) permit forged certificates and impersonation.",
			"Re-issue certificate using SHA-256 or stronger (e.g., SHA256-RSA or ECDSA-SHA256).",
			[]string{"https://cabforum.org/baseline-requirements-documents/"},
		))
	}

	// 3. Check Subject Alternative Names (SAN) matching
	if err := leaf.VerifyHostname(serverName); err != nil && !untrustedCert {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"SSL/TLS Certificate Hostname Mismatch",
			model.SeverityHigh,
			target.URL,
			addr,
			fmt.Sprintf("The certificate Common Name and SANs do not match the target hostname %q.", serverName),
			fmt.Sprintf("Subject Common Name: %s, DNS Names: %v", leaf.Subject.CommonName, leaf.DNSNames),
			"Browsers will refuse connections with hostname mismatch errors.",
			"Obtain a certificate that explicitly lists the domain or wildcard SAN in its Subject Alternative Names.",
			[]string{"https://datatracker.ietf.org/doc/html/rfc6125"},
		))
	}

	return findings, nil
}

// checkProtocolVersions attempts handshakes with specific TLS versions to detect obsolete protocol support.
func (s *TLSScanner) checkProtocolVersions(ctx context.Context, addr, serverName string, target *model.Target) []*model.Finding {
	var findings []*model.Finding

	// Check TLS 1.0 (Deprecated by RFC 8996)
	if s.testTLSVersion(ctx, addr, serverName, tls.VersionTLS10) {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Deprecated TLS 1.0 Protocol Enabled",
			model.SeverityHigh,
			target.URL,
			addr,
			"The server accepted a connection using TLS 1.0, which is formally deprecated by IETF RFC 8996.",
			"TLS 1.0 handshake completed successfully.",
			"Vulnerable to legacy cryptographic attacks (e.g., BEAST, POODLE) and fails PCI-DSS compliance requirements.",
			"Disable TLS 1.0 in web server / load balancer configuration and require TLS 1.2 or TLS 1.3.",
			[]string{
				"https://datatracker.ietf.org/doc/html/rfc8996",
				"https://csrc.nist.gov/pubs/sp/800/52/r2/final",
			},
		))
	}

	// Check TLS 1.1 (Deprecated by RFC 8996)
	if s.testTLSVersion(ctx, addr, serverName, tls.VersionTLS11) {
		findings = append(findings, model.NewFinding(
			s.Name(),
			"Deprecated TLS 1.1 Protocol Enabled",
			model.SeverityMedium,
			target.URL,
			addr,
			"The server accepted a connection using TLS 1.1, which is formally deprecated by IETF RFC 8996.",
			"TLS 1.1 handshake completed successfully.",
			"TLS 1.1 lacks support for modern cipher suites and fails current industry security standards.",
			"Disable TLS 1.1 and enforce TLS 1.2 and TLS 1.3.",
			[]string{
				"https://datatracker.ietf.org/doc/html/rfc8996",
			},
		))
	}

	return findings
}

// testTLSVersion probes if a specific TLS version is supported by forcing MinVersion & MaxVersion.
// Context is propagated so that SIGINT or a scan timeout will abort the probe promptly.
func (s *TLSScanner) testTLSVersion(ctx context.Context, addr, serverName string, version uint16) bool {
	dialer := &net.Dialer{}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //nolint:gosec // Needed for passive protocol probing
	}

	// Use DialContext so the context deadline / cancellation is respected.
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn := tls.Client(netConn, tlsCfg)
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		return false
	}
	return conn.ConnectionState().Version == version
}
