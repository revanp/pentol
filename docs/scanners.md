# Pentol Scanners Reference (Phase V1)

Pentol Phase V1 includes three specialized assessment engines.

---

## 1. HTTP Security Scanner (`http-scanner`)

The HTTP Scanner analyzes communication channel protections, header configurations, cookie security, and response attributes.

| Check | Severity | Description |
| :--- | :--- | :--- |
| **HTTPS Redirection** | `MEDIUM` / `HIGH` | Checks if unencrypted HTTP traffic immediately redirects to secure HTTPS (`301 Moved Permanently`). |
| **HSTS Header** | `MEDIUM` | Verifies presence and valid `max-age` in `Strict-Transport-Security`. |
| **Content-Security-Policy (CSP)** | `MEDIUM` / `LOW` | Verifies presence of CSP and detects unsafe directives (`'unsafe-inline'`, `'unsafe-eval'`). |
| **Anti-Clickjacking (X-Frame-Options)** | `MEDIUM` | Checks for `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors`. |
| **MIME Sniffing (X-Content-Type-Options)** | `LOW` | Verifies `X-Content-Type-Options: nosniff`. |
| **Referrer-Policy** | `LOW` | Verifies presence of safe referrer policies. |
| **Permissions-Policy** | `INFO` | Checks if browser feature access (camera, microphone, geolocation) is restricted. |
| **Wildcard CORS** | `LOW` | Detects `Access-Control-Allow-Origin: *` headers. |
| **Cookie `Secure` Attribute** | `MEDIUM` | Flags cookies set over HTTPS without the `Secure` flag. |
| **Cookie `HttpOnly` Attribute** | `LOW` / `MEDIUM` | Flags session cookies lacking `HttpOnly`. |
| **Cookie `SameSite` Attribute** | `LOW` / `MEDIUM` | Checks for missing `SameSite` or `SameSite=None` without `Secure`. |
| **Server & Tech Disclosure** | `INFO` / `LOW` | Detects version leakage in `Server`, `X-Powered-By`, `X-AspNet-Version`. |
| **Dangerous HTTP Methods** | `LOW` / `HIGH` | Probes for `TRACE` (XST risk) and risky `OPTIONS Allow` methods (`PUT`, `DELETE`). |
| **Directory Listing** | `MEDIUM` | Scans response body for open directory index listings. |

---

## 2. TLS/SSL Security Scanner (`tls-scanner`)

The TLS Scanner evaluates cryptographic hygiene and certificate validity.

| Check | Severity | Description |
| :--- | :--- | :--- |
| **Untrusted Certificate** | `HIGH` | Evaluates X.509 certificate chain trust and self-signed certificates. |
| **Expired Certificate** | `CRITICAL` | Detects expired certificates. |
| **Expiring Soon** | `LOW` | Warns if certificate expiration is within 30 days. |
| **Hostname Mismatch** | `HIGH` | Matches target hostname against Subject Common Name and SANs (Subject Alternative Names). |
| **Weak Signature Algorithms** | `HIGH` | Identifies deprecated signature algorithms (MD5, SHA-1). |
| **Deprecated TLS 1.0** | `HIGH` | Detects support for TLS 1.0 (deprecated by RFC 8996). |
| **Deprecated TLS 1.1** | `MEDIUM` | Detects support for TLS 1.1 (deprecated by RFC 8996). |

---

## 3. Passive Reconnaissance Scanner (`recon-scanner`)

The Recon Scanner maps DNS records, technology stacks, and metadata files.

| Check | Severity | Description |
| :--- | :--- | :--- |
| **DNS Infrastructure** | `INFO` | Resolves A, AAAA, CNAME, MX, TXT, and NS records. |
| **Missing SPF Record** | `LOW` | Warns if domain lacks a `v=spf1` TXT record for email security. |
| **`robots.txt` Discovery** | `INFO` | Parses `robots.txt` file at target root. |
| **Sensitive Disallow Paths** | `LOW` | Extracts administrative, internal, or backup paths listed under `Disallow:`. |
| **`sitemap.xml` Discovery** | `INFO` | Discovers published `sitemap.xml` and counts indexed endpoints. |
| **Technology Fingerprinting** | `INFO` | Identifies web frameworks and CMS platforms (React, Next.js, Vue, Angular, Laravel, WordPress, Drupal). |
