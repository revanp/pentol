# PENTOL Development Phases Roadmap

This document is the single source of truth for the development phases, current statuses, and feature progression of **Pentol (PENetration Testing tOOL)**.

---

## Phase V1 — Foundation & Passive/Low-Risk Assessment

* **Status**: COMPLETED
* **Goal**: Build the first usable Pentol CLI capable of performing structured, safe, passive and low-risk security assessments against explicitly authorized targets.

### Features
* **CLI & Orchestration**:
  * Target specification and strict target validation
  * Scope restrictions (allowed hosts/domains/subdomains, private IP disallow)
  * Conservative rate limiting and safe defaults
  * Verbose/debug mode & safe mode flags
  * Configurable output formats (`terminal`, `json`, `markdown`, `html`) and file exports
* **Normalized Finding Model**:
  * Unified schema (`id`, `title`, `severity`, `target`, `endpoint`, `description`, `evidence`, `impact`, `remediation`, `references`, `scanner`, `status`)
  * Standardized severities: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  * Standardized lifecycle: `OPEN`, `TRIAGED`, `FIXED`, `RETESTED`, `CLOSED`
* **HTTP Assessment Scanner**:
  * HTTPS availability & plaintext HTTP warnings
  * HTTP → HTTPS redirect verification
  * Security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS)
  * Cookie security attributes (`Secure`, `HttpOnly`, `SameSite`)
  * Dangerous HTTP methods check (`TRACE`, `OPTIONS Allow` with `PUT`/`DELETE`)
  * Server information disclosure (`Server` versions, `X-Powered-By`, `X-AspNet-Version`)
  * Response body analysis (Directory listing detection)
* **TLS Assessment Scanner**:
  * Certificate validity & chain validation (self-signed / untrusted CA detection)
  * Certificate expiration warnings & 30-day window alert
  * TLS protocol versions check (TLS 1.0, 1.1, 1.2, 1.3 deprecation detection)
  * Weak signature algorithm detection (MD5, SHA-1)
  * Subject Alternative Names (SANs) & hostname matching
* **Reconnaissance Scanner**:
  * DNS resolution & record lookup (A, AAAA, CNAME, MX, TXT/SPF, NS)
  * Basic domain information
  * Technology fingerprinting (React, Next.js, Vue, Nuxt, Angular, Laravel, WordPress, Drupal)
  * `robots.txt` discovery and sensitive path analysis (`/admin`, `/backup`, `/.env`, etc.)
  * `sitemap.xml` discovery and endpoint mapping
* **Reporting Engine**:
  * Developer-friendly Terminal output (formatted with ANSI severity colors & fix recommendations)
  * Machine-readable JSON report
  * Documentation-ready Markdown report
  * Standalone, responsive HTML report
* **Safety & Ethics**:
  * Explicit confirmation & target display before execution
  * Non-destructive, zero-exploit, no-brute-force design
  * Graceful interruption handling (`SIGINT`/`SIGTERM`)

### Completed
- [x] Pentol CLI runs successfully (`cmd/pentol`)
- [x] Target validation & parsing engine (`pkg/model/target.go`)
- [x] Scope restrictions & boundary controls (`pkg/model/scope.go`)
- [x] Safe defaults & rate limiting (`pkg/engine/config.go`, `pkg/engine/engine.go`)
- [x] HTTP security scanner (`pkg/scanners/http/http.go`)
- [x] TLS security scanner (`pkg/scanners/tls/tls.go`)
- [x] Basic recon scanner (`pkg/scanners/recon/recon.go`)
- [x] Normalized finding model & deterministic IDs (`pkg/model/finding.go`)
- [x] Severity & status lifecycle models (`pkg/model/severity.go`, `pkg/model/status.go`)
- [x] Terminal reporter (`pkg/report/terminal.go`)
- [x] JSON reporter (`pkg/report/json.go`)
- [x] Markdown reporter (`pkg/report/markdown.go`)
- [x] HTML reporter (`pkg/report/html.go`)
- [x] Unit test suites (`pkg/model`, `pkg/scanners/http`, `pkg/scanners/tls`, `pkg/scanners/recon`, `pkg/report`)
- [x] Integration test suites (`tests/integration_test.go`)
- [x] Comprehensive documentation (`README.md`, `CHANGELOG.md`, `docs/architecture.md`, `docs/safety.md`, `docs/scanners.md`)
- [x] Future phase roadmap established without premature V2+ bleeding

### In Progress
- None (Phase V1 complete).

### Deferred
- None for V1 scope.

### Dependencies
- Go 1.22+ standard library & Cobra CLI framework.

### Notes
- All V1 acceptance criteria are satisfied. Ready for Phase V2 planning when requested.

---

## Phase V2 — Active Web & API Security Testing

* **Status**: PLANNED
* **Goal**: Move from passive assessment into controlled active security testing with OpenAPI integration and authentication support.

### Features
* Scope-aware, rate-limited active web application testing (XSS, SQLi indicators, Path Traversal, SSRF indicators, Command injection, SSTI, CORS misconfiguration, File upload validation, Parameter pollution)
* OpenAPI / Swagger API Security scanning (`pentol api scan swagger.json`)
* Authenticated scanning with session management
* Multi-user authorization & privilege escalation testing (BOLA / IDOR)

### Completed
- None (Phase V2 will commence following user request).

### In Progress
- None

### Deferred
- None

### Dependencies
- Phase V1 normalized finding engine and orchestrator.

### Notes
- Strictly planned; no code written ahead of phase transition.

---

## Phase V3 — White Box, DevSecOps & Infrastructure Security

* **Status**: PLANNED
* **Goal**: Turn Pentol into a comprehensive developer-oriented security assessment platform covering SAST, dependencies, secrets, Docker, and Kubernetes.

### Features
* Multi-language SAST (JS/TS, PHP, Python, Rust, Go)
* Dependency vulnerability scanning across lockfiles
* Secret scanning in code, configs, and git history
* Dockerfile and Compose security auditing
* Kubernetes manifest & Helm chart security auditing
* SARIF & CI/CD pipeline integration (GitHub Actions, Jenkins)

### Completed
- None

### In Progress
- None

### Deferred
- None

### Dependencies
- Phase V1 & Phase V2 architecture.

### Notes
- Will leverage standard SARIF export for CI/CD gating.

---

## Phase V4 — Security Platform & Continuous Pentesting

* **Status**: PLANNED
* **Goal**: Expand Pentol into a persistent security platform with dashboards, continuous scanning, regression testing, finding deduplication, and plugin ecosystem.

### Features
* Interactive Security Dashboard & score calculation
* CI/CD threshold gating policies
* Scheduled & continuous pentest workflows
* Finding intelligence, deduplication, and lifecycle tracking
* Project workspaces (targets, credentials, profiles, findings)
* Plugin architecture for community & custom scanners

### Completed
- None

### In Progress
- None

### Deferred
- None

### Dependencies
- Phases V1, V2, and V3.

### Notes
- Platform features will build upon the standardized finding and orchestration layers.
