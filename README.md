# 🛡️ Pentol (PENetration Testing tOOL)

> **⚡ TL;DR:** A safe-by-default, zero-fuss security scanner built for developers. Point it at your app/staging URL, and get a clear, prioritized list of security issues with copy-paste remediation steps.

```text
  ██████╗ ███████╗███╗   ██╗████████╗ ██████╗ ██╗     
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██║     
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║     
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║     
  ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝███████╗
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝
```

---

## ⚡ 10-Second Quickstart

```bash
# 1. Build binary
go build -o bin/pentol ./cmd/pentol

# 2. Run a scan against your staging URL
./bin/pentol scan https://staging.example.com

# 3. Export to a beautiful dark-mode HTML report
./bin/pentol scan https://staging.example.com --format html --output report.html
```

---

## 🎯 What Does Pentol V1 Check?

No exploits, no brute force, no server crashing. Only safe, passive checks:

| Scanner | What it inspects | Why you care |
| :--- | :--- | :--- |
| 🌐 **HTTP Scanner** | Missing security headers (HSTS, CSP, X-Frame-Options, CORS), cookie flags (`Secure`, `HttpOnly`, `SameSite`), dangerous HTTP methods (`TRACE`, `PUT`), server version leaks. | Prevents XSS, Clickjacking, Cookie theft, and Session hijacking. |
| 🔒 **TLS Scanner** | Certificate expiration, untrusted CA/self-signed certs, domain mismatch (SAN), deprecated protocols (TLS 1.0 & 1.1), weak crypto. | Prevents MitM attacks, browser red-screen warnings, and expired cert outages. |
| 🔍 **Recon Scanner** | DNS records (A, CNAME, MX, TXT/SPF, NS), web frameworks (Next.js, React, Vue, Laravel, WordPress), `robots.txt` secret paths, `sitemap.xml`. | Shows you exactly what attackers see during preliminary reconnaissance. |

---

## 📋 Copy-Paste Command Cheat Sheet

```bash
# 🚀 Standard terminal scan
./bin/pentol scan https://staging.example.com

# 📄 Save as Dark-Mode HTML Report (Open in browser!)
./bin/pentol scan https://staging.example.com -f html -o audit-report.html

# 📝 Save as Markdown (Ready for GitHub issues or PRs)
./bin/pentol scan https://staging.example.com -f markdown -o audit.md

# 🤖 Save as JSON (For CI/CD or scripts)
./bin/pentol scan https://staging.example.com -f json -o findings.json

# 🌐 Allow scanning subdomains (e.g. *.example.com)
./bin/pentol scan https://example.com --allow-subdomains

# 🚫 Exclude sensitive hosts & block private IP ranges
./bin/pentol scan https://example.com --exclude prod.example.com --disallow-private

# 🏃 Run only specific scanners
./bin/pentol scan https://staging.example.com --http-only
./bin/pentol scan https://staging.example.com --tls-only
./bin/pentol scan https://staging.example.com --recon-only
```

---

## 🚦 Severity Levels at a Glance

Every finding tells you: **What happened**, **Why it's bad**, and **How to fix it**.

* 🔴 **CRITICAL** — Fix immediately (e.g., Expired TLS certificate, server broken).
* 🟠 **HIGH** — High-priority risk (e.g., Deprecated TLS 1.0 enabled, TRACE method active).
* 🟡 **MEDIUM** — Standard security gap (e.g., Missing HSTS, Missing CSP, Missing Anti-Clickjacking).
* 🔵 **LOW** — Hygiene issue (e.g., Missing `X-Content-Type-Options`, Server version disclosure).
* ⚪ **INFO** — Informational reconnaissance (e.g., Discovered `robots.txt`, Web framework fingerprinted).

---

## 🧩 Anatomy of a Pentol Finding

You get clean, structured findings without security jargon overwhelm:

```yaml
[1] 🟡 MEDIUM Missing Content-Security-Policy (CSP) Header (PENTOL-e1d2c3)
    Endpoint:    /
    Scanner:     http-scanner
    Description: The response does not include a Content-Security-Policy header.
    Impact:      Lacks defense-in-depth protection against XSS and data injection attacks.
    Fix:         Define and enforce a restrictive Content-Security-Policy header.
    References:  https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
```

---

## 🛡️ Safety & Guardrails (Built-in)

* ✅ **Safe-by-Default**: Passive inspection only in V1 (zero invasive payloads).
* ✅ **Rate Limited**: Default 150ms delay between requests to prevent accidental DoS.
* ✅ **Explicit Scope**: Never scans out-of-scope third-party hosts.
* ✅ **Target Confirmation**: Always displays target and scope details before running.

---

## 🧭 Project Roadmap (Phases)

| Phase | Focus | Status |
| :--- | :--- | :--- |
| **Phase V1** | **Foundation & Passive Assessment** (CLI, HTTP, TLS, Recon, Multi-format Reports) | 🟢 **COMPLETED** |
| **Phase V2** | **Active Web & API Testing** (XSS/SQLi checks, OpenAPI/Swagger scan, Auth & BOLA/IDOR) | 🟡 **PLANNED** |
| **Phase V3** | **DevSecOps & SAST** (Source code SAST, Lockfile dependencies, Secret scanning, Docker/K8s) | ⚪ **PLANNED** |
| **Phase V4** | **Security Platform** (Web Dashboard, CI/CD Gate Policies, Continuous Scans) | ⚪ **PLANNED** |

See [`PENTOL_PHASES.md`](PENTOL_PHASES.md) for full phase specifications and history.

---

## 🧪 Run Tests

```bash
# Run all tests (fast, pure Go, zero dependencies)
go test -v ./...
```

---

<details>
<summary><strong>📖 Detailed Technical Documentation Links (Click to expand)</strong></summary>

* [Architecture & System Flow](docs/architecture.md)
* [Safety & Ethical Model](docs/safety.md)
* [Scanners Reference Guide](docs/scanners.md)
* [Full Changelog](CHANGELOG.md)

</details>

---

<p align="center">
  <sub>Built with ❤️ for developers who want clear, fast security without the headache.</sub>
</p>
