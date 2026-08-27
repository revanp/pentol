# Pentol — AI Coding Rules

> These rules govern AI-assisted development on the **Pentol** project (PENetration Testing tOOL).
> A safe-by-default, developer-friendly CLI security scanner written in Go.

---

## 🏗️ Project Architecture

```
pentol/
├── cmd/pentol/main.go          # CLI entry point (Cobra)
├── pkg/
│   ├── model/                  # Shared data models (Finding, Target, Scope, Severity, Status)
│   ├── engine/                 # Scan orchestration (config.go, engine.go)
│   ├── scanners/               # Scanner interface + implementations
│   │   ├── scanner.go          # Scanner interface
│   │   ├── http/               # HTTP security scanner
│   │   ├── tls/                # TLS/certificate scanner
│   │   └── recon/              # Reconnaissance scanner
│   └── report/                 # Output formatters (terminal, json, markdown, html)
├── tests/                      # Integration tests
└── docs/                       # Technical documentation
```

**Dependency direction**: `cmd` → `engine` → `scanners` → `model`. No circular imports. `report` depends on `model` only.

---

## 🔒 Core Principle: Safety First

Pentol is a **safe-by-default** tool. This is non-negotiable across all phases.

- **Never** introduce invasive payloads, brute-force logic, or destructive HTTP methods into any scanner.
- **Never** remove or weaken the rate-limiting logic in `pkg/engine/config.go` (default 150ms delay).
- **Never** bypass the scope enforcement in `pkg/model/scope.go` — it prevents scanning unauthorized hosts.
- All new scanners must be **passive** (V1 design) unless explicitly implementing a V2+ active scanner feature, and even then must respect rate limits and scope boundaries.
- Every new HTTP request made by a scanner must go through the engine's rate limiter.

---

## 📐 Go Code Style & Conventions

### General
- Target **Go 1.22+**. Use standard library idioms; avoid unnecessary third-party dependencies.
- Follow standard `gofmt` / `goimports` formatting. All code must format cleanly.
- Use `golangci-lint` conventions: no unused variables, no shadowed errors.

### Error Handling
- **Always** handle errors explicitly. Never use `_` to discard errors unless there is a documented reason in a comment.
- Wrap errors with context: `fmt.Errorf("context description: %w", err)`.
- Scanner `Run()` methods should return partial findings + a non-nil error when a sub-check fails, not abort entirely.

### Naming
- Exported types/functions use `PascalCase`. Unexported use `camelCase`.
- Scanner file names match the package: `http/http.go`, `tls/tls.go`, `recon/recon.go`.
- Test files use the `_test` package suffix for black-box tests: `package http_test`.

### Comments & Documentation
- All exported symbols (types, functions, constants) **must** have a GoDoc comment.
- Preserve all existing comments and docstrings unless they are directly related to code being changed.
- Non-obvious logic must have an inline comment explaining *why*, not just *what*.

---

## 🧩 The Finding Model (Immutable Schema)

Every scanner output **must** use the `model.NewFinding()` constructor and conform to the normalized `Finding` schema:

| Field         | Required | Notes                                                               |
|:--------------|:--------:|:--------------------------------------------------------------------|
| `ID`          | ✅       | Auto-generated via `model.GenerateFindingID()` — **never hardcode**|
| `Title`       | ✅       | Short, human-readable. Format: `Missing <Header> Header`            |
| `Severity`    | ✅       | Must be one of: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`        |
| `Target`      | ✅       | The full target URL/host                                            |
| `Endpoint`    | ✅       | The specific endpoint path (e.g., `/`, `/login`)                    |
| `Description` | ✅       | What was detected                                                   |
| `Evidence`    | ➖       | Raw data from the response (header value, cert detail, etc.)        |
| `Impact`      | ✅       | Why this matters to the developer                                   |
| `Remediation` | ✅       | Concrete, copy-paste-ready fix instruction                          |
| `References`  | ➖       | OWASP, MDN, RFC, or CVE links                                       |
| `Scanner`     | ✅       | Must match the scanner's `Name()` return value                      |

**Never** add new fields to `Finding` without updating all reporters (`terminal`, `json`, `markdown`, `html`) and the `Validate()` method.

---

## 🔍 Adding a New Scanner

When adding a new scanner (V2+), follow this checklist:

1. Create a new sub-package under `pkg/scanners/<name>/`.
2. Implement the `scanners.Scanner` interface (`Name()`, `Description()`, `Run()`).
3. The scanner **name** (from `Name()`) must be a lowercase, hyphenated string matching the package: e.g., `"active-web-scanner"`.
4. Register the scanner in `pkg/engine/engine.go`.
5. Add a corresponding `--<name>-only` CLI flag in `cmd/pentol/main.go`.
6. Write a dedicated unit test file in the same package: `pkg/scanners/<name>/<name>_test.go`.
7. Update `PENTOL_PHASES.md` to mark the feature as completed.
8. Update `docs/scanners.md` with a description of every check the scanner performs.

---

## 📊 Severity Assignment Guide

Use this table consistently across **all** scanners:

| Severity   | When to use                                                                      |
|:-----------|:---------------------------------------------------------------------------------|
| `CRITICAL` | Service is broken or immediately exploitable (e.g., expired cert, SSRF confirmed)|
| `HIGH`     | Actively exploitable weaknesses (e.g., deprecated TLS, TRACE method enabled)    |
| `MEDIUM`   | Standard security gap that should be remediated soon (e.g., missing CSP, HSTS) |
| `LOW`      | Hygiene/hardening issues (e.g., missing `X-Content-Type-Options`, version leak) |
| `INFO`     | Informational only — no vulnerability (e.g., DNS records, technology detected)  |

---

## 🧪 Testing Requirements

- **All new scanners** must have a unit test file with table-driven tests.
- **All new model types** must have validation tests.
- Use Go's `net/http/httptest` to mock HTTP servers in scanner unit tests — do **not** make real network calls in unit tests.
- Integration tests live in `tests/` and are allowed to use real network calls, but must be clearly documented.
- Run the full test suite before marking any task complete:
  ```bash
  go test -v ./...
  ```
- Tests must pass with zero failures on `go test -race ./...` (race detector enabled).

---

## 📝 Reporting Engine Rules

- All 4 reporters (`terminal`, `json`, `markdown`, `html`) must render **every** field in the `Finding` struct.
- The HTML reporter must remain a **standalone single file** (no external CDN dependencies). All CSS/JS must be inlined.
- The terminal reporter uses ANSI color codes for severity; ensure they degrade gracefully (no color leaks to file output).
- JSON output must be valid, minified JSON by default (pretty-print only on request).

---

## 🚀 Phase Discipline (No Premature Work)

- **V1 (COMPLETED)**: Do not refactor V1 code unless fixing a bug or a test failure.
- **V2 (PLANNED)**: Only begin V2 work when the user explicitly requests it. Do not pre-implement V2 features.
- **V3/V4 (PLANNED)**: Same rule — strict phase gating.
- When completing a phase feature, always update the checklist in `PENTOL_PHASES.md`.

---

## 📦 Dependency Management

- New dependencies require explicit user approval before being added to `go.mod`.
- Prefer Go standard library. The only current approved third-party dependency is `github.com/spf13/cobra`.
- Never add dependencies that require CGO — Pentol must cross-compile cleanly.

---

## 🗂️ File Naming & Package Conventions

| Location              | Package name       | Notes                                   |
|:----------------------|:-------------------|:----------------------------------------|
| `pkg/model/`          | `package model`    | No sub-packages inside model            |
| `pkg/engine/`         | `package engine`   | No sub-packages inside engine           |
| `pkg/scanners/`       | `package scanners` | Only the interface file lives here      |
| `pkg/scanners/<name>/`| `package <name>`   | One package per scanner                 |
| `pkg/report/`         | `package report`   | One file per format                     |
| `cmd/pentol/`         | `package main`     | Single `main.go` — keep it thin         |

---

## 🛑 Things to Never Do

- ❌ Never make real network requests in unit tests.
- ❌ Never hardcode a `Finding.ID` — always use `GenerateFindingID()`.
- ❌ Never disable or reduce the rate limiter without explicit user approval.
- ❌ Never add a scanner that scans hosts outside the configured scope.
- ❌ Never use `panic()` in production scanner or engine code — return errors instead.
- ❌ Never output ANSI codes when writing to a file reporter (json, markdown, html).
- ❌ Never merge V2+ code during an active V1 task context.
