# Pentol Architecture

This document describes the structural architecture, component design, and data flow of **Pentol (PENetration Testing tOOL)**.

## Architecture Overview

Pentol is designed around a modular, orchestrator-driven engine that enforces strict safety constraints, executes pluggable scanners concurrently/safely, normalizes all findings into a unified model, and dispatches them through a multi-format reporting engine.

```text
               ┌───────────────────────────────┐
               │          Pentol CLI           │
               │   (Cobra / Arguments / Flags) │
               └──────────────┬────────────────┘
                              │
                              ▼
               ┌───────────────────────────────┐
               │          Orchestrator         │
               │  - Target Parser & Validator  │
               │  - Scope Enforcer & Safety    │
               │  - Rate Limiter & Concurrency │
               └──────────────┬────────────────┘
                              │
      ┌───────────────────────┼───────────────────────┐
      ▼                       ▼                       ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  HTTP Scanner│       │  TLS Scanner │       │ Recon Scanner│
│ - Headers    │       │ - Cert Chain │       │ - DNS Lookup │
│ - Cookies    │       │ - Expiry     │       │ - Fingerprint│
│ - Methods    │       │ - TLS 1.0-1.3│       │ - robots.txt │
│ - Disclosure │       │ - Ciphers    │       │ - sitemap.xml│
└──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       │                      │                      │
       └──────────────────────┼──────────────────────┘
                              │
                              ▼
               ┌───────────────────────────────┐
               │    Normalized Finding Engine  │
               │   - Standard Schema & IDs     │
               │   - Severity Calculation      │
               │   - Summary Metrics Aggregator│
               └──────────────┬────────────────┘
                              │
      ┌───────────────────────┼───────────────────────┬───────────────────────┐
      ▼                       ▼                       ▼                       ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Terminal   │       │     JSON     │       │   Markdown   │       │     HTML     │
│   Reporter   │       │   Reporter   │       │   Reporter   │       │   Reporter   │
└──────────────┘       └──────────────┘       └──────────────┘       └──────────────┘
```

## Core Modules

### 1. Model Layer (`pkg/model`)
- **`Target`**: Strict URL/host parser that normalizes scheme, hostname, port, and IP flags.
- **`ScopeConfig`**: Boundary engine determining whether candidate URLs or hostnames are authorized for testing.
- **`Finding`**: Standardized data model across all scanners:
  - `id`: Deterministic unique identifier (`PENTOL-<hash>`)
  - `title`: Concise finding title
  - `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - `target` & `endpoint`: Scope and URI context
  - `description`: Plain-language explanation
  - `evidence`: Raw HTTP responses, headers, or DNS records
  - `impact`: Security implications
  - `remediation`: Actionable developer fix instructions
  - `references`: Authoritative security links (OWASP, IETF, RFC, PortSwigger)
  - `scanner`: Originating module name
  - `status`: Lifecycle state (`OPEN`, `TRIAGED`, `FIXED`, `RETESTED`, `CLOSED`)
- **`ScanResult`**: Complete scan output aggregating findings, metadata, execution duration, and severity breakdown.

### 2. Engine Layer (`pkg/engine`)
- **`ScanConfig`**: Configurable settings controlling timeouts, rate limits, concurrency, user agents, and module toggles.
- **`Orchestrator`**: Coordinates execution lifecycle, manages progress callbacks, handles interrupt signals (`SIGINT`/`SIGTERM`), and ensures non-destructive safety guidelines.

### 3. Scanner Modules (`pkg/scanners`)
All scanners implement the common `Scanner` interface:
```go
type Scanner interface {
    Name() string
    Description() string
    Run(ctx context.Context, target *model.Target, scope *model.ScopeConfig) ([]*model.Finding, error)
}
```

### 4. Reporting Engine (`pkg/report`)
- **Terminal**: ANSI-colored findings with developer-friendly remediation cards.
- **JSON**: Machine-readable output for programmatic consumption and automation.
- **Markdown**: GFM-formatted security reports suitable for GitHub issues or Wiki documentation.
- **HTML**: Standalone, responsive dark-mode report with interactive styling.
