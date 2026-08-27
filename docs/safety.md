# Pentol Safety & Ethical Security Model

Security tooling must be safe, transparent, and non-destructive by default. Pentol is engineered to assist developers and security professionals in assessing systems they own or are explicitly authorized to test.

## Safety Principles

### 1. Explicit Target Confirmation
- Pentol requires an explicit target argument.
- Before executing any network requests, Pentol displays the full parsed target URL, hostname, port, allowed scope list, rate limit parameters, and safety mode status.

### 2. Scope Boundaries & Restrictions
- Scans are restricted to the specified target host by default.
- External hosts, unauthorized third-party domains, and CDN endpoints encountered during discovery are ignored unless explicitly allowed via `--allowed-hosts` or `--allow-subdomains`.
- The `--exclude` flag enables exclusion of critical production subdomains.
- The `--disallow-private` flag prevents accidental or unauthorized scans against internal IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`).

### 3. Safe-by-Default Rate Limiting
- To avoid Denial of Service (DoS) or unexpected load on staging/production environments, Pentol includes default delays between requests (`--rate-limit`, default 150ms).
- Max concurrency is strictly limited during passive scans.

### 4. Non-Destructive Passive Operations
- Phase V1 performs **only passive and low-risk checks**:
  - Examining response headers
  - Inspecting TLS certificate chains and protocol negotiations
  - Reviewing public metadata files (`robots.txt`, `sitemap.xml`)
  - Querying standard DNS records
- Pentol does not perform payload fuzzing, brute force attacks, SQL injection attempts, or exploitative state mutations in Phase V1.
