# Changelog

All notable changes to **Pentol** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - Phase V1

### Added
- Initial project roadmap and architecture blueprint (`PENTOL_PHASES.md`).
- Core normalized finding model (`id`, `title`, `severity`, `target`, `endpoint`, `description`, `evidence`, `impact`, `remediation`, `references`, `scanner`, `status`).
- Safe execution engine with strict target validation and scope controls.
- HTTP security scanner (Headers, Cookies, HTTP methods, Redirects, Server disclosures).
- TLS security scanner (Certificate validity, Expiration, Protocol versions, Ciphers).
- Passive Reconnaissance scanner (DNS records, Service discovery, Technology fingerprinting, robots.txt, sitemap.xml).
- Multi-format reporting engine (Terminal, JSON, Markdown, HTML).
- Pentol CLI with `scan` and configuration flags.
