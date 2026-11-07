# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-07

The daily-usefulness release: dlos now keeps watching after the first scan.

### Added

- **`dlos watch`** — re-scan every active asset on a schedule (`--every 30m|6h|1d`),
  notify on notable changes via `--webhook`, filter with `--min-severity`, or run a
  single pass with `--once` under cron/Task Scheduler.
- **Change digest core** — only genuinely *new* or *regressed* findings notify;
  recurring findings never nag. Webhook payloads are structured JSON.
- **security.txt rule (RFC 9116)** — missing file (info), file without a required
  `Contact` field (low), and a "verified" pass for a complete file.
- **Cookie security-flag rules** — cookies lacking `Secure` or `HttpOnly` (low) or
  `SameSite` (info). Only flag *presence* is recorded; cookie names, values and
  domains are never stored.
- New collector: `webmeta` (security.txt lookup with the RFC's `.well-known` +
  root-path fallback).
- Launch videos (dark + light themes) for the project page and socials.

### Fixed

- Cleared all 18 Dependabot alerts (vitest 5.0.5, vite 6.4.5 via override, tsup 9,
  esbuild 0.25.12/0.28.2, @types/node 26); `pnpm audit` is clean.

## [0.1.0] - 2026-10-31

First release of the CLI-first MVP: a local-first, evidence-driven personal
security companion. One closed loop — know what you own, understand what is
exposed, fix what matters, verify the fix.

### Added

- **Asset registry** with explicit ownership/authorization confirmation
  (`dlos asset add <domain> --confirm`); nothing is scanned without scope consent.
- **Passive collectors** (no brute force, no exploitation, no port scanning):
  DNS record inventory (A/AAAA/MX/NS/TXT/CNAME/CAA), HTTP→HTTPS redirect,
  HTTPS reachability, TLS certificate health (expiry, trust, hostname match,
  protocol version), HTTP security headers (whitelist-captured — cookie values
  are never stored, only counted), SPF, DMARC and DKIM (opt-in, selector-based).
- **16 deterministic rules** producing evidence-first findings: observation,
  raw evidence, impact, confidence, recommended action, and verification steps.
- **Change detection across scans** — findings are fingerprinted and classified
  as new / recurring / resolved / regressed, with an append-only event history
  per finding. Re-scanning is the fix-verification mechanism.
- **Transparent prioritization** — `severity × confidence × actionability`,
  hand-checkable by design; no opaque security score anywhere.
- **`dlos` CLI** — `asset add/list/show/remove`, `scan [--fail-on] [--timeout-ms]`,
  `findings`, `finding show/status`, `history`, `report [--format text|json]`.
  Meaningful exit codes for CI; JSON output is valid JSON and nothing else.
- **Local-first storage** — SQLite via Node's built-in `node:sqlite` (zero
  native dependencies), versioned migrations, cascade deletes, WAL mode.
- **Test suite** — 57 offline tests driven by JSON evidence fixtures,
  including false-positive guards (lookup errors and timeouts never become
  "missing X" findings); engine lifecycle test on real temporary databases.
- **CI** — typecheck, tests and build on Node 22/24 across Ubuntu and Windows.
- **Documentation** — architecture & data model, rule format guide,
  security & privacy model, and product spec/roadmap.

[0.2.0]: https://github.com/uzairr-arif/digital-life-os/releases/tag/v0.2.0
[0.1.0]: https://github.com/uzairr-arif/digital-life-os/releases/tag/v0.1.0
