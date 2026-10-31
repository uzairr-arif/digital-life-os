# Roadmap

The product promise: **know what you own, understand what is exposed, fix what
matters, and see your security improve over time.**

Every phase below strengthens the same closed loop (discover → understand →
act & verify → history) rather than adding a disconnected tool.

## ✅ Shipped

### v0.1.0 — 2026-10-31 · the core loop, CLI-first

- Asset registry with explicit scope confirmation
- Passive collectors: DNS/CAA, HTTPS redirect & reachability, TLS certificate
  health, security headers, SPF/DMARC/DKIM
- 16 deterministic, evidence-first rules with verification steps
- Change detection: new / recurring / resolved / regressed + event history
- Transparent prioritization (no opaque score)
- Local SQLite storage, JSON + human reports, CI-friendly CLI exit codes

## 🎯 Next — v0.2 · daily usefulness

Goal: make `dlos` something you run every week, not once.

- **Scheduled rechecks** — `dlos scan --watch` plus OS-scheduler guidance
  (cron/Task Manager), storing a scan trail automatically
- **Change notifications** — new/regressed findings surfaced without re-reading
  reports (log digest, webhook; desktop notification comes with the app)
- **More deterministic rules** — candidates: `security.txt` presence, DNSSEC,
  cookie flags (Secure/HttpOnly — counted, never valued), wildcard certificate
  detection, MX↔SPF consistency
- **HTML report export** — single self-contained file, still no upload
- Rule-authoring ergonomics: rule test scaffolding generator

## 🔭 Later — v0.3 · desktop experience

- Desktop app (Electron, sandboxed renderer, narrow validated bridge) on the
  **same shared engine** — the CLI stays first-class
- Asset relationship graph, only after the data model has proven dependable
- Project profiles for web developers

## 💭 Exploring (no commitment)

- Device posture collectors (OS version, firewall, disk encryption) —
  platform-specific and explicitly scoped
- Browser extension for explaining the current page's signals
- Plugin architecture for community collectors/rules
- Optional self-hosted monitoring for people who want it

## Versioning

[Semantic Versioning](https://semver.org). During 0.x, minor versions may
contain breaking changes — every breaking change is called out at the top of
the release notes in [CHANGELOG.md](CHANGELOG.md).
