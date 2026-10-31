# Digital Life OS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A522.13-brightgreen.svg)](https://nodejs.org)
[![Version](https://img.shields.io/badge/version-0.1.0-informational.svg)](CHANGELOG.md)
<!-- CI badge — enable after pushing to GitHub:
[![CI](https://github.com/YOUR_USERNAME/digital-life-os/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/digital-life-os/actions/workflows/ci.yml)
-->

**A local-first, evidence-driven personal security companion.**

Know what you own · understand what is exposed · fix what matters · **verify the fix worked.**

Most security tools answer one question: *"What did this scan find?"*
Digital Life OS answers four connected questions:

1. **What do I have?** — a user-controlled inventory of your domains and projects
2. **What changed?** — new, recurring, resolved and regressed findings between scans
3. **What should I do first?** — transparent, explainable prioritization
4. **Did the fix work?** — every finding states *how to verify it*, and the next scan verifies it for you

The loop is the product:

```
Discover ──▶ Understand ──▶ Act & verify ──▶ Build history
```

Status: **MVP (CLI-first alpha)** — deterministic checks for domains. Desktop app, device
posture and personal mode come later ([roadmap](docs/product-spec.md)).

---

## What it checks (and how safely)

All checks are **passive, read-only and rate-limit-friendly** — no brute force, no
exploitation, no intrusive port scanning:

| Area | Checks |
| --- | --- |
| HTTPS | HTTP→HTTPS redirect, HTTPS reachability |
| TLS | certificate expiry, trust/hostname validation, protocol version |
| HTTP headers | HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| Email domain | SPF (presence, `all` qualifier, 10-lookup limit), DMARC (presence, `p=` policy), DKIM (only for selectors you configure) |
| DNS | record inventory (A/AAAA/MX/NS/TXT/CNAME), CAA policy |

Every finding carries a consistent structure: **observation, evidence, impact,
confidence, recommended action, verification, and history.** Checks that pass are shown
too — as verified evidence, not just a green tick. There is deliberately **no**
"security score of 82/100".

## Quickstart

Requires **Node.js ≥ 22.13** and pnpm (`corepack enable`).

```bash
pnpm install

# 1. Add a domain you own or are authorized to assess (--confirm is required on purpose)
pnpm dlos asset add example.com --confirm --group personal

# 2. Run the passive assessment
pnpm dlos scan example.com

# 3. See what to fix, ranked by transparent priority
pnpm dlos findings

# 4. Fix something, then re-scan — the finding flips to "resolved" with before/after evidence
pnpm dlos scan example.com

# 5. See what changed over time
pnpm dlos history example.com

# 6. Export machine-readable results
pnpm dlos report example.com --format json --out report.json
```

Everything is stored locally in SQLite (`~/.dlos/dlos.db` by default; override with
`--db <path>`). No account, no cloud, no telemetry.

## Commands

```
dlos asset add <domain> --confirm [--label] [--group] [--dkim-selector s]...
dlos asset list | show <domain> | remove <domain>
dlos scan [target] [--fail-on <severity>] [--timeout-ms n]
dlos findings [--status open,in_progress|all] [--min-severity s] [--asset d] [--json]
dlos finding show <id> [--json]
dlos finding status <id> <open|in_progress|accepted|resolved> [--note ...]
dlos history <domain> [--limit n] [--json]
dlos report <domain> [--format text|json] [--out file]
```

**Exit codes** (`scan` is CI-friendly): `0` = clean or below the threshold,
`1` = open findings at/above `--fail-on` (default `high`), `2` = operational error.
JSON output (`--json`, `--format json`) prints valid JSON and nothing else — logs go to stderr.

## Repository layout

```
digital-life-os/
├── apps/
│   └── cli/              # dlos — the terminal interface
├── packages/
│   ├── core/             # types, scan orchestration, change detection, risk ranking
│   ├── collectors/       # DNS, TLS, HTTP, email collectors (injectable network I/O)
│   ├── rules/            # deterministic rules + "verified" pass descriptions
│   ├── storage/          # SQLite (node:sqlite), migrations, cascade deletes
│   └── reports/          # JSON + human-readable rendering
├── docs/                 # architecture, rule format, security model, product spec
└── examples/             # sample reports
```

One shared engine, two future interfaces (CLI today, desktop later) — the CLI and the
desktop app will never be separate products.

## Development

```bash
pnpm install
pnpm typecheck   # strict TypeScript across the workspace
pnpm test        # 57 offline tests — no network required
pnpm build       # bundle the dlos CLI to apps/cli/dist
pnpm dlos        # run the CLI from source
```

The engine never touches the network in tests: collectors, fetch, DNS and the
clock are injected, and rules are exercised against JSON evidence fixtures.

## Contributing

Rules are pure functions over observations — no network, no randomness. The
highest-value contribution is a new rule with fixtures (including a
false-positive case). Start here:

- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, commit style, PR checklist
- Security issues: [SECURITY.md](SECURITY.md) (private disclosure, please)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

A rule looks like this (full guide in [docs/rule-format.md](docs/rule-format.md)):

```ts
export const hstsRule: Rule = {
  id: "header-hsts",
  consumes: ["http.headers"],
  evaluate(ctx) {
    // read observations, return FindingDraft[] with
    // observation / evidence / impact / confidence / recommendation / verification
  },
};
```

Every rule ships with JSON fixtures and tests (see `packages/rules/tests/fixtures/`).
Details: [docs/rule-format.md](docs/rule-format.md).

## Documentation

- [Roadmap](ROADMAP.md) — what shipped, what's next
- [Changelog](CHANGELOG.md) — every release, Keep-a-Changelog format
- [Architecture & data model](docs/architecture.md)
- [Rule format & finding schema](docs/rule-format.md)
- [Security & privacy model](docs/security-model.md)
- [Product spec](docs/product-spec.md)

## Known limitations (MVP)

- Domain/web checks only — device posture, account safety and personal mode are future phases
- DKIM is checked only when you provide selectors (they are unguessable by design)
- `~all`/`p=none` are flagged as informational/low — they are common staging policies, not emergencies
- Findings reflect configuration, not compromise: an "issue" is evidence of exposure, never proof of an attack

## License

MIT
