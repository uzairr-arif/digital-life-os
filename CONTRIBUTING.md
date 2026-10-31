# Contributing to Digital Life OS

Thank you for considering a contribution. This project is early and deliberate:
a security tool earns trust through precision, so correctness beats feature
count here.

## Development setup

Prerequisites: **Node.js ≥ 22.13** and **pnpm** (via `corepack enable`).

```bash
git clone https://github.com/YOUR_USERNAME/digital-life-os.git
cd digital-life-os
pnpm install

pnpm typecheck   # strict TypeScript across the workspace
pnpm test        # vitest — everything runs offline
pnpm build       # bundles the dlos CLI
pnpm dlos --help # run the CLI from source
```

The engine never touches the network in tests — collectors, fetch, DNS and the
clock are injected. If your change needs new network behavior, add it behind a
fake in tests.

## Project layout

See [docs/architecture.md](docs/architecture.md) for the full picture:

```
packages/core        domain model, scan engine, change detection, prioritization
packages/collectors  passive evidence gathering (DNS, TLS, HTTP, email)
packages/rules       deterministic interpretation of observations
packages/storage     SQLite persistence (node:sqlite), migrations
packages/reports     JSON + human rendering
apps/cli             the dlos command line
```

## Adding a security rule

This is the highest-value contribution path. Rules are pure functions from
observations to findings — no network, no randomness. Follow
[docs/rule-format.md](docs/rule-format.md) and the checklist there; in short:

1. Add a collector (or reuse one) and a stable `checkId`.
2. Implement the rule with the full finding contract (observation, evidence,
   impact, confidence, recommendation, verification).
3. Add a pass description so healthy checks appear as verified evidence.
4. Add JSON fixtures — **including a false-positive case** (lookup error,
   timeout, empty result). A rule that can fire on inconclusive data will be
   rejected.

## Commit and PR style

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
  `docs:`, `test:`, `chore:`, `ci:`, `refactor:` — scope optional, e.g.
  `feat(rules): detect missing security.txt`.
- Keep PRs focused; one rule or one concern per PR is a good size.
- PR checklist: tests pass, new rules ship with fixtures + false-positive
  guards, docs updated, JSON output stays valid JSON.

## Reporting bugs

Open a GitHub issue using the bug template. **Redact domain names, IPs and
report contents** — your scan data is yours, and issue readers don't need it.

## Reporting security issues

This project is itself a security tool; please report vulnerabilities in dlos
privately per [SECURITY.md](SECURITY.md) rather than in a public issue.

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
