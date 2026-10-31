# Security Policy

Digital Life OS is itself a security tool, so vulnerabilities in it are treated
seriously and handled privately.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: GitHub **private security advisory** ("Report a vulnerability"
  on the repository's Security tab), once the repository is public.
- Alternative: email **uzairrarif@gmail.com** with `[dlos security]` in the
  subject.

Include: affected version/commit, steps or input that reproduces the issue,
and your assessment of impact. You will get an acknowledgement within 7 days
and a status update at least every 14 days until resolution. With your
permission, credit is given in the release notes.

## Scope

**In scope:** the `dlos` CLI and its packages — storage (data-at-rest handling),
report export, scan orchestration, dependency supply chain (build scripts,
lockfile), and anything that could cause dlos to scan targets outside the
user's confirmed scope.

**Out of scope:** the websites/domains being scanned (report those to their
owners — dlos is passive and read-only by design), and social-engineering of
end users.

## Design invariants worth knowing when auditing

- All data stays local (`~/.dlos/dlos.db`); no telemetry, no cloud calls.
- HTTP evidence capture is a **whitelist**; cookie values are never stored.
- The engine refuses to scan assets without an explicit ownership/authorization
  confirmation (`--confirm`), which is persisted.
- Scans are passive: DNS queries, at most one HTTPS fetch and one TLS
  handshake per domain per check set — no brute force, no exploitation.
- Findings distinguish observation from interpretation; network errors never
  become security findings.
