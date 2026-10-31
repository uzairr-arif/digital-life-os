# Security & privacy model

A security tool must itself be defensible. The model is deliberately boring:

## Local by default

- All data (assets, scans, observations, findings, events) lives in one SQLite file:
  `~/.dlos/dlos.db` (override with `--db`).
- No account, no cloud backend, no analytics, no telemetry. Nothing leaves your
  machine except the passive checks themselves.

## Scope is explicit

- `dlos asset add` **requires `--confirm`**, storing an ownership/authorization
  attestation timestamp. The tool refuses to scan unconfirmed targets.
- Checks are passive (DNS queries, one HTTPS fetch, one TLS handshake). No brute
  force, no exploitation, no intrusive port scanning — in this release at all.

## No secrets, ever

- No password vault, no credential storage, no cookies or session material in v1.
- HTTP collection uses a **whitelist**: only security-relevant headers are stored.
  `Set-Cookie` values are never persisted — only their count. This makes the
  database safe to export and share by construction.
- A truthful, identifying user agent (`dlos-scan/0.1 …`) is sent on HTTP checks —
  no browser impersonation.

## Findings are evidence, not verdicts

- Every finding distinguishes observation from interpretation (`confidence`), and
  the report says explicitly when a check *couldn't* run versus when it passed.
- Network errors never produce "vulnerable" findings — they produce errored checks.
- There is no numeric "security score". Priority is a published, hand-checkable formula.

## Renderer boundaries (when the desktop app arrives)

The planned Electron app keeps the renderer sandboxed: no unrestricted filesystem,
shell or Node access from UI code; privileged operations only through a narrow,
validated bridge. The engine already separates privileged work (network, SQLite)
from presentation, which is what makes that boundary practical.

## Deleting your data

`dlos asset remove <domain>` deletes the asset and cascades to all its scans,
observations, findings and events. Deleting the database file removes everything.
