# Digital Life OS — product spec (condensed)

> The full product thesis this implementation is built from: a personal security
> system that helps people understand their digital risks, decide what matters,
> and verify that they have actually fixed them.

## Product promise

**Know what you own, understand what is exposed, fix what matters, and see your
security improve over time.**

## The differentiator: a closed loop

| Question | Capability | Status |
| --- | --- | --- |
| What do I have? | Asset Registry (user-controlled, no automatic account discovery) | ✅ MVP |
| What changed? | Change Detection (new / recurring / resolved / regressed) | ✅ MVP |
| What should I do first? | Transparent prioritization + Action Center semantics (open / in-progress / accepted / resolved) | ✅ MVP |
| Did the fix work? | Verification via re-scan with before/after evidence | ✅ MVP |
| Device posture | OS, firewall, disk-encryption collectors (platform-specific) | Phase 2 |
| Relationship graph | assets ↔ observations ↔ risks ↔ actions, navigable | Phase 3 |
| Personal mode | plain-language explanations, browser extension, breach notifications | Phase 3 |

## Two experiences, one engine

- **Developer mode (built first):** CLI, JSON reports, evidence and severity detail,
  CI-friendly exit codes. Developers give detailed feedback and use the tool daily.
- **Personal mode (later):** plain-language guidance on top of the same findings.
  Do not try to make one interface equally understandable to everyone.

## What makes findings trustworthy

Evidence-first structure (see [rule-format.md](rule-format.md)): observation,
evidence, impact, confidence, recommended action, verification, history.
A security tool that confidently produces false alarms loses trust immediately.

## Stack

TypeScript · pnpm workspaces · Node ≥ 22.13 · SQLite (node:sqlite — zero native
dependencies) · CLI via commander · vitest · tsup for the distributable build.
Desktop app later: React + Electron (sandboxed renderer, narrow validated bridge);
Tauri is a reasonable alternative.

## Roadmap

- **Phase 1 — Core engine (this MVP):** domain inventory, deterministic checks,
  evidence-backed findings, remediation tracking, CLI + reports, local history.
- **Phase 2 — Daily usefulness:** scheduled rechecks and change notifications;
  Windows/Linux device posture; project profiles; guided remediation.
- **Phase 3 — Personal mode:** simplified explanations; browser extension for the
  current page; account-security checklist; optional breach notifications via
  reputable providers.
- **Phase 4 — Security observatory:** visual asset graph; authorized home-network
  inventory; historical trends; signed/exportable reports; plugin architecture.
- **Phase 5 — Ecosystem:** optional self-hosted monitoring; family/multi-device;
  team workspaces; paid capabilities only if demand supports them.

## What NOT to build yet

- A universal account scanner claiming to discover someone's entire online identity
- A password manager or credential vault
- A custom vulnerability scanner duplicating established tools
- Automatic remediation changing firewall/DNS/account settings without approval
- Cloud dashboard, subscription, or AI API before the local workflow works
- A single numeric score implying someone is "secure"
- An enormous animated asset graph before the data model is dependable

## What to measure

| Measure | Tells you |
| --- | --- |
| Time to first useful finding | how fast a new user gets value |
| Finding precision / false-positive rate | whether the tool is trustworthy |
| Fix verification rate | whether users successfully resolve issues |
| Repeat usage | whether users return to check changes |
| Time to run a scan | whether the product feels responsive |

## Signature feature

> **"Show me what changed, why it matters, and prove whether my fix worked."**
