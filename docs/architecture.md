# Architecture

One shared security engine, two interfaces (CLI today, desktop later), one local
database. The engine is a dependency-injected core so collectors, rules, storage and
the clock are all swappable — which is also what makes every scan testable offline.

```
┌─────────────────────┐   ┌──────────────────┐
│   Desktop (later)   │   │        CLI       │
└──────────┬──────────┘   └────────┬─────────┘
           └──────────┬────────────┘
                      ▼
        ┌───────────────────────────────┐
        │         @dlos/core            │
        │  ScanDeps (all injected):     │
        │  collectors · rules ·         │
        │  passCatalog · storage ·      │
        │  fetch · resolver · clock     │
        └──────┬───────────────┬────────┘
               │               │
   ┌───────────▼───┐   ┌───────▼────────┐
   │  collectors   │   │     rules      │
   │  dns https    │   │  16 pure rules │
   │  tls headers  │   │  + passCatalog │
   │  email        │   │  + parsers     │
   └───────────────┘   └────────────────┘
                      ▼
        ┌───────────────────────────────┐
        │        @dlos/storage          │
        │  SQLite via node:sqlite       │
        │  assets · scans ·             │
        │  observations · findings ·    │
        │  finding_events               │
        └───────────────────────────────┘
```

## The scan pipeline (`runScan` in `packages/core/src/engine.ts`)

1. **Collect** — each collector runs against the asset with its own timeout
   (`AbortSignal.timeout`). A collector crash never fails the scan; it records
   `erroredChecks`. Results are stored as immutable **observations** (the evidence layer).
2. **Interpret** — deterministic rules read observations and return finding drafts.
   Rules are pure: same observation in, same finding out. No network, no randomness.
3. **Diff (change detection)** — each draft is fingerprinted as
   `sha256(ruleId | assetId | subject)` and compared to tracked findings
   (`open` / `in_progress` / `accepted`):
   - fingerprint already tracked → **recurring** (evidence refreshed, `firstSeen` preserved)
   - fingerprint seen before but currently `resolved` → **regressed** (reopened)
   - fingerprint never seen → **new**
   - tracked finding *not* re-observed this scan → **resolved** (this is fix verification)
   - `accepted` findings stay accepted when they disappear; they still update `lastSeen` when they recur
4. **Verify** — healthy checks are turned into human-readable **pass results**
   (`passCatalog`) so reports show what was checked and confirmed, not just failures.
5. **Summarize** — per-scan summary (severities, pass/error counts) is stored, and the
   asset's `lastCheckedAt` is updated.

Every lifecycle change appends a row to `finding_events`, giving an auditable
before/after history per finding.

## Data model (SQLite, schema v1)

| Table | Purpose |
| --- | --- |
| `assets` | user-confirmed inventory items (`identifier` unique, ownership attestation timestamp, DKIM selectors) |
| `scans` | one row per scan run, with a JSON `summary` |
| `observations` | immutable check results (the evidence layer), one row per check |
| `findings` | current finding state: severity, status, JSON detail, fingerprint, first/last seen, resolution |
| `finding_events` | append-only lifecycle log: `new / recurring / resolved / regressed / status_changed` |

Deletes cascade from `assets` down, so removing an asset erases its entire history.
`foreign_keys = ON` and WAL mode are set on every open. Migrations live in
`packages/storage/src/migrations.ts` and are versioned through the `meta` table.

## Prioritization (transparent by design)

```
priority = severityWeight × confidenceWeight × actionabilityWeight
           critical=100   high=1      immediate=1
           high=60        medium=0.7  planned=0.8
           medium=30      low=0.4     informational=0.5
           low=10
           info=1
```

Any priority number in a report can be recomputed by hand. There is no opaque score
and no AI involvement in evidence generation.

## Dependency rules

- `core` depends on nothing but Node built-ins (it defines the ports).
- `collectors` / `rules` / `storage` / `reports` depend on `core` only
  (`rules` also uses `collectors` for observation data types).
- `cli` composes everything and owns the only network defaults.

## Testing strategy

- Collectors and the engine take injected `fetch` / `DomainResolver` / `clock` — tests never touch the network.
- Rules are exercised against JSON fixtures under `packages/rules/tests/fixtures/`,
  including false-positive edge cases (lookup errors, `ENODATA`, inconclusive results).
- Storage is tested against real temporary SQLite files (migrations, cascades, constraints).
- `packages/core/tests/engine.test.ts` walks the full lifecycle:
  new → recurring → resolved → regressed → accepted.
