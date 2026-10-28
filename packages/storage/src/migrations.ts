import type { DatabaseSync } from "node:sqlite";

interface Migration {
  version: number;
  description: string;
  sql: string;
}

/**
 * Schema v1 — assets, scans, observations (evidence), findings, events.
 * All timestamps are ISO-8601 UTC strings; all payloads are JSON.
 */
const MIGRATIONS: Migration[] = [
  {
    version: 1,
    description: "initial schema",
    sql: `
      CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS assets (
        id                    TEXT PRIMARY KEY,
        type                  TEXT NOT NULL,
        identifier            TEXT NOT NULL UNIQUE,
        label                 TEXT,
        group_name            TEXT,
        ownership_confirmed_at TEXT,
        dkim_selectors        TEXT NOT NULL DEFAULT '[]',
        created_at            TEXT NOT NULL,
        last_checked_at       TEXT,
        active                INTEGER NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS scans (
        id           TEXT PRIMARY KEY,
        asset_id     TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        status       TEXT NOT NULL,
        summary_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id, started_at);

      CREATE TABLE IF NOT EXISTS observations (
        id           TEXT PRIMARY KEY,
        scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        asset_id     TEXT NOT NULL,
        collector_id TEXT NOT NULL,
        check_id     TEXT NOT NULL,
        observed_at  TEXT NOT NULL,
        data_json    TEXT,
        error        TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_observations_scan ON observations(scan_id);

      CREATE TABLE IF NOT EXISTS findings (
        id                TEXT PRIMARY KEY,
        asset_id          TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        fingerprint       TEXT NOT NULL,
        rule_id           TEXT NOT NULL,
        check_id          TEXT NOT NULL,
        severity          TEXT NOT NULL,
        title             TEXT NOT NULL,
        status            TEXT NOT NULL,
        status_note       TEXT,
        actionability     TEXT NOT NULL,
        detail_json       TEXT NOT NULL,
        first_seen_at     TEXT NOT NULL,
        last_seen_at      TEXT NOT NULL,
        last_seen_scan_id TEXT,
        resolved_at       TEXT,
        resolved_scan_id  TEXT,
        priority_score    REAL NOT NULL DEFAULT 0,
        UNIQUE(asset_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id, status);
      CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen_scan_id);

      CREATE TABLE IF NOT EXISTS finding_events (
        id         TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        scan_id    TEXT,
        event      TEXT NOT NULL,
        detail     TEXT,
        at         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id, at);
      CREATE INDEX IF NOT EXISTS idx_events_scan ON finding_events(scan_id);
    `,
  },
];

export function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const row = db
    .prepare("SELECT value FROM meta WHERE key = 'schema_version'")
    .get() as { value: string } | undefined;
  const current = row ? Number(row.value) : 0;

  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    db.exec("BEGIN");
    try {
      db.exec(m.sql);
      db.prepare(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
      ).run(String(m.version));
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw new Error(
        `migration ${m.version} (${m.description}) failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}
