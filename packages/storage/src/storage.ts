import { DatabaseSync } from "node:sqlite";
import {
  severityAtLeast,
  severityRank,
} from "@dlos/core";
import type {
  Asset,
  AssetPatch,
  Finding,
  FindingDetail,
  FindingEvent,
  FindingStatus,
  Observation,
  Scan,
  ScanSummary,
  Storage,
} from "@dlos/core";
import type { FindingsFilter, FindingPatch } from "@dlos/core";
import { migrate } from "./migrations";
import { openDatabase } from "./open";

type Row = Record<string, null | number | bigint | string | Uint8Array>;

function str(v: unknown): string {
  return typeof v === "string" ? v : String(v);
}
function nstr(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function num(v: unknown): number {
  return typeof v === "number" ? v : Number(v);
}
function bool(v: unknown): boolean {
  return Number(v) !== 0;
}

function jsonParse<T>(text: unknown, fallback: T): T {
  if (typeof text !== "string") return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

function rowToAsset(r: Row): Asset {
  return {
    id: str(r.id),
    type: str(r.type) as Asset["type"],
    identifier: str(r.identifier),
    label: nstr(r.label),
    group: nstr(r.group_name),
    ownershipConfirmedAt: nstr(r.ownership_confirmed_at),
    dkimSelectors: jsonParse<string[]>(r.dkim_selectors, []),
    createdAt: str(r.created_at),
    lastCheckedAt: nstr(r.last_checked_at),
    active: bool(r.active),
  };
}

function rowToScan(r: Row): Scan {
  return {
    id: str(r.id),
    assetId: str(r.asset_id),
    startedAt: str(r.started_at),
    finishedAt: nstr(r.finished_at),
    status: str(r.status) as Scan["status"],
    summary: jsonParse<ScanSummary | undefined>(r.summary_json, undefined),
  };
}

function rowToObservation(r: Row): Observation {
  return {
    id: str(r.id),
    scanId: str(r.scan_id),
    assetId: str(r.asset_id),
    collectorId: str(r.collector_id),
    checkId: str(r.check_id),
    observedAt: str(r.observed_at),
    data: r.data_json === null ? undefined : jsonParse(r.data_json, undefined),
    error: nstr(r.error),
  };
}

function rowToFinding(r: Row): Finding {
  return {
    id: str(r.id),
    assetId: str(r.asset_id),
    fingerprint: str(r.fingerprint),
    ruleId: str(r.rule_id),
    checkId: str(r.check_id),
    severity: str(r.severity) as Finding["severity"],
    title: str(r.title),
    status: str(r.status) as FindingStatus,
    statusNote: nstr(r.status_note),
    actionability: str(r.actionability) as Finding["actionability"],
    detail: jsonParse<FindingDetail>(r.detail_json, {
      observation: "(corrupt detail)",
      evidence: null,
      impact: "",
      confidence: "low",
      recommendation: "",
      verification: "",
    }),
    firstSeenAt: str(r.first_seen_at),
    lastSeenAt: str(r.last_seen_at),
    lastSeenScanId: nstr(r.last_seen_scan_id),
    resolvedAt: nstr(r.resolved_at),
    resolvedScanId: nstr(r.resolved_scan_id),
    priorityScore: num(r.priority_score),
  };
}

function rowToEvent(r: Row): FindingEvent {
  return {
    id: str(r.id),
    findingId: str(r.finding_id),
    scanId: nstr(r.scan_id),
    event: str(r.event) as FindingEvent["event"],
    detail: nstr(r.detail),
    at: str(r.at),
  };
}

export class SqliteStorage implements Storage {
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    this.db = openDatabase(dbPath);
  }

  // -------------------------------------------------------------------- assets
  insertAsset(asset: Asset): void {
    this.db
      .prepare(
        `INSERT INTO assets
           (id, type, identifier, label, group_name, ownership_confirmed_at,
            dkim_selectors, created_at, last_checked_at, active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        asset.id,
        asset.type,
        asset.identifier,
        asset.label ?? null,
        asset.group ?? null,
        asset.ownershipConfirmedAt ?? null,
        JSON.stringify(asset.dkimSelectors),
        asset.createdAt,
        asset.lastCheckedAt ?? null,
        asset.active ? 1 : 0,
      );
  }

  getAsset(assetId: string): Asset | null {
    const r = this.db.prepare("SELECT * FROM assets WHERE id = ?").get(assetId) as Row | undefined;
    return r ? rowToAsset(r) : null;
  }

  getAssetByIdentifier(identifier: string): Asset | null {
    const r = this.db
      .prepare("SELECT * FROM assets WHERE identifier = ?")
      .get(identifier) as Row | undefined;
    return r ? rowToAsset(r) : null;
  }

  listAssets(): Asset[] {
    const rows = this.db
      .prepare("SELECT * FROM assets ORDER BY identifier")
      .all() as Row[];
    return rows.map(rowToAsset);
  }

  updateAsset(assetId: string, patch: AssetPatch): void {
    const sets: string[] = [];
    const params: (string | number)[] = [];
    if (patch.label !== undefined) { sets.push("label = ?"); params.push(patch.label); }
    if (patch.group !== undefined) { sets.push("group_name = ?"); params.push(patch.group); }
    if (patch.dkimSelectors !== undefined) {
      sets.push("dkim_selectors = ?");
      params.push(JSON.stringify(patch.dkimSelectors));
    }
    if (patch.active !== undefined) { sets.push("active = ?"); params.push(patch.active ? 1 : 0); }
    if (sets.length === 0) return;
    params.push(assetId);
    this.db.prepare(`UPDATE assets SET ${sets.join(", ")} WHERE id = ?`).run(...params);
  }

  /** Deletes the asset; findings/scans/observations/events go with it via FK cascades. */
  deleteAssetDeep(assetId: string): void {
    this.db.prepare("DELETE FROM assets WHERE id = ?").run(assetId);
  }

  setAssetChecked(assetId: string, checkedAt: string): void {
    this.db
      .prepare("UPDATE assets SET last_checked_at = ? WHERE id = ?")
      .run(checkedAt, assetId);
  }

  // --------------------------------------------------------------------- scans
  createScan(scan: Scan): void {
    this.db
      .prepare(
        "INSERT INTO scans (id, asset_id, started_at, finished_at, status, summary_json) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(scan.id, scan.assetId, scan.startedAt, scan.finishedAt ?? null, scan.status, null);
  }

  updateScan(scan: Scan): void {
    this.db
      .prepare("UPDATE scans SET finished_at = ?, status = ?, summary_json = ? WHERE id = ?")
      .run(
        scan.finishedAt ?? null,
        scan.status,
        scan.summary ? JSON.stringify(scan.summary) : null,
        scan.id,
      );
  }

  getScan(scanId: string): Scan | null {
    const r = this.db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId) as Row | undefined;
    return r ? rowToScan(r) : null;
  }

  listScans(assetId: string, limit = 20): Scan[] {
    const rows = this.db
      .prepare("SELECT * FROM scans WHERE asset_id = ? ORDER BY started_at DESC LIMIT ?")
      .all(assetId, limit) as Row[];
    return rows.map(rowToScan);
  }

  // -------------------------------------------------------------- observations
  insertObservations(observations: Observation[]): void {
    if (observations.length === 0) return;
    const stmt = this.db.prepare(
      `INSERT INTO observations
         (id, scan_id, asset_id, collector_id, check_id, observed_at, data_json, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    this.db.exec("BEGIN");
    try {
      for (const o of observations) {
        stmt.run(
          o.id,
          o.scanId,
          o.assetId,
          o.collectorId,
          o.checkId,
          o.observedAt,
          o.data === undefined ? null : JSON.stringify(o.data),
          o.error ?? null,
        );
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  listObservations(scanId: string): Observation[] {
    const rows = this.db
      .prepare("SELECT * FROM observations WHERE scan_id = ? ORDER BY observed_at")
      .all(scanId) as Row[];
    return rows.map(rowToObservation);
  }

  // ------------------------------------------------------------------ findings
  insertFinding(f: Finding): void {
    this.db
      .prepare(
        `INSERT INTO findings
           (id, asset_id, fingerprint, rule_id, check_id, severity, title, status,
            status_note, actionability, detail_json, first_seen_at, last_seen_at,
            last_seen_scan_id, resolved_at, resolved_scan_id, priority_score)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        f.id,
        f.assetId,
        f.fingerprint,
        f.ruleId,
        f.checkId,
        f.severity,
        f.title,
        f.status,
        f.statusNote ?? null,
        f.actionability,
        JSON.stringify(f.detail),
        f.firstSeenAt,
        f.lastSeenAt,
        f.lastSeenScanId ?? null,
        f.resolvedAt ?? null,
        f.resolvedScanId ?? null,
        f.priorityScore,
      );
  }

  updateFinding(findingId: string, patch: FindingPatch): void {
    const sets: string[] = [];
    const params: (string | number | null)[] = [];
    const set = (col: string, v: string | number | null): void => {
      sets.push(`${col} = ?`);
      params.push(v);
    };
    if (patch.severity !== undefined) set("severity", patch.severity);
    if (patch.title !== undefined) set("title", patch.title);
    if (patch.detail !== undefined) set("detail_json", JSON.stringify(patch.detail));
    if (patch.actionability !== undefined) set("actionability", patch.actionability);
    if (patch.status !== undefined) set("status", patch.status);
    if (patch.priorityScore !== undefined) set("priority_score", patch.priorityScore);
    if (patch.lastSeenAt !== undefined) set("last_seen_at", patch.lastSeenAt);
    // Nullable fields honor explicit `undefined` (clear to NULL) via `in` checks.
    if ("statusNote" in patch) set("status_note", patch.statusNote ?? null);
    if ("lastSeenScanId" in patch) set("last_seen_scan_id", patch.lastSeenScanId ?? null);
    if ("resolvedAt" in patch) set("resolved_at", patch.resolvedAt ?? null);
    if ("resolvedScanId" in patch) set("resolved_scan_id", patch.resolvedScanId ?? null);
    if (sets.length === 0) return;
    params.push(findingId);
    this.db.prepare(`UPDATE findings SET ${sets.join(", ")} WHERE id = ?`).run(...params);
  }

  getFinding(findingId: string): Finding | null {
    const r = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId) as Row | undefined;
    return r ? rowToFinding(r) : null;
  }

  findingByFingerprint(assetId: string, fingerprint: string): Finding | null {
    const r = this.db
      .prepare("SELECT * FROM findings WHERE asset_id = ? AND fingerprint = ?")
      .get(assetId, fingerprint) as Row | undefined;
    return r ? rowToFinding(r) : null;
  }

  listFindings(filter: FindingsFilter = {}): Finding[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (filter.assetId !== undefined) {
      where.push("asset_id = ?");
      params.push(filter.assetId);
    }
    if (filter.statuses && filter.statuses.length > 0) {
      where.push(`status IN (${filter.statuses.map(() => "?").join(", ")})`);
      params.push(...filter.statuses);
    }
    const sql = `SELECT * FROM findings ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY priority_score DESC, first_seen_at ASC
      LIMIT ?`;
    const limit = filter.limit ?? 1000;
    const rows = this.db.prepare(sql).all(...params, limit) as Row[];
    const findings = rows.map(rowToFinding);
    if (filter.minSeverity !== undefined) {
      const threshold = severityRank(filter.minSeverity);
      return findings.filter((f) => severityAtLeast(f.severity, filter.minSeverity!) || severityRank(f.severity) >= threshold);
    }
    return findings;
  }

  // -------------------------------------------------------------------- events
  insertEvents(events: FindingEvent[]): void {
    if (events.length === 0) return;
    const stmt = this.db.prepare(
      "INSERT INTO finding_events (id, finding_id, scan_id, event, detail, at) VALUES (?, ?, ?, ?, ?, ?)",
    );
    this.db.exec("BEGIN");
    try {
      for (const e of events) {
        stmt.run(e.id, e.findingId, e.scanId ?? null, e.event, e.detail ?? null, e.at);
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  eventsForFinding(findingId: string): FindingEvent[] {
    const rows = this.db
      .prepare("SELECT * FROM finding_events WHERE finding_id = ? ORDER BY at")
      .all(findingId) as Row[];
    return rows.map(rowToEvent);
  }

  eventsForAsset(assetId: string, limit = 100): FindingEvent[] {
    const rows = this.db
      .prepare(
        `SELECT fe.* FROM finding_events fe
         JOIN findings f ON f.id = fe.finding_id
         WHERE f.asset_id = ?
         ORDER BY fe.at DESC
         LIMIT ?`,
      )
      .all(assetId, limit) as Row[];
    return rows.map(rowToEvent).reverse();
  }
}
