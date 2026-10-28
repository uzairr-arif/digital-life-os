import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { SqliteStorage } from "../src/storage";
import { openDatabase } from "../src/open";

const dbPath = (): string =>
  join(mkdtempSync(join(tmpdir(), "dlos-storage-")), "test.db");

let storage: SqliteStorage;

beforeEach(() => {
  storage = new SqliteStorage(dbPath());
});

function sampleAsset() {
  return {
    id: "a-1",
    type: "domain" as const,
    identifier: "example.com",
    label: "Example",
    dkimSelectors: ["mail"],
    createdAt: "2026-11-01T00:00:00Z",
    active: true,
  };
}

function sampleFinding(over: Partial<Parameters<SqliteStorage["insertFinding"]>[0]> = {}) {
  return {
    id: "f-1",
    assetId: "a-1",
    fingerprint: "fp-1",
    ruleId: "rule-1",
    checkId: "http.headers",
    severity: "medium" as const,
    title: "Missing HSTS",
    status: "open" as const,
    actionability: "planned" as const,
    detail: {
      observation: "observed",
      evidence: { checkId: "http.headers", data: { headers: {} } },
      impact: "impact",
      confidence: "high" as const,
      recommendation: "fix",
      verification: "verify",
    },
    firstSeenAt: "2026-11-01T00:00:00Z",
    lastSeenAt: "2026-11-01T00:00:00Z",
    priorityScore: 30,
    ...over,
  };
}

describe("SqliteStorage", () => {
  it("reopens the same database with migrations already applied", () => {
    const p = dbPath();
    new SqliteStorage(p); // first open migrates
    expect(() => new SqliteStorage(p)).not.toThrow();
    expect(() => openDatabase(p)).not.toThrow();
  });

  it("stores and retrieves assets; identifiers are unique", () => {
    storage.insertAsset(sampleAsset());
    const got = storage.getAssetByIdentifier("example.com");
    expect(got?.dkimSelectors).toEqual(["mail"]);
    expect(got?.label).toBe("Example");
    expect(() => storage.insertAsset({ ...sampleAsset(), id: "a-2" })).toThrow();
  });

  it("round-trips findings with evidence intact", () => {
    storage.insertAsset(sampleAsset());
    storage.insertFinding(sampleFinding());
    const got = storage.getFinding("f-1");
    expect(got?.detail.evidence).toEqual({
      checkId: "http.headers",
      data: { headers: {} },
    });
    expect(got?.severity).toBe("medium");
  });

  it("enforces UNIQUE(asset, fingerprint)", () => {
    storage.insertAsset(sampleAsset());
    storage.insertFinding(sampleFinding());
    expect(() => storage.insertFinding({ ...sampleFinding(), id: "f-2" })).toThrow();
  });

  it("applies updateFinding patches, including clearing resolved fields", () => {
    storage.insertAsset(sampleAsset());
    storage.insertFinding(sampleFinding());
    storage.updateFinding("f-1", {
      status: "resolved",
      resolvedAt: "2026-11-02T00:00:00Z",
      resolvedScanId: "s-1",
    });
    expect(storage.getFinding("f-1")?.status).toBe("resolved");
    storage.updateFinding("f-1", {
      status: "open",
      resolvedAt: undefined,
      resolvedScanId: undefined,
    });
    const f = storage.getFinding("f-1")!;
    expect(f.status).toBe("open");
    expect(f.resolvedAt).toBeUndefined();
    expect(f.resolvedScanId).toBeUndefined();
  });

  it("filters findings by status and minimum severity", () => {
    storage.insertAsset(sampleAsset());
    storage.insertFinding(sampleFinding({ id: "f-1", severity: "high", priorityScore: 60 }));
    storage.insertFinding(
      sampleFinding({ id: "f-2", fingerprint: "fp-2", severity: "low", priorityScore: 10 }),
    );
    expect(storage.listFindings({ statuses: ["open"] })).toHaveLength(2);
    expect(
      storage.listFindings({ statuses: ["open"], minSeverity: "high" }).map((f) => f.id),
    ).toEqual(["f-1"]);
    expect(storage.listFindings({ statuses: ["resolved"] })).toHaveLength(0);
  });

  it("cascades deletes: asset → scans → observations → findings → events", () => {
    storage.insertAsset(sampleAsset());
    storage.createScan({
      id: "s-1",
      assetId: "a-1",
      startedAt: "2026-11-01T00:00:00Z",
      status: "completed",
    });
    storage.insertObservations([
      {
        id: "o-1",
        scanId: "s-1",
        assetId: "a-1",
        collectorId: "c",
        checkId: "http.headers",
        observedAt: "2026-11-01T00:00:00Z",
        data: { ok: true },
      },
    ]);
    storage.insertFinding(sampleFinding({ lastSeenScanId: "s-1" }));
    storage.insertEvents([
      { id: "e-1", findingId: "f-1", scanId: "s-1", event: "new", at: "2026-11-01T00:00:00Z" },
    ]);

    expect(storage.listObservations("s-1")).toHaveLength(1);
    storage.deleteAssetDeep("a-1");
    expect(storage.getAsset("a-1")).toBeNull();
    expect(storage.getScan("s-1")).toBeNull();
    expect(storage.listObservations("s-1")).toHaveLength(0);
    expect(storage.getFinding("f-1")).toBeNull();
    expect(storage.eventsForFinding("f-1")).toHaveLength(0);
  });

  it("records events and returns them oldest → newest per asset", () => {
    storage.insertAsset(sampleAsset());
    storage.insertFinding(sampleFinding());
    storage.insertFinding(sampleFinding({ id: "f-2", fingerprint: "fp-2" }));
    storage.insertEvents([
      { id: "e-1", findingId: "f-1", scanId: "s-1", event: "new", at: "2026-11-01T01:00:00Z" },
      { id: "e-2", findingId: "f-1", scanId: "s-2", event: "recurring", at: "2026-11-02T01:00:00Z" },
      { id: "e-3", findingId: "f-2", scanId: "s-2", event: "new", at: "2026-11-02T02:00:00Z" },
    ]);
    const events = storage.eventsForAsset("a-1");
    expect(events.map((e) => e.at)).toEqual([
      "2026-11-01T01:00:00Z",
      "2026-11-02T01:00:00Z",
      "2026-11-02T02:00:00Z",
    ]);
  });

  it("lists scans newest first and keeps summaries as JSON", () => {
    storage.insertAsset(sampleAsset());
    storage.createScan({ id: "s-1", assetId: "a-1", startedAt: "2026-11-01T00:00:00Z", status: "running" });
    storage.createScan({ id: "s-2", assetId: "a-1", startedAt: "2026-11-02T00:00:00Z", status: "running" });
    const done = {
      id: "s-2",
      assetId: "a-1",
      startedAt: "2026-11-02T00:00:00Z",
      finishedAt: "2026-11-02T00:00:10Z",
      status: "completed" as const,
      summary: {
        checksRun: 7,
        checksErrored: 1,
        openBySeverity: { critical: 0, high: 1, medium: 2, low: 0, info: 0 },
        acceptedCount: 0,
        passCount: 4,
      },
    };
    storage.updateScan(done);
    const scans = storage.listScans("a-1");
    expect(scans.map((s) => s.id)).toEqual(["s-2", "s-1"]);
    expect(scans[0]!.summary?.checksErrored).toBe(1);
  });
});
