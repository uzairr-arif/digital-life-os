import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { runScan } from "../src/engine";
import type { ScanDeps } from "../src/engine";
import type { Storage } from "../src/ports";
import type { Asset, JsonValue } from "../src/types";
import type { Collector, DomainResolver } from "../src/collectors";
import type { FindingDraft, Rule } from "../src/rules";
import { openStorage } from "@dlos/storage";

const ASSET_ID = "asset-1";
const BASE = new Date("2026-11-01T12:00:00Z").getTime();
let tickCount = 0;
const tick = (): string => new Date(BASE + tickCount++ * 3_600_000).toISOString();

let storage: Storage;
let hstsHeader: string | undefined;
let collectorFails: boolean;
let asset: Asset;

const unreachable = (): never => {
  throw new Error("no network in tests");
};

const fakeResolver: DomainResolver = {
  resolveTxt: unreachable,
  resolveMx: unreachable,
  resolveNs: unreachable,
  resolve4: unreachable,
  resolve6: unreachable,
  resolveCname: unreachable,
  resolveCaa: unreachable,
};

/** The single fake collector under test: emits an http.headers observation. */
const fakeCollector: Collector = {
  id: "http-headers-fake",
  checkIds: ["http.headers"],
  async run() {
    if (collectorFails) throw new Error("network unreachable (simulated)");
    const headers: JsonValue = hstsHeader
      ? { "strict-transport-security": hstsHeader }
      : {};
    return [
      {
        checkId: "http.headers",
        data: {
          url: "https://example.com/",
          status: 200,
          headers,
          setCookieCount: 0,
        },
      },
    ];
  },
};

/** The single fake rule: flags missing HSTS. */
const hstsRule: Rule = {
  id: "test-hsts",
  consumes: ["http.headers"],
  evaluate(ctx): FindingDraft[] {
    const obs = ctx.observations.get("http.headers")?.[0];
    if (!obs || obs.data === undefined || obs.error !== undefined) return [];
    const headers = (obs.data as { headers: Record<string, string> }).headers;
    if (headers["strict-transport-security"]) return [];
    return [
      {
        subject: "hsts",
        checkId: "http.headers",
        severity: "medium",
        confidence: "high",
        actionability: "planned",
        title: "Missing strict-transport-security header (HSTS)",
        detail: {
          observation: "no HSTS in fake observation",
          evidence: obs.data,
          impact: "test impact",
          confidence: "high",
          recommendation: "test fix",
          verification: "test verify",
        },
      },
    ];
  },
};

const passCatalog = {
  "http.headers": {
    describe: (data: unknown) => {
      const h = (data as { headers: Record<string, string> }).headers;
      return h["strict-transport-security"]
        ? [{ title: "HSTS enabled", text: h["strict-transport-security"] }]
        : [];
    },
  },
};

function makeDeps(): ScanDeps {
  return {
    storage,
    collectors: [fakeCollector],
    rules: [hstsRule],
    passCatalog,
    fetch: unreachable,
    resolver: fakeResolver,
    timeoutMs: 1000,
    now: () => new Date(BASE + tickCount++ * 60_000),
  };
}

beforeEach(() => {
  storage = openStorage(join(mkdtempSync(join(tmpdir(), "dlos-engine-")), "test.db"));
  hstsHeader = undefined;
  collectorFails = false;
  tickCount = 0;
  storage.insertAsset({
    id: ASSET_ID,
    type: "domain",
    identifier: "example.com",
    dkimSelectors: [],
    createdAt: tick(),
    active: true,
  });
  asset = storage.getAssetByIdentifier("example.com")!;
});

describe("runScan — the closed loop", () => {
  it("walks the full lifecycle: new → recurring → resolved → regressed", async () => {
    const r1 = await runScan(makeDeps(), asset);
    expect(r1.findings).toHaveLength(1);
    expect(r1.findings[0]!.status).toBe("open");
    expect(r1.events.map((e) => e.event)).toEqual(["new"]);
    expect(r1.scan.status).toBe("completed");

    const r2 = await runScan(makeDeps(), asset);
    expect(r2.events.map((e) => e.event)).toEqual(["recurring"]);
    // firstSeen must not drift on recurring findings
    expect(r2.findings[0]!.firstSeenAt).toBe(r1.findings[0]!.firstSeenAt);

    hstsHeader = "max-age=31536000";
    const r3 = await runScan(makeDeps(), asset);
    expect(r3.findings).toHaveLength(0);
    expect(r3.events.map((e) => e.event)).toEqual(["resolved"]);
    expect(r3.passes.some((p) => p.title === "HSTS enabled")).toBe(true);

    hstsHeader = undefined;
    const r4 = await runScan(makeDeps(), asset);
    expect(r4.findings).toHaveLength(1);
    expect(r4.events.map((e) => e.event)).toEqual(["regressed"]);
    expect(r4.findings[0]!.status).toBe("open");
  });

  it("accepted risks stay accepted while present, and resolve once actually fixed", async () => {
    const r1 = await runScan(makeDeps(), asset);
    storage.updateFinding(r1.findings[0]!.id, {
      status: "accepted",
      statusNote: "known, fix planned",
    });

    const r2 = await runScan(makeDeps(), asset);
    expect(r2.findings[0]!.status).toBe("accepted");
    expect(r2.events.map((e) => e.event)).toEqual(["recurring"]);

    hstsHeader = "max-age=31536000"; // issue disappears → accepted is moot, resolve it
    const r3 = await runScan(makeDeps(), asset);
    expect(storage.getFinding(r1.findings[0]!.id)!.status).toBe("resolved");
    expect(r3.events.map((e) => e.event)).toEqual(["resolved"]);
  });

  it("a crashing collector completes the scan with errored checks", async () => {
    collectorFails = true;
    const r = await runScan(makeDeps(), asset);
    expect(r.scan.status).toBe("completed");
    expect(r.erroredChecks).toContainEqual({
      checkId: "http.headers",
      error: expect.stringContaining("network unreachable"),
    });
    expect(r.findings).toHaveLength(0);
    expect(r.scan.summary?.checksErrored).toBe(1);
  });

  it("summary counts severities, passes and accepted findings", async () => {
    const r1 = await runScan(makeDeps(), asset);
    expect(r1.scan.summary?.openBySeverity.medium).toBe(1);
    expect(r1.scan.summary?.passCount).toBe(0);
    expect(r1.scan.summary?.checksRun).toBe(1);

    storage.updateFinding(r1.findings[0]!.id, { status: "accepted" });
    const r2 = await runScan(makeDeps(), asset); // still present → accepted
    expect(r2.scan.summary?.acceptedCount).toBe(1);
    expect(r2.scan.summary?.openBySeverity.medium).toBe(0);

    hstsHeader = "max-age=31536000";
    const r3 = await runScan(makeDeps(), asset); // fixed → resolved + pass
    expect(r3.scan.summary?.passCount).toBe(1);
    expect(r3.scan.summary?.acceptedCount).toBe(0);
    expect(storage.getAssetByIdentifier("example.com")!.lastCheckedAt).toBeTruthy();
  });
});
