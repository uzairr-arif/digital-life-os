import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openStorage } from "@dlos/storage";
import type { ServerHandle } from "@dlos/server";
import { startServer } from "@dlos/server";
import type { SqliteStorage } from "@dlos/storage";

let storage: SqliteStorage;
let handle: ServerHandle;
let assetId: string;
const base = () => handle.url;

beforeAll(async () => {
  storage = openStorage(join(mkdtempSync(join(tmpdir(), "dlos-server-")), "test.db"));
  assetId = "asset-1";
  storage.insertAsset({
    id: assetId,
    type: "domain",
    identifier: "example.com",
    group: "test",
    dkimSelectors: [],
    createdAt: "2026-11-01T00:00:00Z",
    active: true,
  });
  storage.insertFinding({
    id: "f-1",
    assetId,
    fingerprint: "fp-1",
    ruleId: "header-hsts",
    checkId: "http.headers",
    severity: "medium",
    title: "Missing strict-transport-security header (HSTS)",
    status: "open",
    actionability: "planned",
    detail: {
      observation: "no HSTS",
      evidence: { checkId: "http.headers", observedAt: "2026-11-01T00:00:00Z", data: {} },
      impact: "downgrade risk",
      confidence: "high",
      recommendation: "add the header",
      verification: "rescan",
    },
    firstSeenAt: "2026-11-01T00:00:00Z",
    lastSeenAt: "2026-11-01T00:00:00Z",
    priorityScore: 24,
  });
  storage.createScan({ id: "s-1", assetId, startedAt: "2026-11-01T00:00:00Z", status: "running" });
  storage.insertObservations([
    {
      id: "o-1",
      scanId: "s-1",
      assetId,
      collectorId: "http-headers",
      checkId: "http.headers",
      observedAt: "2026-11-01T00:00:00Z",
      data: { status: 200, headers: {}, setCookieCount: 0 },
    },
  ]);
  handle = await startServer({ storage, publicDir: join(__dirname, "..", "public") });
});

afterAll(async () => {
  await handle.close();
});

describe("local dashboard server", () => {
  it("serves the dashboard with the boot token injected", async () => {
    const res = await fetch(base() + "/");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain("dlos");
    expect(html).toMatch(/window\.__DLOS_TOKEN__ = "[0-9a-f]{48}"/);
  });

  it("exposes state, per-asset detail and the graph", async () => {
    const state = (await (await fetch(base() + "/api/state")).json()) as {
      version: string;
      assets: { identifier: string; bySeverity: Record<string, number> }[];
    };
    expect(state.version).toBe("0.3.0");
    expect(state.assets[0]!.identifier).toBe("example.com");
    expect(state.assets[0]!.bySeverity.medium).toBe(1);

    const detail = (await (await fetch(base() + "/api/asset/" + assetId)).json()) as {
      findings: unknown[];
      scans: unknown[];
    };
    expect(detail.findings).toHaveLength(1);
    expect(detail.scans).toHaveLength(1);

    const graph = (await (await fetch(base() + "/api/graph?assetId=" + assetId)).json()) as {
      nodes: { kind: string }[];
      links: unknown[];
    };
    const kinds = graph.nodes.map((n) => n.kind);
    expect(kinds).toContain("asset");
    expect(kinds).toContain("check");
    expect(kinds).toContain("finding");
    expect(graph.links).toHaveLength(2); // asset→check, check→finding
  });

  it("gates the scan endpoint behind the boot token (CSRF boundary)", async () => {
    const noToken = await fetch(base() + "/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(noToken.status).toBe(403);
    const badToken = await fetch(base() + "/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "x-dlos-token": "wrong" },
      body: "{}",
    });
    expect(badToken.status).toBe(403);
  });

  it("rejects unknown routes and path traversal on static files", async () => {
    expect((await fetch(base() + "/nope")).status).toBe(404);
    expect((await fetch(base() + "/assets/../server.ts")).status).toBe(404);
    expect((await fetch(base() + "/api/asset/nope")).status).toBe(404);
  });

  it("binds to loopback only", async () => {
    expect(handle.url.startsWith("http://127.0.0.1:")).toBe(true);
  });
});
