import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openStorage } from "@dlos/storage";
import { buildGraph } from "../src/graph";
import type { SqliteStorage } from "@dlos/storage";

function seed(): SqliteStorage {
  const storage = openStorage(join(mkdtempSync(join(tmpdir(), "dlos-graph-")), "test.db"));
  storage.insertAsset({
    id: "a1",
    type: "domain",
    identifier: "example.com",
    dkimSelectors: [],
    createdAt: "2026-11-01T00:00:00Z",
    active: true,
  });
  storage.insertAsset({
    id: "a2",
    type: "domain",
    identifier: "inactive.example",
    dkimSelectors: [],
    createdAt: "2026-11-01T00:00:00Z",
    active: false,
  });
  return storage;
}

describe("buildGraph", () => {
  it("links asset → check → finding, skipping inactive assets", () => {
    const storage = seed();
    storage.createScan({ id: "s1", assetId: "a1", startedAt: "2026-11-01T00:00:00Z", status: "completed" });
    storage.insertObservations([
      { id: "o1", scanId: "s1", assetId: "a1", collectorId: "c", checkId: "http.headers", observedAt: "t", data: {} },
      { id: "o2", scanId: "s1", assetId: "a1", collectorId: "c", checkId: "tls.certificate", observedAt: "t", data: {} },
    ]);
    storage.insertFinding({
      id: "f1", assetId: "a1", fingerprint: "fp", ruleId: "header-hsts", checkId: "http.headers",
      severity: "medium", title: "Missing HSTS", status: "open", actionability: "planned",
      detail: { observation: "", evidence: null, impact: "", confidence: "high", recommendation: "", verification: "" },
      firstSeenAt: "t", lastSeenAt: "t", priorityScore: 24,
    });

    const g = buildGraph(storage);
    expect(g.nodes.filter((n) => n.kind === "asset").map((n) => n.identifier)).toEqual(["example.com"]);
    const checkIds = g.nodes.filter((n) => n.kind === "check").map((n) => n.checkId);
    expect(checkIds).toContain("http.headers");
    expect(checkIds).toContain("tls.certificate");
    const finding = g.nodes.find((n) => n.kind === "finding");
    expect(finding?.severity).toBe("medium");
    expect(g.links.filter((l) => l.kind === "asset-check")).toHaveLength(2);
    expect(g.links.filter((l) => l.kind === "check-finding")).toHaveLength(1);
  });

  it("creates a check node for findings even without a completed scan", () => {
    const storage = seed();
    storage.insertFinding({
      id: "f1", assetId: "a1", fingerprint: "fp", ruleId: "r", checkId: "email.spf",
      severity: "low", title: "t", status: "open", actionability: "planned",
      detail: { observation: "", evidence: null, impact: "", confidence: "high", recommendation: "", verification: "" },
      firstSeenAt: "t", lastSeenAt: "t", priorityScore: 8,
    });
    const g = buildGraph(storage, "a1");
    expect(g.nodes.some((n) => n.kind === "check" && n.checkId === "email.spf")).toBe(true);
    expect(g.links).toHaveLength(2);
  });

  it("includes errored checks with the errored flag", () => {
    const storage = seed();
    storage.createScan({ id: "s1", assetId: "a1", startedAt: "t", status: "completed" });
    storage.insertObservations([
      { id: "o1", scanId: "s1", assetId: "a1", collectorId: "c", checkId: "http.redirect", observedAt: "t", error: "timeout" },
    ]);
    const g = buildGraph(storage);
    const node = g.nodes.find((n) => n.kind === "check");
    expect(node?.errored).toBe(true);
  });
});
