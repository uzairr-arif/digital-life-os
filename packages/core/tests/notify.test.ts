import { describe, expect, it } from "vitest";
import {
  buildDigest,
  digestHasSeverity,
  formatDigestJson,
  formatDigestText,
} from "../src/notify";
import type { Finding, ScanResult } from "../src/types";

const finding = (over: Partial<Finding>): Finding => ({
  id: "f1",
  assetId: "a1",
  fingerprint: "fp",
  ruleId: "rule-x",
  checkId: "c",
  severity: "high",
  title: "Something broke",
  status: "open",
  actionability: "immediate",
  detail: {
    observation: "observed something",
    evidence: null,
    impact: "impact",
    confidence: "high",
    recommendation: "fix it",
    verification: "rescan",
  },
  firstSeenAt: "2026-11-01T00:00:00Z",
  lastSeenAt: "2026-11-01T00:00:00Z",
  priorityScore: 60,
  ...over,
});

const result = (findings: Finding[], events: ScanResult["events"]): ScanResult => ({
  scan: { id: "s1", assetId: "a1", startedAt: "2026-11-01T00:00:00Z", status: "completed" },
  findings,
  passes: [],
  erroredChecks: [],
  events,
});

describe("buildDigest", () => {
  it("includes new and regressed findings, excludes recurring", () => {
    const fNew = finding({ id: "f1" });
    const fRec = finding({ id: "f2", title: "Recurring thing" });
    const fReg = finding({ id: "f3", title: "Came back" });
    const r = result(
      [fNew, fRec, fReg],
      [
        { id: "e1", findingId: "f1", event: "new", at: "t" },
        { id: "e2", findingId: "f2", event: "recurring", at: "t" },
        { id: "e3", findingId: "f3", event: "regressed", at: "t" },
      ],
    );
    const digest = buildDigest(r);
    expect(digest.map((d) => d.findingId)).toEqual(["f1", "f3"]);
    expect(digest[1]!.event).toBe("regressed");
  });

  it("returns empty when nothing is new (the quiet case is the common case)", () => {
    const r = result([finding({})], [{ id: "e1", findingId: "f1", event: "recurring", at: "t" }]);
    expect(buildDigest(r)).toEqual([]);
  });
});

describe("digestHasSeverity", () => {
  it("respects the threshold", () => {
    const entries = buildDigest(
      result([finding({ severity: "low" })], [{ id: "e1", findingId: "f1", event: "new", at: "t" }]),
    );
    expect(digestHasSeverity(entries, "info")).toBe(true);
    expect(digestHasSeverity(entries, "medium")).toBe(false);
    expect(digestHasSeverity(entries, "low")).toBe(true);
  });
});

describe("formatters", () => {
  const entries = buildDigest(
    result([finding({})], [{ id: "e1", findingId: "f1", event: "new", at: "t" }]),
  );

  it("text digest is human-readable and empty when quiet", () => {
    const text = formatDigestText("example.com", entries);
    expect(text).toContain("example.com: 1 notable change");
    expect(text).toContain("[HIGH] Something broke (new)");
    expect(formatDigestText("example.com", [])).toBe("");
  });

  it("json digest is webhook-shaped and JSON-safe", () => {
    const json = formatDigestJson({ identifier: "example.com" }, "s1", entries) as {
      changes: { title: string }[];
    };
    expect(json.changes[0]!.title).toBe("Something broke");
    expect(JSON.parse(JSON.stringify(json))).toBeTruthy();
  });
});
