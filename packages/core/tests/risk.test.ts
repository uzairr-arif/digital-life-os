import { describe, expect, it } from "vitest";
import {
  ACTIONABILITY_WEIGHT,
  CONFIDENCE_WEIGHT,
  SEVERITY_WEIGHT,
  priorityScore,
  rankFindings,
  severityAtLeast,
} from "../src/risk";
import type { Finding } from "../src/types";

const finding = (over: Partial<Finding>): Finding => ({
  id: "f1",
  assetId: "a1",
  fingerprint: "fp",
  ruleId: "r",
  checkId: "c",
  severity: "medium",
  title: "t",
  status: "open",
  actionability: "planned",
  detail: {
    observation: "",
    evidence: null,
    impact: "",
    confidence: "high",
    recommendation: "",
    verification: "",
  },
  firstSeenAt: "2026-11-01T00:00:00Z",
  lastSeenAt: "2026-11-01T00:00:00Z",
  priorityScore: priorityScore("medium", "high", "planned"),
  ...over,
});

describe("priorityScore", () => {
  it("is severity × confidence × actionability", () => {
    expect(
      priorityScore("high", "high", "immediate"),
    ).toBe(SEVERITY_WEIGHT.high * CONFIDENCE_WEIGHT.high * ACTIONABILITY_WEIGHT.immediate);
    expect(priorityScore("critical", "medium", "informational")).toBe(
      Math.round(100 * 0.7 * 0.5 * 10) / 10,
    );
  });

  it("orders severities monotonically", () => {
    expect(priorityScore("critical", "high", "immediate")).toBeGreaterThan(
      priorityScore("high", "high", "immediate"),
    );
    expect(priorityScore("high", "high", "immediate")).toBeGreaterThan(
      priorityScore("medium", "high", "immediate"),
    );
  });
});

describe("severityAtLeast", () => {
  it("respects the order info < low < medium < high < critical", () => {
    expect(severityAtLeast("high", "high")).toBe(true);
    expect(severityAtLeast("critical", "high")).toBe(true);
    expect(severityAtLeast("medium", "high")).toBe(false);
  });
});

describe("rankFindings", () => {
  it("sorts by score desc, then severity, then age", () => {
    const list = [
      finding({ id: "a", priorityScore: 30 }),
      finding({ id: "b", priorityScore: 60 }),
      finding({ id: "c", priorityScore: 30, firstSeenAt: "2026-01-01T00:00:00Z" }),
    ];
    expect(rankFindings(list).map((f) => f.id)).toEqual(["b", "c", "a"]);
  });
});
