import { describe, expect, it } from "vitest";
import { buildReport, renderReportHtml } from "../src";
import type { Asset, Finding, Scan } from "@dlos/core";

const asset: Asset = {
  id: "a1",
  type: "domain",
  identifier: "example.com",
  dkimSelectors: [],
  createdAt: "2026-11-01T00:00:00Z",
  active: true,
};

const scan: Scan = {
  id: "abc12345-0000-0000-0000-000000000000",
  assetId: "a1",
  startedAt: "2026-11-07T00:00:00Z",
  finishedAt: "2026-11-07T00:00:10Z",
  status: "completed",
  summary: {
    checksRun: 8,
    checksErrored: 0,
    openBySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    acceptedCount: 0,
    passCount: 2,
  },
};

const finding: Finding = {
  id: "f1",
  assetId: "a1",
  fingerprint: "fp",
  ruleId: "https-redirect",
  checkId: "http.redirect",
  severity: "high",
  title: "HTTP does not redirect to HTTPS",
  status: "open",
  actionability: "immediate",
  detail: {
    observation: "The plain-HTTP endpoint responded directly with content.",
    evidence: { checkId: "http.redirect", status: 200 },
    impact: "Traffic can be read or altered.",
    confidence: "high",
    recommendation: "Add a permanent redirect.",
    verification: "Re-run dlos scan.",
  },
  firstSeenAt: "2026-11-07T00:00:00Z",
  lastSeenAt: "2026-11-07T00:00:00Z",
  priorityScore: 60,
};

describe("renderReportHtml", () => {
  const report = buildReport({
    asset,
    scan,
    findings: [finding],
    passes: [{ checkId: "tls.certificate", title: "TLS certificate trusted", text: "expires in 90 days" }],
    erroredChecks: [],
    events: [{ id: "e1", findingId: "f1", scanId: scan.id, event: "new", at: scan.startedAt }],
  });

  it("renders a complete self-contained document", () => {
    const html = renderReportHtml(report);
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("example.com");
    expect(html).toContain("HTTP does not redirect to HTTPS");
    expect(html).toContain("TLS certificate trusted");
    expect(html).toContain("dlos v0.3.0");
    expect(html).not.toContain("undefined");
    expect(html).not.toMatch(/\u2014/); // no em dashes in shipped reports
  });

  it("escapes finding text (no HTML injection through evidence)", () => {
    const hostile = buildReport({
      asset,
      scan,
      findings: [
        {
          ...finding,
          id: "f2",
          fingerprint: "fp2",
          title: '<script>alert("x")</script>',
          detail: { ...finding.detail, observation: '<img src=x onerror="y()">' },
        },
      ],
      passes: [],
      erroredChecks: [],
      events: [{ id: "e1", findingId: "f1", scanId: scan.id, event: "new", at: scan.startedAt }],
    });
    const html = renderReportHtml(hostile);
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("&lt;script&gt;");
  });
});
