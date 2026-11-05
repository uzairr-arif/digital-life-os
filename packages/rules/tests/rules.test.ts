import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Asset, JsonValue, Observation, RuleContext } from "@dlos/core";
import { allRules } from "../src";

const load = (name: string): unknown =>
  JSON.parse(
    readFileSync(fileURLToPath(new URL(`./fixtures/${name}.json`, import.meta.url)), "utf8"),
  ) as JsonValue;

const TEST_ASSET: Asset = {
  id: "asset-1",
  type: "domain",
  identifier: "example.com",
  dkimSelectors: ["mail"],
  createdAt: "2026-11-01T00:00:00Z",
  active: true,
};

interface Hit {
  rule: string;
  subject: string;
  severity: string;
  title: string;
}

function runAll(checkId: string, fixtureName?: string, error?: string): Hit[] {
  const obs: Observation = {
    id: "obs-1",
    scanId: "scan-1",
    assetId: TEST_ASSET.id,
    collectorId: "test",
    checkId,
    observedAt: "2026-11-01T00:00:00Z",
    data: error === undefined && fixtureName !== undefined ? (load(fixtureName) as JsonValue) : undefined,
    error,
  };
  const ctx: RuleContext = {
    asset: TEST_ASSET,
    observations: new Map([[checkId, [obs]]]),
  };
  const hits: Hit[] = [];
  for (const rule of allRules) {
    if (!rule.consumes.includes(checkId)) continue;
    for (const d of rule.evaluate(ctx)) {
      hits.push({ rule: rule.id, subject: d.subject, severity: d.severity, title: d.title });
    }
  }
  return hits;
}

const byRule = (hits: Hit[]): Record<string, Hit> =>
  Object.fromEntries(hits.map((h) => [h.rule, h]));

describe("header rules", () => {
  it("flags all six headers when none are present", () => {
    const hits = runAll("http.headers", "headers-missing");
    expect(hits).toHaveLength(6);
    const r = byRule(hits);
    expect(r["header-hsts"]!.severity).toBe("medium");
    expect(r["header-csp"]!.severity).toBe("medium");
    expect(r["header-x-content-type-options"]!.severity).toBe("low");
    expect(r["header-x-frame-options"]!.severity).toBe("low");
    expect(r["header-referrer-policy"]!.severity).toBe("low");
    expect(r["header-permissions-policy"]!.severity).toBe("info");
  });

  it("is quiet when strong headers are present", () => {
    expect(runAll("http.headers", "headers-complete")).toEqual([]);
  });

  it("flags short HSTS max-age", () => {
    const hits = runAll("http.headers", "headers-short-hsts");
    const r = byRule(hits);
    expect(r["header-hsts"]!.subject).toBe("hsts-max-age");
    expect(r["header-hsts"]!.severity).toBe("low");
    expect(r["header-csp"]).toBeUndefined();
  });

  it("flags CSP without default-src, and downgrades XFO when frame-ancestors exists", () => {
    const hits = runAll("http.headers", "headers-csp-no-default-src");
    const r = byRule(hits);
    expect(r["header-csp"]!.subject).toBe("csp-default-src");
    expect(r["header-csp"]!.severity).toBe("low");
    // CSP frame-ancestors present → missing X-Frame-Options downgraded to info
    expect(r["header-x-frame-options"]!.severity).toBe("info");
  });
});

describe("https rules", () => {
  it("flags missing redirect at high severity", () => {
    const r = byRule(runAll("http.redirect", "https-no-redirect"));
    expect(r["https-redirect"]!.severity).toBe("high");
  });

  it("flags redirects to another plain-HTTP location", () => {
    expect(runAll("http.redirect", "https-redirect-to-http")).toHaveLength(1);
  });

  it("is quiet when the redirect is verified", () => {
    expect(runAll("http.redirect", "https-redirect-ok")).toEqual([]);
  });

  it("reports server errors as info, not scary findings", () => {
    const r = byRule(runAll("http.https", "https-server-error"));
    expect(r["https-reachable"]!.severity).toBe("info");
  });

  it("stays quiet when the endpoint is healthy", () => {
    const obs = {
      url: "https://example.com/",
      status: 200,
      ok: true,
    };
    const ctx: RuleContext = {
      asset: TEST_ASSET,
      observations: new Map([
        ["http.https", [{ id: "o", scanId: "s", assetId: "a", collectorId: "c", checkId: "http.https", observedAt: "2026-01-01T00:00:00Z", data: obs }]],
      ]),
    };
    const rule = allRules.find((r) => r.id === "https-reachable")!;
    expect(rule.evaluate(ctx)).toEqual([]);
  });
});

describe("tls rules", () => {
  it("critical for expired certificates", () => {
    const r = byRule(runAll("tls.certificate", "tls-expired"));
    expect(r["tls-certificate"]!.severity).toBe("critical");
    expect(r["tls-certificate"]!.title).toContain("expired");
  });

  it("high when expiry is within 14 days", () => {
    const r = byRule(runAll("tls.certificate", "tls-expiring"));
    expect(r["tls-certificate"]!.severity).toBe("high");
  });

  it("high for self-signed, critical for hostname mismatch", () => {
    expect(byRule(runAll("tls.certificate", "tls-self-signed"))["tls-certificate"]!.severity).toBe("high");
    expect(byRule(runAll("tls.certificate", "tls-hostname-mismatch"))["tls-certificate"]!.severity).toBe("critical");
  });

  it("quiet on a healthy certificate, but flags old protocols", () => {
    expect(runAll("tls.certificate", "tls-ok")).toEqual([]);
    const r = byRule(runAll("tls.certificate", "tls-old-protocol"));
    expect(r["tls-protocol"]!.severity).toBe("medium");
    expect(r["tls-certificate"]).toBeUndefined();
  });
});

describe("spf rules", () => {
  it("flags missing SPF at medium", () => {
    const r = byRule(runAll("email.spf", "spf-missing"));
    expect(r["spf-present"]!.severity).toBe("medium");
  });

  it("flags +all at high and ?all at medium, stays quiet on -all", () => {
    expect(byRule(runAll("email.spf", "spf-plus-all"))["spf-all-qualifier"]!.severity).toBe("high");
    expect(runAll("email.spf", "spf-hardfail")).toEqual([]);
  });

  it("notes softfail as informational", () => {
    const r = byRule(runAll("email.spf", "spf-softfail"));
    expect(r["spf-all-qualifier"]!.severity).toBe("info");
  });

  it("flags lookup-limit violations with medium confidence", () => {
    const hits = runAll("email.spf", "spf-many-lookups");
    const r = byRule(hits);
    expect(r["spf-lookup-limit"]!.severity).toBe("medium");
    expect(r["spf-lookup-limit"]!.rule).toBe("spf-lookup-limit");
  });

  it("never flags when the lookup itself failed", () => {
    expect(runAll("email.spf", undefined, "Error: queryTxt ETIMEDOUT example.com")).toEqual([]);
  });
});

describe("dmarc rules", () => {
  it("flags missing DMARC at medium", () => {
    expect(byRule(runAll("email.dmarc", "dmarc-missing"))["dmarc-present"]!.severity).toBe("medium");
  });

  it("flags multiple records at high", () => {
    expect(byRule(runAll("email.dmarc", "dmarc-multiple"))["dmarc-present"]!.severity).toBe("high");
  });

  it("flags records without a p= tag", () => {
    const r = byRule(runAll("email.dmarc", "dmarc-no-p"));
    expect(r["dmarc-present"]!.subject).toBe("no-policy");
  });

  it("flags p=none at low (monitoring-only), quiet at p=quarantine", () => {
    const none = byRule(runAll("email.dmarc", "dmarc-none"));
    expect(none["dmarc-policy"]!.severity).toBe("low");
    expect(none["dmarc-policy"]!.title).toContain("not enforcing");
    expect(runAll("email.dmarc", "dmarc-quarantine")).toEqual([]);
  });
});

describe("dns caa rule", () => {
  it("flags absent CAA as info (ENODATA counts as absence)", () => {
    const r = byRule(runAll("dns.records", "dns-no-caa"));
    expect(r["caa-present"]!.severity).toBe("info");
  });

  it("stays quiet when CAA exists or the lookup is inconclusive", () => {
    expect(runAll("dns.records", "dns-caa-present")).toEqual([]);
    const obs: Observation = {
      id: "o",
      scanId: "s",
      assetId: "a",
      collectorId: "c",
      checkId: "dns.records",
      observedAt: "2026-01-01T00:00:00Z",
      data: { domain: "example.com", A: { error: "Error: queryA ETIMEDOUT example.com" }, CAA: { error: "Error: queryCaa SERVFAIL example.com" } },
    };
    const ctx: RuleContext = { asset: TEST_ASSET, observations: new Map([["dns.records", [obs]]]) };
    const rule = allRules.find((r) => r.id === "caa-present")!;
    expect(rule.evaluate(ctx)).toEqual([]);
  });
});

describe("false-positive guards (regression)", () => {
  it("header rules stay SILENT when the check errored — inconclusive is never 'missing'", () => {
    const hits = runAll("http.headers", undefined, "TimeoutError: The operation was aborted due to timeout");
    expect(hits).toEqual([]);
  });

  it("unrelated TXT records are not counted as SPF/DMARC records", () => {
    expect(runAll("email.spf", "spf-mixed-txt")).toEqual([]);
    expect(runAll("email.dmarc", "dmarc-mixed-txt")).toEqual([]);
  });
});

describe("security.txt rules (v0.2)", () => {
  it("flags missing security.txt as info", () => {
    const r = byRule(runAll("web.securitytxt", "securitytxt-missing"));
    expect(r["web-securitytxt"]!.severity).toBe("info");
    expect(r["web-securitytxt"]!.title).toContain("No security.txt");
  });

  it("flags a file without Contact at low, stays quiet on a complete file", () => {
    const r = byRule(runAll("web.securitytxt", "securitytxt-no-contact"));
    expect(r["web-securitytxt"]!.severity).toBe("low");
    expect(r["web-securitytxt"]!.subject).toBe("no-contact");
    expect(runAll("web.securitytxt", "securitytxt-ok")).toEqual([]);
  });
});

describe("cookie flag rules (v0.2)", () => {
  it("counts cookies per missing flag, without ever seeing names or values", () => {
    const hits = runAll("http.headers", "headers-cookie-flags");
    const r = byRule(hits);
    expect(r["cookie-secure"]!.severity).toBe("low");
    expect(r["cookie-secure"]!.title).toContain("1 cookie");
    expect(r["cookie-httponly"]!.title).toContain("2 cookie");
    expect(r["cookie-samesite"]!.severity).toBe("info");
    // fixture keeps 5 of 6 headers (permissions-policy missing → 1 finding) + 3 cookie rules
    expect(hits).toHaveLength(4);
  });

  it("stays quiet when all cookies carry all flags, or when no cookies are present", () => {
    expect(runAll("http.headers", "headers-complete")).toEqual([]);
    expect(runAll("http.headers", "headers-missing")).toHaveLength(6); // no cookies field → no cookie findings
  });
});

describe("determinism", () => {
  it("the same fixture always produces the same findings", () => {
    const a = runAll("http.headers", "headers-missing");
    const b = runAll("http.headers", "headers-missing");
    expect(a).toEqual(b);
  });
});
