import type { Finding, FindingEvent, ScanResult, Severity } from "./types";

/** A notable change worth notifying about: brand-new or regressed findings. */
export interface DigestEntry {
  assetId: string;
  findingId: string;
  severity: Severity;
  title: string;
  ruleId: string;
  event: "new" | "regressed";
  observation: string;
  recommendation: string;
}

/**
 * Change digest for a scan: the findings the user should hear about.
 * Recurring findings are NOT notified — nagging kills trust. Only genuinely
 * new or regressed issues surface.
 */
export function buildDigest(result: ScanResult): DigestEntry[] {
  const notable = new Set(result.events.filter((e) => e.event === "new" || e.event === "regressed").map((e) => e.findingId));
  if (notable.size === 0) return [];
  const byId = new Map(result.findings.map((f) => [f.id, f]));
  const entries: DigestEntry[] = [];
  for (const e of result.events) {
    if (!notable.has(e.findingId)) continue;
    const f = byId.get(e.findingId);
    if (!f) continue;
    entries.push({
      assetId: result.scan.assetId,
      findingId: f.id,
      severity: f.severity,
      title: f.title,
      ruleId: f.ruleId,
      event: e.event as "new" | "regressed",
      observation: f.detail.observation,
      recommendation: f.detail.recommendation,
    });
  }
  return entries;
}

/** How many entries at or above the given severity. */
export function digestHasSeverity(entries: DigestEntry[], threshold: Severity): boolean {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  const min = order.indexOf(threshold);
  return entries.some((e) => order.indexOf(e.severity) >= min);
}

/** Plain-text digest for console/log notification. Empty string when nothing notable. */
export function formatDigestText(assetIdentifier: string, entries: DigestEntry[]): string {
  if (entries.length === 0) return "";
  const lines: string[] = [];
  lines.push(`${assetIdentifier}: ${entries.length} notable change${entries.length === 1 ? "" : "s"}`);
  for (const e of entries) {
    const marker = e.event === "regressed" ? "REGRESSED" : "new";
    lines.push(`  [${e.severity.toUpperCase()}] ${e.title} (${marker})`);
    lines.push(`    ${e.observation}`);
  }
  return lines.join("\n");
}

/** JSON payload for webhook notifications. */
export function formatDigestJson(
  asset: { identifier: string },
  scanId: string,
  entries: DigestEntry[],
): Record<string, unknown> {
  return {
    tool: "dlos",
    type: "findings-digest",
    asset: asset.identifier,
    scanId,
    generatedAt: new Date().toISOString(),
    changes: entries.map((e) => ({
      event: e.event,
      severity: e.severity,
      title: e.title,
      ruleId: e.ruleId,
      findingId: e.findingId,
      observation: e.observation,
      recommendation: e.recommendation,
    })),
  };
}

export type { Finding, FindingEvent };
