import type {
  Asset,
  Finding,
  FindingEvent,
  FindingEventType,
  PassResult,
  Scan,
  ScanResult,
  ScanSummary,
} from "@dlos/core";

export const TOOL_VERSION = "0.2.0";

export interface ReportFinding extends Finding {
  /** Latest lifecycle change observed for this finding (new/recurring/resolved/regressed). */
  change: FindingEventType | null;
}

export interface ReportJson {
  tool: "dlos";
  version: string;
  generatedAt: string;
  asset: Asset;
  scan: Scan;
  summary: ScanSummary | null;
  findings: ReportFinding[];
  passes: PassResult[];
  erroredChecks: { checkId: string; error: string }[];
}

export interface ReportInput {
  generatedAt?: Date;
  asset: Asset;
  scan: Scan;
  findings: Finding[];
  passes: PassResult[];
  erroredChecks: { checkId: string; error: string }[];
  events: FindingEvent[];
}

export function buildReport(input: ReportInput): ReportJson {
  const latestEventByFinding = new Map<string, FindingEventType>();
  for (const e of input.events) {
    if (e.event === "status_changed") continue;
    // events arrive oldest → newest; later entries win
    latestEventByFinding.set(e.findingId, e.event);
  }

  return {
    tool: "dlos",
    version: TOOL_VERSION,
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
    asset: input.asset,
    scan: input.scan,
    summary: input.scan.summary ?? null,
    findings: input.findings.map((f) => ({
      ...f,
      change: latestEventByFinding.get(f.id) ?? null,
    })),
    passes: input.passes,
    erroredChecks: input.erroredChecks,
  };
}

/** Derive the report shape directly from a fresh ScanResult (post-scan rendering). */
export function reportFromScanResult(
  asset: Asset,
  result: ScanResult,
  generatedAt?: Date,
): ReportJson {
  return buildReport({
    generatedAt,
    asset,
    scan: result.scan,
    findings: result.findings,
    passes: result.passes,
    erroredChecks: result.erroredChecks,
    events: result.events,
  });
}

/** Stable, pretty-printed JSON — machine-readable output must be valid JSON and nothing else. */
export function serializeReportJson(report: ReportJson): string {
  return JSON.stringify(report, null, 2);
}
