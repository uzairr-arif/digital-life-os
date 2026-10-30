import { writeFileSync } from "node:fs";
import type { Command } from "commander";
import { normalizeDomain } from "@dlos/core";
import type { Observation, PassResult } from "@dlos/core";
import { passCatalog } from "@dlos/rules";
import {
  buildReport,
  renderReport,
  serializeReportJson,
} from "@dlos/reports";
import { fail, ctxFrom, note } from "../ui";

/**
 * Build a report from stored evidence for the asset's latest completed scan.
 * Findings include everything that was present at that scan *or* resolved by it,
 * so "did the fix work?" is visible in the report itself.
 */
export function registerReportCommand(program: Command): void {
  program
    .command("report <target>")
    .description("Render a report for an asset from the latest scan")
    .option("--format <format>", "text or json", "text")
    .option("--out <file>", "write the report to a file instead of stdout")
    .action((target: string, opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      let identifier: string;
      try {
        identifier = normalizeDomain(target);
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }
      if (opts.format !== "text" && opts.format !== "json") {
        return fail(`invalid --format "${opts.format}" (expected: text, json)`);
      }

      const asset = storage.getAssetByIdentifier(identifier);
      if (!asset) return fail(`unknown asset "${identifier}"`);

      const scans = storage.listScans(asset.id, 10).filter((s) => s.status === "completed");
      const scan = scans[0];
      if (!scan) {
        return fail(`no completed scan for ${identifier} yet — run: dlos scan ${identifier}`);
      }

      const findings = storage
        .listFindings({ assetId: asset.id, statuses: ["open", "in_progress", "accepted", "resolved"] })
        .filter((f) => f.lastSeenScanId === scan.id || f.resolvedScanId === scan.id);
      const observations = storage.listObservations(scan.id);
      const passes = derivePasses(observations);
      const erroredChecks = observations
        .filter((o) => o.error !== undefined)
        .map((o) => ({ checkId: o.checkId, error: o.error as string }));
      const events = storage.eventsForAsset(asset.id, 500).filter((e) => e.scanId === scan.id);

      const report = buildReport({ asset, scan, findings, passes, erroredChecks, events });

      if (opts.out) {
        writeFileSync(opts.out, serializeReportJson(report), "utf8");
        console.log(`✔ report written to ${opts.out}`);
        return;
      }

      if (opts.format === "json") {
        // Machine mode: stdout carries JSON and nothing else.
        console.log(serializeReportJson(report));
        return;
      }
      console.log(renderReport(report));
      note("JSON: dlos report <domain> --format json --out report.json");
    });
}

/** Re-derive "verified" entries from stored observations (deterministic, no re-scan needed). */
function derivePasses(observations: Observation[]): PassResult[] {
  const passes: PassResult[] = [];
  for (const obs of observations) {
    if (obs.data === undefined || obs.error !== undefined) continue;
    const descriptor = passCatalog[obs.checkId];
    if (!descriptor) continue;
    try {
      for (const p of descriptor.describe(obs.data)) {
        passes.push({ checkId: obs.checkId, title: p.title, text: p.text });
      }
    } catch {
      // best-effort
    }
  }
  return passes;
}
