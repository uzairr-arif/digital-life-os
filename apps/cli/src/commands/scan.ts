import type { Command } from "commander";
import { runScan, severityAtLeast, normalizeDomain } from "@dlos/core";
import type { Asset } from "@dlos/core";
import { reportFromScanResult, renderReport } from "@dlos/reports";
import { fail, ctxFrom, isActionable, note, parseSeverity } from "../ui";
import { scanDeps } from "../context";

export function registerScanCommand(program: Command): void {
  program
    .command("scan [target]")
    .description(
      "Run a passive security assessment (omit target to scan every active asset)",
    )
    .option(
      "--fail-on <severity>",
      "exit 1 when open findings meet this severity (critical|high|medium|low|info|none)",
      "high",
    )
    .option("--timeout-ms <n>", "per-collector network timeout in milliseconds", "12000")
    .action(async (target: string | undefined, opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const failOn = parseSeverity(opts.failOn);
      const timeoutMs = Number(opts.timeoutMs);
      if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
        return fail("--timeout-ms must be between 1000 and 120000");
      }

      let assets: Asset[];
      if (target) {
        let identifier: string;
        try {
          identifier = normalizeDomain(target);
        } catch (err) {
          return fail(err instanceof Error ? err.message : String(err));
        }
        const found = storage.getAssetByIdentifier(identifier);
        if (!found) {
          return fail(
            `"${identifier}" is not in the inventory — add it first: dlos asset add ${identifier} --confirm`,
          );
        }
        assets = [found];
      } else {
        assets = storage.listAssets().filter((a) => a.active);
        if (assets.length === 0) {
          note("no active assets to scan — add one first: dlos asset add example.com --confirm");
          return;
        }
      }

      const deps = scanDeps(storage, timeoutMs);
      let shouldFail = false;

      for (const asset of assets) {
        const result = await runScan(deps, asset);
        console.log(renderReport(reportFromScanResult(asset, result)));
        if (
          failOn !== null &&
          result.findings.some((f) => isActionable(f) && severityAtLeast(f.severity, failOn))
        ) {
          shouldFail = true;
        }
      }

      if (shouldFail) {
        note(`open findings at or above "${opts.failOn}" severity — exiting 1 (CI-friendly)`);
        process.exitCode = 1;
      }
    });
}
