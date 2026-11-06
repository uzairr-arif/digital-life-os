import type { Command } from "commander";
import chalk from "chalk";
import type { ScanResult, Severity } from "@dlos/core";
import {
  buildDigest,
  digestHasSeverity,
  formatDigestJson,
  formatDigestText,
  runScan,
  severityAtLeast,
} from "@dlos/core";
import { fail, ctxFrom, note, parseSeverity } from "../ui";
import { scanDeps } from "../context";

/** "30m" | "6h" | "1d" | "90" (minutes) → milliseconds. */
export function parseIntervalMs(value: string): number | null {
  const m = /^(\d+)\s*(m|min|h|d)?$/i.exec(value.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = (m[2] ?? "m").toLowerCase();
  const mult = unit === "h" ? 3_600_000 : unit === "d" ? 86_400_000 : 60_000;
  return n * mult;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const id = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(id);
        reject(new Error("aborted"));
      },
      { once: true },
    );
  });
}

export function registerWatchCommand(program: Command): void {
  program
    .command("watch")
    .description(
      "Re-scan all assets on a schedule and notify on new or regressed findings. " +
        "Use --once under cron/Task Scheduler instead of a long-running loop.",
    )
    .option("--every <interval>", "recheck interval: 30m | 6h | 1d (default 6h)", "6h")
    .option("--webhook <url>", "POST a JSON digest of notable changes to this URL")
    .option("--min-severity <severity>", "only notify at or above this severity", "info")
    .option("--timeout-ms <n>", "per-collector network timeout in milliseconds", "12000")
    .option("--once", "run a single pass and exit (for OS schedulers)")
    .action(async (opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const minSeverity = parseSeverity(opts.minSeverity);
      const intervalMs = parseIntervalMs(opts.every);
      if (intervalMs === null || intervalMs < 60_000) {
        return fail('--every must be a valid interval of at least 1 minute (e.g. "30m", "6h", "1d")');
      }
      const timeoutMs = Number(opts.timeoutMs);
      if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
        return fail("--timeout-ms must be between 1000 and 120000");
      }

      let notified = 0;
      const runPass = async (): Promise<void> => {
        const assets = storage.listAssets().filter((a) => a.active);
        if (assets.length === 0) {
          note("no active assets to scan — add one: dlos asset add example.com --confirm");
          return;
        }
        const deps = scanDeps(storage, timeoutMs);
        for (const asset of assets) {
          let result: ScanResult;
          try {
            result = await runScan(deps, asset);
          } catch (err) {
            note(`scan failed for ${asset.identifier}: ${err instanceof Error ? err.message : String(err)}`);
            continue;
          }
          let entries = buildDigest(result);
          if (minSeverity !== null && !digestHasSeverity(entries, minSeverity)) {
            entries = entries.filter((e) => severityAtLeast(e.severity, minSeverity as Severity));
          }
          if (entries.length === 0) continue;

          const text = formatDigestText(asset.identifier, entries);
          console.log(chalk.yellow(text));
          notified += entries.length;

          if (opts.webhook) {
            try {
              const res = await fetch(opts.webhook, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(formatDigestJson(asset, result.scan.id, entries)),
                signal: AbortSignal.timeout(10_000),
              });
              if (!res.ok) note(`webhook responded ${res.status} for ${asset.identifier}`);
            } catch (err) {
              note(`webhook failed for ${asset.identifier}: ${err instanceof Error ? err.message : String(err)}`);
            }
          }
        }
      };

      if (opts.once) {
        await runPass();
        if (notified > 0) note(`${notified} notable change${notified === 1 ? "" : "s"} this pass`);
        return;
      }

      const stop = new AbortController();
      let running = false;
      process.on("SIGINT", () => {
        if (running) return; // let the current pass finish
        note("watch stopped");
        process.exit(0);
      });

      console.log(
        chalk.gray(`watching ${storage.listAssets().filter((a) => a.active).length || 0} asset(s) every ${opts.every}`) +
          (opts.webhook ? chalk.gray(` · webhook on`) : "") +
          chalk.gray(" · Ctrl+C to stop"),
      );

      const loop = async (): Promise<void> => {
        for (;;) {
          running = true;
          try {
            await runPass();
          } catch (err) {
            note(`pass failed: ${err instanceof Error ? err.message : String(err)}`);
          }
          running = false;
          try {
            await sleep(intervalMs, stop.signal);
          } catch {
            return;
          }
        }
      };
      await loop();
    });
}
