import type { Command } from "commander";
import { normalizeDomain } from "@dlos/core";
import { renderEvents, renderScansTable } from "@dlos/reports";
import { fail, ctxFrom, note } from "../ui";

export function registerHistoryCommand(program: Command): void {
  program
    .command("history <target>")
    .description("Show scan history and what changed for an asset")
    .option("--limit <n>", "number of scans / events to show", "10")
    .option("--json", "machine-readable JSON output")
    .action((target: string, opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      let identifier: string;
      try {
        identifier = normalizeDomain(target);
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }
      const asset = storage.getAssetByIdentifier(identifier);
      if (!asset) return fail(`unknown asset "${identifier}"`);

      const limit = Math.max(1, Math.min(100, Number(opts.limit) || 10));
      const scans = storage.listScans(asset.id, limit);
      const events = storage.eventsForAsset(asset.id, limit * 5);

      if (opts.json) {
        console.log(
          JSON.stringify(
            {
              asset: { id: asset.id, identifier: asset.identifier },
              scans,
              events,
            },
            null,
            2,
          ),
        );
        return;
      }

      console.log(renderScansTable(scans));
      console.log("");
      const titles = new Map<string, string>();
      for (const f of storage.listFindings({ assetId: asset.id, statuses: [...ALL_STATUSES] })) {
        titles.set(f.id, f.title);
      }
      console.log(renderEvents(events, titles));
      note("full detail: dlos report <domain> · dlos finding show <id>");
    });
}

const ALL_STATUSES = ["open", "in_progress", "accepted", "resolved"] as const;
