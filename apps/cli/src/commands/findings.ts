import type { Command } from "commander";
import type { Finding, FindingStatus } from "@dlos/core";
import { rankFindings } from "@dlos/core";
import type { SqliteStorage } from "@dlos/storage";
import { renderFindingDetail, renderFindingsTable, fmtDate } from "@dlos/reports";
import { fail, ctxFrom, note, parseSeverity } from "../ui";

const STATUSES: FindingStatus[] = ["open", "in_progress", "accepted", "resolved"];

function parseStatuses(value: string): FindingStatus[] {
  if (value === "all") return [...STATUSES];
  const parts = value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean) as FindingStatus[];
  for (const p of parts) {
    if (!STATUSES.includes(p)) {
      throw new Error(`invalid status "${p}" (expected: ${STATUSES.join(", ")}, all)`);
    }
  }
  return parts;
}

function findingToJson(f: Finding) {
  return {
    id: f.id,
    assetId: f.assetId,
    ruleId: f.ruleId,
    checkId: f.checkId,
    severity: f.severity,
    title: f.title,
    status: f.status,
    statusNote: f.statusNote ?? null,
    priorityScore: f.priorityScore,
    actionability: f.actionability,
    firstSeenAt: f.firstSeenAt,
    lastSeenAt: f.lastSeenAt,
    resolvedAt: f.resolvedAt ?? null,
    detail: f.detail,
  };
}

export function registerFindingsCommands(program: Command): void {
  program
    .command("findings")
    .description("List findings across the inventory")
    .option("--status <statuses>", "comma-separated: open,in_progress,accepted,resolved,all", "open,in_progress")
    .option("--min-severity <severity>", "only findings at or above this severity")
    .option("--asset <identifier>", "limit to one asset")
    .option("--json", "machine-readable JSON output")
    .action((opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const minSeverity = parseSeverity(opts.minSeverity);
      let statuses: FindingStatus[];
      try {
        statuses = parseStatuses(opts.status);
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }

      let assetId: string | undefined;
      if (opts.asset) {
        const found = storage.getAssetByIdentifier(String(opts.asset).toLowerCase().trim());
        if (!found) return fail(`unknown asset "${opts.asset}"`);
        assetId = found.id;
      }

      const findings = rankFindings(
        storage.listFindings({ assetId, statuses, minSeverity: minSeverity ?? undefined }),
      );

      if (opts.json) {
        console.log(JSON.stringify(findings.map(findingToJson), null, 2));
        return;
      }
      console.log(renderFindingsTable(findings));
      note("details: dlos finding show <id>");
    });

  const finding = program.command("finding").description("Inspect and manage a single finding");

  finding
    .command("show <id>")
    .description("Show full detail and history for a finding")
    .option("--json", "machine-readable JSON output")
    .action((id: string, opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const f = storage.getFinding(id) ?? findByIdPrefix(storage, id);
      if (!f) return fail(`unknown finding "${id}"`);
      if (opts.json) {
        console.log(JSON.stringify({ ...findingToJson(f), events: storage.eventsForFinding(f.id) }, null, 2));
        return;
      }
      console.log(renderFindingDetail(f, storage.eventsForFinding(f.id)));
    });

  finding
    .command("status <id> <status>")
    .description("Update a finding's status (open|in_progress|accepted|resolved)")
    .option("--note <note>", "why the status changed")
    .action((id: string, status: string, opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      if (!STATUSES.includes(status as FindingStatus)) {
        return fail(`invalid status "${status}" (expected: ${STATUSES.join(", ")})`);
      }
      const f = storage.getFinding(id) ?? findByIdPrefix(storage, id);
      if (!f) return fail(`unknown finding "${id}"`);
      const at = new Date().toISOString();
      storage.updateFinding(f.id, { status: status as FindingStatus, statusNote: opts.note ?? undefined });
      storage.insertEvents([
        {
          id: crypto.randomUUID(),
          findingId: f.id,
          event: "status_changed",
          detail: `${f.status} → ${status}${opts.note ? ` — ${opts.note}` : ""}`,
          at,
        },
      ]);
      console.log(`✔ finding ${f.id.slice(0, 8)} status: ${f.status} → ${status}`);
      note(
        status === "accepted"
          ? "accepted risks keep their status on rescans while the issue persists; once it is no longer observed, the finding is marked resolved."
          : "the next scan will re-verify this finding against fresh evidence.",
      );
    });
}

/** Accept full UUIDs or unambiguous 8+ char prefixes. */
function findByIdPrefix(storage: SqliteStorage, id: string): Finding | null {
  const direct = storage.getFinding(id);
  if (direct) return direct;
  if (id.length < 8) return null;
  const matches = storage.listFindings({ statuses: [...STATUSES] }).filter((f) => f.id.startsWith(id));
  return matches.length === 1 ? matches[0]! : null;
}
