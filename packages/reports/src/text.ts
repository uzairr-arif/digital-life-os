import chalk from "chalk";
import type {
  Asset,
  Finding,
  FindingEvent,
  Scan,
} from "@dlos/core";
import { rankFindings } from "@dlos/core";
import type { ReportJson } from "./report";

const SEV_STYLE: Record<Finding["severity"], (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow.bold(s),
  low: (s) => chalk.cyan(s),
  info: (s) => chalk.gray(s),
};

const CHANGE_LABEL: Record<string, string> = {
  new: chalk.green("new"),
  recurring: chalk.gray("recurring"),
  resolved: chalk.greenBright("resolved"),
  regressed: chalk.red("regressed"),
  status_changed: chalk.gray("status"),
};

export function sevLabel(severity: Finding["severity"]): string {
  return SEV_STYLE[severity](severity.toUpperCase().padEnd(8));
}

export function fmtDate(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function relDays(iso: string, now = Date.now()): string {
  const days = Math.floor((now - new Date(iso).getTime()) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "1 day";
  return `${days} days`;
}

function truncate(s: string, max: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

// ---------------------------------------------------------------- scan report

export function renderReport(report: ReportJson): string {
  const lines: string[] = [];
  const { asset, scan, summary, findings, passes, erroredChecks } = report;

  lines.push(chalk.bold(`dlos report — ${asset.identifier}`));
  lines.push(
    chalk.gray(
      `scan ${scan.id.slice(0, 8)} · ${fmtDate(scan.finishedAt ?? scan.startedAt)} · ${scan.status}`,
    ),
  );
  lines.push("");

  if (summary) {
    const counts = (
      ["critical", "high", "medium", "low", "info"] as const
    )
      .filter((s) => summary.openBySeverity[s] > 0)
      .map((s) => `${summary.openBySeverity[s]} ${s}`)
      .join(", ");
    const openTotal = Object.values(summary.openBySeverity).reduce((a, b) => a + b, 0);
    lines.push(
      openTotal === 0
        ? chalk.green.bold("No open findings.") +
            (summary.acceptedCount > 0 ? chalk.gray(` (${summary.acceptedCount} accepted)`) : "")
        : `${chalk.bold(String(openTotal))} open finding${openTotal === 1 ? "" : "s"} — ${counts}` +
            (summary.acceptedCount > 0 ? chalk.gray(` · ${summary.acceptedCount} accepted`) : ""),
    );
    lines.push(
      chalk.gray(
        `${summary.passCount} check${summary.passCount === 1 ? "" : "s"} verified · ${summary.checksRun} ran · ${summary.checksErrored} errored`,
      ),
    );
    lines.push("");
  }

  const ranked = rankFindings(findings);

  if (ranked.length > 0) {
    lines.push(chalk.bold("Findings (by priority)"));
    lines.push("");
    ranked.forEach((f, i) => {
      const change = f.change ? ` ${CHANGE_LABEL[f.change] ?? ""}` : "";
      lines.push(
        `${chalk.gray(`${String(i + 1).padStart(2)}.`)} ${sevLabel(f.severity)}  ${chalk.bold(f.title)}${change}`,
      );
      lines.push(chalk.gray(`    rule ${f.ruleId} · score ${f.priorityScore} · status ${f.status}${f.statusNote ? ` (${f.statusNote})` : ""} · first seen ${relDays(f.firstSeenAt)}`));
      lines.push(`    ${chalk.bold("Observed:")} ${truncate(f.detail.observation, 200)}`);
      lines.push(`    ${chalk.bold("Impact:  ")} ${truncate(f.detail.impact, 200)}`);
      lines.push(`    ${chalk.bold("Fix:     ")} ${truncate(f.detail.recommendation, 200)}`);
      lines.push(`    ${chalk.bold("Verify:  ")} ${truncate(f.detail.verification, 200)}`);
      lines.push(
        chalk.gray(
          `    Evidence: ${f.checkId} · confidence ${f.detail.confidence} · ${truncate(JSON.stringify(f.detail.evidence), 140)}`,
        ),
      );
      if (f.status === "resolved") {
        lines.push(chalk.green(`    ✔ marked resolved ${fmtDate(f.resolvedAt)}`));
      }
      lines.push("");
    });
  } else if (passes.length > 0 || erroredChecks.length > 0) {
    lines.push(chalk.bold("Findings"));
    lines.push("");
    lines.push(chalk.green("  None. Everything checked came back clean."));
    lines.push("");
  }

  if (passes.length > 0) {
    lines.push(chalk.bold("Verified (checks that passed)"));
    for (const p of passes) {
      lines.push(`  ${chalk.green("✔")} ${chalk.bold(p.title)} — ${chalk.gray(truncate(p.text, 110))}`);
    }
    lines.push("");
  }

  if (erroredChecks.length > 0) {
    lines.push(chalk.bold("Checks that could not run"));
    for (const e of erroredChecks) {
      lines.push(`  ${chalk.yellow("⚠")} ${chalk.bold(e.checkId)} — ${chalk.gray(truncate(e.error, 110))}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ------------------------------------------------------------------ scan list

export function renderScansTable(scans: Scan[]): string {
  const lines: string[] = [chalk.bold("Scans"), ""];
  if (scans.length === 0) {
    lines.push(chalk.gray("  no scans yet — run `dlos scan <domain>`"));
    return lines.join("\n");
  }
  for (const s of scans) {
    const sum = s.summary;
    const open = sum
      ? Object.values(sum.openBySeverity).reduce((a, b) => a + b, 0)
      : null;
    const detail = sum
      ? ` · ${open ?? 0} open, ${sum.passCount} passed, ${sum.checksErrored} errored`
      : "";
    lines.push(
      `  ${chalk.gray(s.id.slice(0, 8))}  ${fmtDate(s.finishedAt ?? s.startedAt)}  ${s.status}${detail}`,
    );
  }
  return lines.join("\n");
}

export function renderEvents(events: FindingEvent[], titles: Map<string, string>): string {
  const lines: string[] = [chalk.bold("Change history"), ""];
  if (events.length === 0) {
    lines.push(chalk.gray("  no recorded changes yet"));
    return lines.join("\n");
  }
  for (const e of events) {
    const label = CHANGE_LABEL[e.event] ?? e.event;
    const title = titles.get(e.findingId) ?? e.findingId.slice(0, 8);
    const detail = e.detail ? chalk.gray(` — ${truncate(e.detail, 90)}`) : "";
    lines.push(`  ${chalk.gray(fmtDate(e.at))}  ${label.padEnd(11)} ${truncate(title, 70)}${detail}`);
  }
  return lines.join("\n");
}

// ------------------------------------------------------------ findings table

export function renderFindingsTable(findings: Finding[]): string {
  const lines: string[] = [chalk.bold("Findings (by priority)"), ""];
  if (findings.length === 0) {
    lines.push(chalk.green("  no findings match the current filters"));
    return lines.join("\n");
  }
  const ranked = rankFindings(findings);
  for (const f of ranked) {
    lines.push(
      `  ${sevLabel(f.severity)}  ${chalk.bold(truncate(f.title, 64))}`,
    );
    lines.push(
      chalk.gray(
        `          ${f.id.slice(0, 8)} · ${f.assetId.slice(0, 8)} · status ${f.status} · score ${f.priorityScore} · seen ${relDays(f.lastSeenAt)}`,
      ),
    );
  }
  return lines.join("\n");
}

export function renderFindingDetail(f: Finding, events: FindingEvent[]): string {
  const lines: string[] = [];
  lines.push(`${sevLabel(f.severity)}  ${chalk.bold(f.title)}`);
  lines.push(chalk.gray(`finding ${f.id}`));
  lines.push("");
  lines.push(`  ${chalk.bold("Status:  ")} ${f.status}${f.statusNote ? chalk.gray(` — ${f.statusNote}`) : ""}`);
  lines.push(`  ${chalk.bold("Rule:    ")} ${f.ruleId} · check ${f.checkId} · score ${f.priorityScore}`);
  lines.push(`  ${chalk.bold("First:   ")} ${fmtDate(f.firstSeenAt)}`);
  lines.push(`  ${chalk.bold("Last:    ")} ${fmtDate(f.lastSeenAt)}${f.resolvedAt ? chalk.gray(` · resolved ${fmtDate(f.resolvedAt)}`) : ""}`);
  lines.push("");
  lines.push(`  ${chalk.bold("Observed:")} ${f.detail.observation}`);
  lines.push(`  ${chalk.bold("Impact:  ")} ${f.detail.impact}`);
  lines.push(`  ${chalk.bold("Fix:     ")} ${f.detail.recommendation}`);
  lines.push(`  ${chalk.bold("Verify:  ")} ${f.detail.verification}`);
  lines.push("");
  lines.push(chalk.bold("Evidence"));
  lines.push(chalk.gray(indent(JSON.stringify(f.detail.evidence, null, 2), 4)));
  if (events.length > 0) {
    lines.push("");
    lines.push(chalk.bold("History"));
    for (const e of events) {
      const label = CHANGE_LABEL[e.event] ?? e.event;
      lines.push(`  ${chalk.gray(fmtDate(e.at))}  ${label}${e.detail ? chalk.gray(` — ${e.detail}`) : ""}`);
    }
  }
  return lines.join("\n");
}

// --------------------------------------------------------------------- assets

export function renderAssetsTable(assets: Asset[], openCounts: Map<string, number>): string {
  const lines: string[] = [chalk.bold("Assets"), ""];
  if (assets.length === 0) {
    lines.push(chalk.gray("  none yet — add one with: dlos asset add example.com --confirm"));
    return lines.join("\n");
  }
  for (const a of assets) {
    const open = openCounts.get(a.id) ?? 0;
    const checked = a.lastCheckedAt ? fmtDate(a.lastCheckedAt) : chalk.gray("never");
    const count = open > 0 ? chalk.yellow(`${open} open`) : chalk.green("clean");
    lines.push(
      `  ${chalk.bold(a.identifier.padEnd(30))} ${count.padEnd(14)} last scan ${checked}${a.group ? chalk.gray(` · group ${a.group}`) : ""}`,
    );
  }
  return lines.join("\n");
}

function indent(text: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return text
    .split("\n")
    .map((l) => pad + l)
    .join("\n");
}
