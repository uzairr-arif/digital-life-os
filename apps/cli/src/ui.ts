import chalk from "chalk";
import type { Command } from "commander";
import type { Finding, Severity } from "@dlos/core";
import { SEVERITY_ORDER } from "@dlos/core";
import { openContext } from "./context";

export function fail(message: string): void {
  console.error(`${chalk.red("error:")} ${message}`);
  process.exitCode = 2;
}

export function note(message: string): void {
  console.error(chalk.gray(message));
}

/** Parse + validate a severity option value; null means "no threshold". */
export function parseSeverity(value: string | undefined): Severity | null {
  if (value === undefined || value === "none") return null;
  if (!(SEVERITY_ORDER as readonly string[]).includes(value)) {
    throw new Error(`invalid severity "${value}" (expected: ${SEVERITY_ORDER.join(", ")}, none)`);
  }
  return value as Severity;
}

export function isActionable(f: Finding): boolean {
  return f.status === "open" || f.status === "in_progress";
}

/**
 * Open the storage using the global --db option.
 * Subcommand opts() only contains the subcommand's own options, so walk the
 * parent chain to find the program-level --db value.
 */
export function ctxFrom(cmd: Command) {
  let db: string | undefined;
  for (let c: Command | null = cmd; c !== null; c = c.parent) {
    const v = (c.opts() as { db?: string }).db;
    if (v !== undefined) {
      db = v;
      break;
    }
  }
  return openContext({ db });
}
