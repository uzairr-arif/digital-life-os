import { defaultCollectors, defaultResolver } from "@dlos/collectors";
import type { ScanDeps } from "@dlos/core";
import { allRules, passCatalog } from "@dlos/rules";
import { defaultDbPath, openStorage } from "@dlos/storage";
import type { SqliteStorage } from "@dlos/storage";

export interface CliOptions {
  db?: string;
}

export interface CliContext {
  storage: SqliteStorage;
  dbPath: string;
}

/** Lazily opens the database for a command. */
export function openContext(opts: CliOptions): CliContext {
  const dbPath = opts.db ?? defaultDbPath();
  return { storage: openStorage(dbPath), dbPath };
}

/** Real-network scan dependencies: default collectors, all rules, real DNS + fetch. */
export function scanDeps(storage: SqliteStorage, timeoutMs: number): ScanDeps {
  const fetchImpl: ScanDeps["fetch"] = (url, init) => globalThis.fetch(url, init);
  return {
    storage,
    collectors: defaultCollectors,
    rules: allRules,
    passCatalog,
    fetch: fetchImpl,
    resolver: defaultResolver,
    timeoutMs,
  };
}
