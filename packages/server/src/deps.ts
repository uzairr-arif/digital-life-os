import { defaultCollectors, defaultResolver } from "@dlos/collectors";
import type { ScanDeps, ScanResult, Storage } from "@dlos/core";
import { runScan } from "@dlos/core";
import { allRules, passCatalog } from "@dlos/rules";

/** Real-network scan dependencies, shared by the CLI, the dashboard and Electron. */
export function createScanDeps(storage: Storage, timeoutMs = 12_000): ScanDeps {
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

export { runScan };
export type { ScanResult };
