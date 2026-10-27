import type { Asset, JsonValue } from "./types";


/** DNS resolver port — injectable so tests never touch the network. */
export interface DomainResolver {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolveNs(name: string): Promise<string[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolveCname(name: string): Promise<string[]>;
  /** CAA records, normalized to JSON-safe objects. */
  resolveCaa(name: string): Promise<JsonValue[]>;
}

/** Minimal fetch port (matches globalThis.fetch structurally). */
export interface FetchLike {
  (
    url: string,
    init?: {
      redirect?: "follow" | "manual" | "error";
      signal?: AbortSignal;
      headers?: Record<string, string>;
    },
  ): Promise<Response>;
}

export interface CollectContext {
  asset: Asset;
  /** Hard timeout for this collector's network work. */
  timeoutMs: number;
  signal: AbortSignal;
  fetch: FetchLike;
  resolver: DomainResolver;
}

/** One check result produced by a collector. */
export interface ObservationDraft {
  checkId: string;
  data?: JsonValue;
  error?: string;
}

/**
 * A collector gathers raw observations for one asset.
 * Collectors must be passive and read-only (no brute force, no exploitation).
 */
export interface Collector {
  id: string;
  checkIds: string[];
  run(ctx: CollectContext): Promise<ObservationDraft[]>;
}

export function errorText(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}
