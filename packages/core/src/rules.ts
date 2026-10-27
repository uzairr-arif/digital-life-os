import type { Asset, JsonValue, Observation } from "./types";
import type { Actionability, Confidence, Severity } from "./types";
import type { FindingDetail } from "./types";

export interface RuleContext {
  asset: Asset;
  /** Observations from the current scan, grouped by checkId. */
  observations: Map<string, Observation[]>;
}

/**
 * A draft finding produced by a rule. The engine assigns identity
 * (id, fingerprint, timestamps, status) and persists it.
 */
export interface FindingDraft {
  /** Stable subject within the rule, e.g. "hsts", "spf", "certificate". */
  subject: string;
  checkId: string;
  severity: Severity;
  confidence: Confidence;
  actionability: Actionability;
  title: string;
  detail: FindingDetail;
}

/** A deterministic rule maps observations to finding drafts. No randomness, no network. */
export interface Rule {
  id: string;
  /** checkIds this rule reads observations from. */
  consumes: string[];
  evaluate(ctx: RuleContext): FindingDraft[];
}

/** Turns a healthy observation into human-readable "verified" entries for reports. */
export interface PassDescriptor {
  describe(data: JsonValue): { title: string; text: string }[];
}

export type PassCatalog = Record<string, PassDescriptor | undefined>;

/** Convenience helper for building drafts. */
export function draft(input: FindingDraft): FindingDraft {
  return input;
}

/** Fetch the first observation recorded for a checkId in the current scan. */
export function firstObservation(
  ctx: RuleContext,
  checkId: string,
): Observation | null {
  return ctx.observations.get(checkId)?.[0] ?? null;
}

/** True when the check ran and produced data (i.e. rules may interpret it). */
export function hasData(ctx: RuleContext, checkId: string): boolean {
  const obs = firstObservation(ctx, checkId);
  return obs !== null && obs.data !== undefined && obs.error === undefined;
}

export function dataOf<T>(obs: Observation | null): T | null {
  if (!obs || obs.data === undefined || obs.error !== undefined) return null;
  return obs.data as T;
}
