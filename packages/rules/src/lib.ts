import type { FindingDraft, JsonValue, RuleContext } from "@dlos/core";
import { firstObservation } from "@dlos/core";

/**
 * Evidence attached to every finding: the check that produced it,
 * when it was observed, and the (already redacted) raw data.
 */
export function evidenceOf(ctx: RuleContext, checkId: string): JsonValue {
  const obs = firstObservation(ctx, checkId);
  if (!obs) return null;
  return {
    checkId: obs.checkId,
    collectorId: obs.collectorId,
    observedAt: obs.observedAt,
    data: obs.data ?? null,
    error: obs.error ?? null,
  };
}

export type FindingInput = Omit<FindingDraft, never>;

export const VERIFICATION_RESCAN =
  "The next `dlos scan` verifies the fix automatically and marks this finding resolved.";
