import type {
  Actionability,
  Confidence,
  Finding,
  Severity,
} from "./types";

/**
 * Transparent, deterministic prioritization.
 *
 * priority = severityWeight × confidenceWeight × actionabilityWeight
 *
 * The formula is published on purpose: no opaque 0–100 "security score",
 * no hidden machine learning — a user can recompute any priority by hand.
 */
export const SEVERITY_ORDER: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 60,
  medium: 30,
  low: 10,
  info: 1,
};

export const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  high: 1,
  medium: 0.7,
  low: 0.4,
};

export const ACTIONABILITY_WEIGHT: Record<Actionability, number> = {
  immediate: 1,
  planned: 0.8,
  informational: 0.5,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export function priorityScore(
  severity: Severity,
  confidence: Confidence,
  actionability: Actionability,
): number {
  const raw =
    SEVERITY_WEIGHT[severity] *
    CONFIDENCE_WEIGHT[confidence] *
    ACTIONABILITY_WEIGHT[actionability];
  // Round to one decimal so the number is hand-recomputable.
  return Math.round(raw * 10) / 10;
}

/** Highest-priority first. Ties: higher severity, then oldest finding. */
export function rankFindings<T extends Finding>(findings: T[]): T[] {
  return [...findings].sort((a, b) => {
    if (b.priorityScore !== a.priorityScore) return b.priorityScore - a.priorityScore;
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    return a.firstSeenAt.localeCompare(b.firstSeenAt);
  });
}

export function highestSeverity(findings: Finding[]): Severity | null {
  let best: Severity | null = null;
  for (const f of findings) {
    if (best === null || severityRank(f.severity) > severityRank(best)) {
      best = f.severity;
    }
  }
  return best;
}
