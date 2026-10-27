/**
 * Shared domain model for Digital Life OS.
 *
 * Every finding is evidence-first: it records what was observed, the raw
 * evidence that produced it, why it matters, and how to verify a fix.
 */

/** JSON-serializable values — every piece of stored evidence must fit this. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Actionability = "immediate" | "planned" | "informational";
export type FindingStatus = "open" | "in_progress" | "accepted" | "resolved";
export type AssetType = "domain";

export interface Asset {
  id: string;
  type: AssetType;
  /** Lower-case canonical identifier, e.g. "example.com". */
  identifier: string;
  label?: string;
  group?: string;
  /** ISO timestamp of the user's ownership/authorization attestation. */
  ownershipConfirmedAt?: string;
  /** Optional DKIM selectors to probe (DKIM is only checked when a selector is known). */
  dkimSelectors: string[];
  createdAt: string;
  lastCheckedAt?: string;
  active: boolean;
}

export interface AssetInput {
  identifier: string;
  type?: AssetType;
  label?: string;
  group?: string;
  ownershipConfirmedAt?: string;
  dkimSelectors?: string[];
}

export interface Scan {
  id: string;
  assetId: string;
  startedAt: string;
  finishedAt?: string;
  status: "running" | "completed" | "failed";
  summary?: ScanSummary;
}

export interface ScanSummary {
  /** Number of observations recorded (one per executed check). */
  checksRun: number;
  /** Number of checks that could not produce a result. */
  checksErrored: number;
  openBySeverity: Record<Severity, number>;
  /** Findings present but explicitly accepted by the user. */
  acceptedCount: number;
  passCount: number;
}

/**
 * A raw measurement taken by a collector during a scan.
 * Observations are the immutable evidence layer; findings are derived from them.
 */
export interface Observation {
  id: string;
  scanId: string;
  assetId: string;
  collectorId: string;
  /** Stable check identifier, e.g. "tls.certificate". */
  checkId: string;
  observedAt: string;
  /** Structured, redacted result of the check. */
  data?: JsonValue;
  /** Set when the check could not produce a result. */
  error?: string;
}

/**
 * What the tool actually detected + why it matters + what to do about it.
 * This is the user-facing contract that makes findings trustworthy.
 */
export interface FindingDetail {
  /** What the tool actually detected, in one or two sentences. */
  observation: string;
  /** Raw result, timestamp and the check that produced it. */
  evidence: JsonValue;
  /** What the issue could mean in practical terms. */
  impact: string;
  /** How certain the tool is about its interpretation. */
  confidence: Confidence;
  /** What the user can do next. */
  recommendation: string;
  /** How to test whether the issue is resolved. */
  verification: string;
}

export interface Finding {
  id: string;
  assetId: string;
  /** Stable hash of (rule, asset, subject) — identifies the same issue across scans. */
  fingerprint: string;
  ruleId: string;
  checkId: string;
  severity: Severity;
  title: string;
  status: FindingStatus;
  statusNote?: string;
  /** How directly the user can act on this finding. */
  actionability: Actionability;
  detail: FindingDetail;
  firstSeenAt: string;
  lastSeenAt: string;
  lastSeenScanId?: string;
  resolvedAt?: string;
  resolvedScanId?: string;
  /** Transparent priority: severity × confidence × actionability (see risk.ts). */
  priorityScore: number;
}

export type FindingEventType =
  | "new"
  | "recurring"
  | "resolved"
  | "regressed"
  | "status_changed";

export interface FindingEvent {
  id: string;
  findingId: string;
  scanId?: string;
  event: FindingEventType;
  detail?: string;
  at: string;
}

/** A check that produced no finding — recorded so reports can show what was verified as healthy. */
export interface PassResult {
  checkId: string;
  title: string;
  text: string;
}

export interface ScanResult {
  scan: Scan;
  /** Findings present in this scan (new, recurring or regressed). */
  findings: Finding[];
  passes: PassResult[];
  erroredChecks: { checkId: string; error: string }[];
  events: FindingEvent[];
}
