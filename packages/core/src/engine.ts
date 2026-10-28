import type {
  DomainResolver,
  Collector,
  CollectContext,
  FetchLike,
  ObservationDraft,
} from "./collectors";
import { errorText } from "./collectors";
import { findingFingerprint } from "./fingerprint";
import { newId } from "./ids";
import type { FindingDraft, PassCatalog, Rule } from "./rules";
import type { Storage } from "./ports";
import type {
  Asset,
  Finding,
  FindingEvent,
  FindingStatus,
  Observation,
  PassResult,
  Scan,
  ScanResult,
  Severity,
} from "./types";
import { priorityScore } from "./risk";

export interface ScanDeps {
  storage: Storage;
  collectors: Collector[];
  rules: Rule[];
  passCatalog: PassCatalog;
  fetch: FetchLike;
  resolver: DomainResolver;
  /** Per-collector network timeout. */
  timeoutMs?: number;
  now?: () => Date;
}

const DEFAULT_TIMEOUT_MS = 12_000;

/**
 * Run one full security assessment of an asset:
 *
 *   1. collectors gather observations (evidence layer, immutable)
 *   2. deterministic rules map observations to finding drafts
 *   3. findings are diffed against the previous state:
 *        new / recurring / resolved / regressed
 *   4. healthy checks become "verified" pass results
 *
 * Every step is persisted so history is auditable.
 */
export async function runScan(deps: ScanDeps, asset: Asset): Promise<ScanResult> {
  const now = deps.now ?? (() => new Date());
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const { storage } = deps;

  const scan: Scan = {
    id: newId(),
    assetId: asset.id,
    startedAt: now().toISOString(),
    status: "running",
  };
  storage.createScan(scan);

  // ---------------------------------------------------------------- collectors
  const observations: Observation[] = [];
  const erroredChecks: { checkId: string; error: string }[] = [];

  await Promise.allSettled(
    deps.collectors.map(async (collector: Collector) => {
      const ctx: CollectContext = {
        asset,
        timeoutMs,
        signal: AbortSignal.timeout(timeoutMs),
        fetch: deps.fetch,
        resolver: deps.resolver,
      };
      let drafts: ObservationDraft[];
      try {
        drafts = await collector.run(ctx);
      } catch (err) {
        const message = errorText(err);
        for (const checkId of collector.checkIds) {
          erroredChecks.push({ checkId, error: message });
        }
        return;
      }
      for (const d of drafts) {
        observations.push({
          id: newId(),
          scanId: scan.id,
          assetId: asset.id,
          collectorId: collector.id,
          checkId: d.checkId,
          observedAt: now().toISOString(),
          data: d.data,
          error: d.error,
        });
        if (d.error !== undefined) {
          erroredChecks.push({ checkId: d.checkId, error: d.error });
        }
      }
    }),
  );

  storage.insertObservations(observations);

  // ---------------------------------------------------------------------- rules
  const byCheck = new Map<string, Observation[]>();
  for (const obs of observations) {
    const list = byCheck.get(obs.checkId) ?? [];
    list.push(obs);
    byCheck.set(obs.checkId, list);
  }
  const ruleCtx = { asset, observations: byCheck };

  const trackedStatuses: FindingStatus[] = ["open", "in_progress", "accepted"];
  const existing = storage.listFindings({ assetId: asset.id, statuses: trackedStatuses });
  const byFingerprint = new Map(existing.map((f) => [f.fingerprint, f]));

  const events: FindingEvent[] = [];
  const present: Finding[] = [];
  const presentFingerprints = new Set<string>();

  const addEvent = (
    findingId: string,
    event: FindingEvent["event"],
    at: string,
    detail?: string,
  ): void => {
    events.push({ id: newId(), findingId, scanId: scan.id, event, detail, at });
  };

  for (const rule of deps.rules) {
    let drafts: FindingDraft[];
    try {
      drafts = rule.evaluate(ruleCtx);
    } catch (err) {
      // A crashing rule must never take down a scan.
      erroredChecks.push({ checkId: `rule:${rule.id}`, error: errorText(err) });
      continue;
    }

    for (const d of drafts) {
      const fingerprint = findingFingerprint(rule.id, asset.id, d.subject);
      const seenAt = now().toISOString();
      const score = priorityScore(d.severity, d.detail.confidence, d.actionability);
      const prev = byFingerprint.get(fingerprint);

      if (prev) {
        // Same issue as before: refresh evidence, keep status and history.
        const severityChanged = prev.severity !== d.severity;
        const updated: Finding = {
          ...prev,
          severity: d.severity,
          title: d.title,
          detail: d.detail,
          actionability: d.actionability,
          priorityScore: score,
          lastSeenAt: seenAt,
          lastSeenScanId: scan.id,
        };
        storage.updateFinding(prev.id, {
          severity: updated.severity,
          title: updated.title,
          detail: updated.detail,
          actionability: updated.actionability,
          priorityScore: updated.priorityScore,
          lastSeenAt: updated.lastSeenAt,
          lastSeenScanId: updated.lastSeenScanId,
        });
        addEvent(
          prev.id,
          "recurring",
          seenAt,
          severityChanged ? `severity ${prev.severity} → ${updated.severity}` : undefined,
        );
        present.push(updated);
        presentFingerprints.add(fingerprint);
        continue;
      }

      const prior = storage.findingByFingerprint(asset.id, fingerprint);
      if (prior && prior.status === "resolved") {
        // A resolved finding came back — that is a regression worth shouting about.
        const reopened: Finding = {
          ...prior,
          severity: d.severity,
          title: d.title,
          detail: d.detail,
          actionability: d.actionability,
          priorityScore: score,
          status: "open",
          lastSeenAt: seenAt,
          lastSeenScanId: scan.id,
          resolvedAt: undefined,
          resolvedScanId: undefined,
        };
        storage.updateFinding(prior.id, {
          status: "open",
          severity: reopened.severity,
          title: reopened.title,
          detail: reopened.detail,
          actionability: reopened.actionability,
          priorityScore: reopened.priorityScore,
          lastSeenAt: reopened.lastSeenAt,
          lastSeenScanId: reopened.lastSeenScanId,
          resolvedAt: undefined,
          resolvedScanId: undefined,
        });
        addEvent(prior.id, "regressed", seenAt, "resolved finding reappeared");
        present.push(reopened);
        presentFingerprints.add(fingerprint);
        continue;
      }

      const created: Finding = {
        id: newId(),
        assetId: asset.id,
        fingerprint,
        ruleId: rule.id,
        checkId: d.checkId,
        severity: d.severity,
        title: d.title,
        status: "open",
        actionability: d.actionability,
        detail: d.detail,
        firstSeenAt: seenAt,
        lastSeenAt: seenAt,
        lastSeenScanId: scan.id,
        priorityScore: score,
      };
      storage.insertFinding(created);
      addEvent(created.id, "new", seenAt);
      present.push(created);
      presentFingerprints.add(fingerprint);
    }
  }

  // Findings that did not reappear are resolved by evidence (fix verification).
  // This includes accepted risks: once the issue is actually gone, "accepted" is moot.
  for (const f of existing) {
    if (presentFingerprints.has(f.fingerprint)) continue;
    const at = now().toISOString();
    storage.updateFinding(f.id, {
      status: "resolved",
      resolvedAt: at,
      resolvedScanId: scan.id,
    });
    addEvent(f.id, "resolved", at, "not observed in latest scan");
  }

  storage.insertEvents(events);

  // --------------------------------------------------------------------- passes
  const passes: PassResult[] = [];
  for (const obs of observations) {
    if (obs.data === undefined || obs.error !== undefined) continue;
    const descriptor = deps.passCatalog[obs.checkId];
    if (!descriptor) continue;
    try {
      for (const p of descriptor.describe(obs.data)) {
        passes.push({ checkId: obs.checkId, title: p.title, text: p.text });
      }
    } catch {
      // Pass descriptions are best-effort; never fail a scan over them.
    }
  }

  // ------------------------------------------------------------------- summary
  const openBySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let acceptedCount = 0;
  for (const f of present) {
    if (f.status === "accepted") {
      acceptedCount++;
      continue;
    }
    openBySeverity[f.severity]++;
  }

  scan.finishedAt = now().toISOString();
  scan.status = "completed";
  scan.summary = {
    checksRun: observations.length,
    checksErrored: erroredChecks.length,
    openBySeverity,
    acceptedCount,
    passCount: passes.length,
  };
  storage.updateScan(scan);
  storage.setAssetChecked(asset.id, scan.finishedAt);

  return { scan, findings: present, passes, erroredChecks, events };
}
