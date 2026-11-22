import type { Finding, JsonValue, Severity, Storage } from "@dlos/core";

/**
 * The relationship graph: assets ─▶ checks ─▶ findings.
 *
 * Check nodes exist for every check that actually produced evidence in the
 * asset's latest completed scan - healthy checks appear too, so the graph
 * shows coverage, not just problems.
 */
export type GraphNodeKind = "asset" | "check" | "finding";

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  /** findings only */
  severity?: Severity;
  status?: string;
  /** findings only */
  ruleId?: string;
  /** assets only */
  identifier?: string;
  /** checks only */
  checkId?: string;
  /** checks only: true when the latest scan for this asset errored on this check */
  errored?: boolean;
}

export interface GraphLink {
  source: string;
  target: string;
  kind: "asset-check" | "check-finding";
}

export interface GraphModel {
  nodes: GraphNode[];
  links: GraphLink[];
}

const TRACKED = ["open", "in_progress", "accepted"] as const;

export function buildGraph(storage: Storage, assetId?: string): GraphModel {
  const assets = storage.listAssets().filter((a) => a.active && (!assetId || a.id === assetId));
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const checkNodeIds = new Set<string>();
  const assetCheckLinks = new Set<string>();

  /** Ensure the asset→check link exists exactly once per pair. */
  const linkAssetCheck = (asset: string, checkNodeId: string): void => {
    const key = `${asset}|${checkNodeId}`;
    if (!assetCheckLinks.has(key)) {
      assetCheckLinks.add(key);
      links.push({ source: `asset:${asset}`, target: checkNodeId, kind: "asset-check" });
    }
  };

  for (const asset of assets) {
    nodes.push({ id: `asset:${asset.id}`, kind: "asset", label: asset.identifier, identifier: asset.identifier });

    const scans = storage.listScans(asset.id, 1).filter((s) => s.status === "completed");
    const latest = scans[0];
    if (latest) {
      for (const obs of storage.listObservations(latest.id)) {
        const nodeId = `check:${asset.id}:${obs.checkId}`;
        if (!checkNodeIds.has(nodeId)) {
          checkNodeIds.add(nodeId);
          nodes.push({
            id: nodeId,
            kind: "check",
            label: obs.checkId,
            checkId: obs.checkId,
            errored: obs.error !== undefined,
          });
        }
        linkAssetCheck(asset.id, nodeId);
      }
    }

    for (const f of storage.listFindings({ assetId: asset.id, statuses: [...TRACKED] })) {
      const nodeId = `finding:${f.id}`;
      nodes.push({
        id: nodeId,
        kind: "finding",
        label: f.title,
        severity: f.severity,
        status: f.status,
        ruleId: f.ruleId,
      });
      const checkNodeId = `check:${asset.id}:${f.checkId}`;
      // findings always attach to their check node; create it if the asset has
      // no completed scan yet (finding imported/seeded without observations)
      if (!checkNodeIds.has(checkNodeId)) {
        checkNodeIds.add(checkNodeId);
        nodes.push({
          id: checkNodeId,
          kind: "check",
          label: f.checkId,
          checkId: f.checkId,
        });
      }
      linkAssetCheck(asset.id, checkNodeId);
      links.push({ source: checkNodeId, target: nodeId, kind: "check-finding" });
    }
  }

  return { nodes, links };
}

/** Small helper for dashboard rendering: severity → display weight. */
export function severityWeight(s: Severity | undefined): number {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return s ? order.indexOf(s) : -1;
}

export type { JsonValue };
