import type {
  Asset,
  AssetInput,
  Finding,
  FindingEvent,
  FindingStatus,
  Observation,
  Scan,
  Severity,
} from "./types";

export interface AssetPatch {
  label?: string;
  group?: string;
  dkimSelectors?: string[];
  active?: boolean;
}

export interface FindingPatch {
  severity?: Finding["severity"];
  title?: string;
  detail?: Finding["detail"];
  actionability?: Finding["actionability"];
  status?: FindingStatus;
  statusNote?: string | undefined;
  priorityScore?: number;
  lastSeenAt?: string;
  lastSeenScanId?: string | undefined;
  resolvedAt?: string | undefined;
  resolvedScanId?: string | undefined;
}

export interface FindingsFilter {
  assetId?: string;
  statuses?: FindingStatus[];
  minSeverity?: Severity;
  limit?: number;
}

/**
 * Local persistence port. Implementations are synchronous (SQLite) —
 * the engine's asynchrony comes from the network, not the database.
 */
export interface Storage {
  // Assets
  insertAsset(asset: Asset): void;
  getAsset(assetId: string): Asset | null;
  getAssetByIdentifier(identifier: string): Asset | null;
  listAssets(): Asset[];
  updateAsset(assetId: string, patch: AssetPatch): void;
  deleteAssetDeep(assetId: string): void;
  setAssetChecked(assetId: string, checkedAt: string): void;

  // Scans
  createScan(scan: Scan): void;
  updateScan(scan: Scan): void;
  getScan(scanId: string): Scan | null;
  listScans(assetId: string, limit?: number): Scan[];

  // Observations
  insertObservations(observations: Observation[]): void;
  listObservations(scanId: string): Observation[];

  // Findings
  insertFinding(finding: Finding): void;
  updateFinding(findingId: string, patch: FindingPatch): void;
  getFinding(findingId: string): Finding | null;
  findingByFingerprint(assetId: string, fingerprint: string): Finding | null;
  listFindings(filter: FindingsFilter): Finding[];

  // Events
  insertEvents(events: FindingEvent[]): void;
  eventsForFinding(findingId: string): FindingEvent[];
  eventsForAsset(assetId: string, limit?: number): FindingEvent[];
}

export type { AssetInput };
