import { createHash } from "node:crypto";

/**
 * Stable fingerprint identifying "the same issue" across scans:
 * hash(ruleId | assetId | subject). The subject narrows the rule to a
 * concrete target (e.g. a header name, "spf", "dmarc", a DKIM selector).
 *
 * Fingerprints power change detection: new / recurring / resolved / regressed.
 */
export function findingFingerprint(
  ruleId: string,
  assetId: string,
  subject: string,
): string {
  return createHash("sha256")
    .update(`${ruleId}|${assetId}|${subject}`)
    .digest("hex")
    .slice(0, 32);
}
