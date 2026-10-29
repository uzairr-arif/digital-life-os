/**
 * Pure parsers for email-protection records. Rules (and tests) interpret
 * raw DNS TXT evidence through these — no network access, no state.
 */

/** Join chunked TXT strings into one record text (DNS splits long TXT records). */
export function joinTxt(chunks: string[]): string {
  return chunks.join("");
}

export type SpfAllQualifier = "-all" | "~all" | "?all" | "+all";

export interface SpfRecord {
  raw: string;
  qualifierAll: SpfAllQualifier | null;
  /** Top-level DNS-consuming mechanisms (include/a/mx/ptr/exists/redirect). */
  lookupCount: number;
}

export function parseSpf(records: string[]): SpfRecord | null {
  const raw = records.find((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!raw) return null;
  const terms = raw.trim().split(/\s+/).slice(1);
  const allTerm = terms.find((t) => /^[~+\-?]all$/i.test(t));
  const qualifierAll = allTerm ? (allTerm.toLowerCase() as SpfAllQualifier) : null;
  const lookupCount = terms.filter((t) =>
    /^(include:|a(?::|$)|mx(?::|$)|ptr(?::|$)|exists:|redirect=)/i.test(t),
  ).length;
  return { raw, qualifierAll, lookupCount };
}

export interface DmarcRecord {
  raw: string;
  policy: "none" | "quarantine" | "reject" | null;
  subdomainPolicy: string | null;
  hasRua: boolean;
  tags: Record<string, string>;
}

export function parseDmarc(records: string[]): DmarcRecord | null {
  const raw = records.find((r) => /^v=DMARC1(\s|;|$)/i.test(r.trim()));
  if (!raw) return null;
  const tags: Record<string, string> = {};
  for (const part of raw.trim().split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    tags[trimmed.slice(0, eq).trim().toLowerCase()] = trimmed.slice(eq + 1).trim();
  }
  const p = (tags.p ?? "").toLowerCase();
  const policy =
    p === "none" || p === "quarantine" || p === "reject" ? (p as DmarcRecord["policy"]) : null;
  return { raw, policy, subdomainPolicy: tags.sp ?? null, hasRua: Boolean(tags.rua), tags };
}
