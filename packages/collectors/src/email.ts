import type { Collector, CollectContext, JsonValue, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";

/** Join chunked TXT strings into one record text (DNS splits long TXT records). */
function joinTxt(chunks: string[]): string {
  return chunks.join("");
}

export type DkimSelectorResult = {
  selector: string;
  records: string[] | null;
  error?: string;
}

export type SpfObservation = {
  records: string[];
  /** Set when the DNS lookup itself failed (rule must not flag on lookup errors). */
  lookupError?: string;
}

export type DmarcObservation = {
  records: string[];
  lookupError?: string;
}

export type DkimObservation = {
  skipped: boolean;
  reason?: string;
  selectors: DkimSelectorResult[];
}

async function lookupTxtOrError(
  resolver: CollectContext["resolver"],
  name: string,
): Promise<{ records: string[] } | { error: string }> {
  try {
    const chunks = await resolver.resolveTxt(name);
    return { records: chunks.map(joinTxt) };
  } catch (err) {
    return { error: errorText(err) };
  }
}

/**
 * Email-domain protections: SPF, DMARC, and DKIM (only where the user
 * configured selectors — DKIM selectors are unguessable by design).
 */
export const emailCollector: Collector = {
  id: "email",
  checkIds: ["email.spf", "email.dmarc", "email.dkim"],
  async run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const domain = ctx.asset.identifier;
    const out: ObservationDraft[] = [];

    const [spfResult, dmarcResult] = await Promise.all([
      lookupTxtOrError(ctx.resolver, domain),
      lookupTxtOrError(ctx.resolver, `_dmarc.${domain}`),
    ]);

    const spfData: SpfObservation =
      "records" in spfResult
        ? { records: spfResult.records }
        : { records: [], lookupError: spfResult.error };
    out.push({ checkId: "email.spf", data: spfData as JsonValue });

    const dmarcData: DmarcObservation =
      "records" in dmarcResult
        ? { records: dmarcResult.records }
        : { records: [], lookupError: dmarcResult.error };
    out.push({ checkId: "email.dmarc", data: dmarcData as JsonValue });

    const selectors = ctx.asset.dkimSelectors;
    if (selectors.length === 0) {
      const dkimData: DkimObservation = {
        skipped: true,
        reason: "no DKIM selectors configured on this asset",
        selectors: [],
      };
      out.push({ checkId: "email.dkim", data: dkimData as JsonValue });
    } else {
      const results: DkimSelectorResult[] = [];
      for (const selector of selectors) {
        const r = await lookupTxtOrError(ctx.resolver, `${selector}._domainkey.${domain}`);
        if ("records" in r) {
          results.push({ selector, records: r.records });
        } else {
          results.push({ selector, records: null, error: r.error });
        }
      }
      const dkimData: DkimObservation = { skipped: false, selectors: results };
      out.push({ checkId: "email.dkim", data: dkimData as JsonValue });
    }

    return out;
  },
};
