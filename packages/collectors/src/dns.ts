import type { Collector, CollectContext, JsonValue, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";

async function safe<T extends JsonValue>(p: Promise<T>): Promise<T | { error: string }> {
  try {
    return await p;
  } catch (err) {
    return { error: errorText(err) };
  }
}

export type DnsObservation = {
  domain: string;
  A?: JsonValue;
  AAAA?: JsonValue;
  MX?: JsonValue;
  NS?: JsonValue;
  TXT?: JsonValue;
  CNAME?: JsonValue;
  CAA?: JsonValue;
}

/**
 * Passive DNS record inventory. Mostly evidence/context for other checks
 * (e.g. CAA presence, MX before SPF interpretation).
 */
export const dnsCollector: Collector = {
  id: "dns",
  checkIds: ["dns.records"],
  async run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const r = ctx.resolver;
    const domain = ctx.asset.identifier;
    const [a, aaaa, mx, ns, txt, cname, caa] = await Promise.all([
      safe(r.resolve4(domain)),
      safe(r.resolve6(domain)),
      safe(r.resolveMx(domain)),
      safe(r.resolveNs(domain)),
      safe(r.resolveTxt(domain)),
      safe(r.resolveCname(domain)),
      safe(r.resolveCaa(domain)),
    ]);
    const data: DnsObservation = {
      domain,
      A: a,
      AAAA: aaaa,
      MX: mx,
      NS: ns,
      TXT: txt,
      CNAME: cname,
      CAA: caa,
    };
    return [{ checkId: "dns.records", data }];
  },
};
