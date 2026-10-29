import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { DnsObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

/**
 * No CAA record = any certificate authority on the web may issue certificates
 * for the domain. Low severity (most domains live fine without it), but it is
 * the cheapest anti-misissuance control that exists.
 */
export const caaPresentRule: Rule = {
  id: "caa-present",
  consumes: ["dns.records"],
  evaluate(ctx) {
    const obs = firstObservation(ctx, "dns.records");
    if (!obs || obs.error !== undefined || obs.data === undefined) return [];
    const d = obs.data as unknown as DnsObservation;

    let hasCaa: boolean | null = null;
    if (Array.isArray(d.CAA)) {
      hasCaa = (d.CAA as unknown[]).length > 0;
    } else if (d.CAA !== undefined && d.CAA !== null && typeof d.CAA === "object" && "error" in (d.CAA as object)) {
      const error = String((d.CAA as { error: unknown }).error);
      // ENODATA = the domain exists but publishes no CAA records.
      if (error.includes("ENODATA")) hasCaa = false;
      // Other errors (network, SERVFAIL) are inconclusive — never flag on them.
    }
    if (hasCaa !== false) return [];

    return [
      draft({
        subject: "policy",
        checkId: "dns.records",
        severity: "info",
        confidence: "high",
        actionability: "planned",
        title: "No CAA policy published",
        detail: {
          observation: `The domain ${ctx.asset.identifier} publishes no CAA DNS records.`,
          evidence: evidenceOf(ctx, "dns.records"),
          impact:
            "Any certificate authority may issue certificates for this domain. With CAA, you name the CAs allowed to issue — limiting the blast radius of CA compromise or mis-issuance.",
          confidence: "high",
          recommendation:
            "Add a CAA record for CAs you use, e.g. `example.com. IN CAA 0 issue \"letsencrypt.org\"` (plus an `issuewild` entry if you use wildcard certificates).",
          verification:
            "`dig CAA <domain> +short` should return the record; re-run `dlos scan`. " + VERIFICATION_RESCAN,
        },
      }),
    ];
  },
};
