import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { SecurityTxtObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

function securityTxtData(ctx: Parameters<Rule["evaluate"]>[0]): SecurityTxtObservation | null {
  const obs = firstObservation(ctx, "web.securitytxt");
  if (!obs || obs.error !== undefined || obs.data === undefined) return null;
  return obs.data as unknown as SecurityTxtObservation;
}

/** RFC 9116: security.txt tells researchers where to report issues. Absence is an informational gap. */
export const securityTxtRule: Rule = {
  id: "web-securitytxt",
  consumes: ["web.securitytxt"],
  evaluate(ctx) {
    const d = securityTxtData(ctx);
    if (!d) return []; // check failed or inconclusive → silent

    if (!d.found) {
      return [
        draft({
          subject: "record",
          checkId: "web.securitytxt",
          severity: "info",
          confidence: "high",
          actionability: "planned",
          title: "No security.txt published",
          detail: {
            observation: `No security.txt was found at /.well-known/security.txt or /security.txt on ${ctx.asset.identifier}.`,
            evidence: evidenceOf(ctx, "web.securitytxt"),
            impact:
              "Researchers who find a security issue have no documented channel to report it, so reports may arrive late, via social media, or never.",
            confidence: "high",
            recommendation:
              "Publish /.well-known/security.txt with at least Contact and Expires fields (see RFC 9116). Point Contact at a monitored inbox or your vulnerability-reporting process.",
            verification:
              "The file should return HTTP 200 at /.well-known/security.txt; re-run `dlos scan` and this check moves to 'verified'. " +
              VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    if (!d.hasContact) {
      return [
        draft({
          subject: "no-contact",
          checkId: "web.securitytxt",
          severity: "low",
          confidence: "high",
          actionability: "planned",
          title: "security.txt exists but has no Contact field",
          detail: {
            observation: `A security.txt file was found${d.url ? ` at ${d.url}` : ""}, but it declares no Contact field, which RFC 9116 marks as required.`,
            evidence: evidenceOf(ctx, "web.securitytxt"),
            impact: "The file cannot serve its purpose: there is no address for researchers to write to.",
            confidence: "high",
            recommendation: "Add a `Contact:` line (mailto: or https://) and an `Expires:` line while you are at it.",
            verification: "Update the file and re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    return [];
  },
};
