import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { RedirectObservation, HttpsReachabilityObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

/**
 * Plain HTTP must hand visitors to HTTPS (ideally 301/308).
 * Missing redirect = users (and form data) can travel unencrypted.
 */
export const httpsRedirectRule: Rule = {
  id: "https-redirect",
  consumes: ["http.redirect"],
  evaluate(ctx) {
    const obs = firstObservation(ctx, "http.redirect");
    if (!obs || obs.error !== undefined || obs.data === undefined) return [];
    const d = obs.data as unknown as RedirectObservation;
    if (d.redirectsToHttps) return [];

    const detail =
      d.location === null && d.status < 400
        ? "The plain-HTTP endpoint responded directly with content (no redirect)."
        : d.location !== null && d.location.toLowerCase().startsWith("http://")
          ? `The plain-HTTP endpoint redirects to another unencrypted location: ${d.location}`
          : `The plain-HTTP endpoint responded with status ${d.status} without redirecting to HTTPS.`;

    return [
      draft({
        subject: "default",
        checkId: "http.redirect",
        severity: "high",
        confidence: "high",
        actionability: "immediate",
        title: "HTTP does not redirect to HTTPS",
        detail: {
          observation: detail,
          evidence: evidenceOf(ctx, "http.redirect"),
          impact:
            "Visitors who type the bare domain (or follow old http:// links) reach an unencrypted version of the site; anyone on the network path can read or alter that traffic.",
          confidence: "high",
          recommendation:
            "Configure the web server to answer http:// with a 301 (or 308) redirect to the https:// URL, and keep the redirect permanent.",
          verification:
            "Open http://<domain>/ in a private window — it should land on https:// without warnings. Then re-run `dlos scan`: the redirect check should move to 'verified'. " +
            VERIFICATION_RESCAN,
        },
      }),
    ];
  },
};

/** The HTTPS endpoint itself must answer. Lookup/handshake errors are reported conservatively. */
export const httpsReachableRule: Rule = {
  id: "https-reachable",
  consumes: ["http.https"],
  evaluate(ctx) {
    const obs = firstObservation(ctx, "http.https");
    if (!obs) return [];

    if (obs.error !== undefined || obs.data === undefined) {
      return [
        draft({
          subject: "default",
          checkId: "http.https",
          severity: "info",
          confidence: "low",
          actionability: "informational",
          title: "HTTPS check could not be completed",
          detail: {
            observation: `The HTTPS endpoint for ${ctx.asset.identifier} could not be verified: ${obs.error ?? "no result"}.`,
            evidence: evidenceOf(ctx, "http.https"),
            impact:
              "Unknown — this is usually a network or connectivity limitation of the machine running the scan, not necessarily a problem with the site.",
            confidence: "low",
            recommendation:
              "Re-run the scan from a network with access to the site. If the site genuinely has no HTTPS, set it up (e.g. via a certificate authority like Let's Encrypt).",
            verification:
              "Confirm https://<domain>/ opens in a browser, then re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    const d = obs.data as unknown as HttpsReachabilityObservation;
    if (d.status >= 500) {
      return [
        draft({
          subject: "default",
          checkId: "http.https",
          severity: "info",
          confidence: "high",
          actionability: "informational",
          title: `HTTPS endpoint returned a server error (${d.status})`,
          detail: {
            observation: `https://${ctx.asset.identifier}/ responded with HTTP ${d.status}.`,
            evidence: evidenceOf(ctx, "http.https"),
            impact:
              "The service is unhealthy at the moment. Other security checks on this response may be unreliable.",
            confidence: "high",
            recommendation: "Check the server/application logs for the failing request.",
            verification: "Re-run `dlos scan` once the service answers normally.",
          },
        }),
      ];
    }
    return [];
  },
};
