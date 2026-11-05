import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { HeadersObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

function headersData(ctx: Parameters<Rule["evaluate"]>[0]): HeadersObservation | null {
  const obs = firstObservation(ctx, "http.headers");
  if (!obs || obs.error !== undefined || obs.data === undefined) return null;
  return obs.data as unknown as HeadersObservation;
}

function makeCookieRule(spec: {
  id: string;
  subject: string;
  flag: "secure" | "httponly" | "samesite";
  severity: "low" | "info";
  title: string;
  impact: string;
  recommendation: string;
}): Rule {
  return {
    id: spec.id,
    consumes: ["http.headers"],
    evaluate(ctx) {
      const d = headersData(ctx);
      if (!d || !Array.isArray(d.cookies) || d.cookies.length === 0) return [];
      const missing = d.cookies.filter((c) => !c[spec.flag]).length;
      if (missing === 0) return [];
      return [
        draft({
          subject: spec.subject,
          checkId: "http.headers",
          severity: spec.severity,
          confidence: "high",
          actionability: "planned",
          title: spec.title.replace("{n}", String(missing)),
          detail: {
            observation: `${missing} of ${d.cookies.length} cookie(s) lack the \`${spec.flag}\` attribute. Only flag presence is recorded, never cookie names or values.`,
            evidence: evidenceOf(ctx, "http.headers"),
            impact: spec.impact,
            confidence: "high",
            recommendation: spec.recommendation,
            verification: `Set the attribute on all cookies, reload, then re-run \`dlos scan\`. ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    },
  };
}

export const cookieSecureRule = makeCookieRule({
  id: "cookie-secure",
  subject: "cookie-secure",
  flag: "secure",
  severity: "low",
  title: "{n} cookie(s) sent without the Secure flag",
  impact:
    "Those cookies travel over plain HTTP if the user ever follows an http:// link, exposing session material on shared networks.",
  recommendation: "Add `Secure` to every Set-Cookie; with HSTS enforced, Secure-only cookies are the norm anyway.",
});

export const cookieHttpOnlyRule = makeCookieRule({
  id: "cookie-httponly",
  subject: "cookie-httponly",
  flag: "httponly",
  severity: "low",
  title: "{n} cookie(s) sent without HttpOnly",
  impact:
    "Scripts (including any injected one) can read those cookies via document.cookie, so an XSS can exfiltrate session identifiers.",
  recommendation: "Add `HttpOnly` to every cookie that the frontend does not strictly need to read.",
});

export const cookieSameSiteRule = makeCookieRule({
  id: "cookie-samesite",
  subject: "cookie-samesite",
  flag: "samesite",
  severity: "info",
  title: "{n} cookie(s) sent without SameSite",
  impact:
    "Without SameSite, browsers may attach those cookies on cross-site requests, which is exactly what CSRF relies on.",
  recommendation: "Set `SameSite=Lax` (or Strict for sensitive cookies) on every cookie.",
});
