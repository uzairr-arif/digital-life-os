import type { Actionability, Confidence, Rule, RuleContext, Severity } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { HeadersObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

/**
 * Returns the headers observation, or null when the check could not run.
 * null means INCONCLUSIVE — rules must stay silent, never flag "missing".
 */
function headersData(ctx: RuleContext): HeadersObservation | null {
  const obs = firstObservation(ctx, "http.headers");
  if (!obs || obs.error !== undefined || obs.data === undefined) return null;
  return obs.data as unknown as HeadersObservation;
}

function headerValue(ctx: RuleContext, name: string): string | null {
  const d = headersData(ctx);
  if (!d) return null;
  const v = d.headers[name.toLowerCase()];
  return v === undefined ? null : v;
}

function parseMaxAge(value: string): number | null {
  const m = /max-age\s*=\s*(\d+)/i.exec(value);
  return m ? Number(m[1]) : null;
}

interface HeaderRuleSpec {
  id: string;
  header: string;
  subject: string;
  severity: Severity;
  confidence: Confidence;
  actionability: Actionability;
  title: string;
  impact: string;
  recommendation: string;
  /** Optional downgrade logic, e.g. when a stronger alternative header exists. */
  downgrade?: (ctx: RuleContext) => { severity: Severity; note: string } | null;
}

const ADD_AND_RESCAN =
  "Add the header in the web server / hosting configuration, reload, then re-run `dlos scan`.";

function makeHeaderRule(spec: HeaderRuleSpec): Rule {
  return {
    id: spec.id,
    consumes: ["http.headers"],
    evaluate(ctx) {
      if (headersData(ctx) === null) return []; // check failed → inconclusive, not "missing"
      const value = headerValue(ctx, spec.header);
      if (value !== null) return [];
      const downgrade = spec.downgrade?.(ctx) ?? null;
      const severity = downgrade ? downgrade.severity : spec.severity;
      const note = downgrade ? ` ${downgrade.note}` : "";
      return [
        draft({
          subject: spec.subject,
          checkId: "http.headers",
          severity,
          confidence: spec.confidence,
          actionability: spec.actionability,
          title: `Missing ${spec.header} header`,
          detail: {
            observation:
              `The HTTPS response did not include a \`${spec.header}\` header.` + note,
            evidence: evidenceOf(ctx, "http.headers"),
            impact: spec.impact,
            confidence: spec.confidence,
            recommendation: spec.recommendation,
            verification: `${ADD_AND_RESCAN} ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    },
  };
}

export const hstsRule: Rule = {
  id: "header-hsts",
  consumes: ["http.headers"],
  evaluate(ctx) {
    if (headersData(ctx) === null) return [];
    const value = headerValue(ctx, "strict-transport-security");
    if (value === null) {
      return [
        draft({
          subject: "hsts",
          checkId: "http.headers",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "Missing strict-transport-security header (HSTS)",
          detail: {
            observation: "The HTTPS response did not include a `strict-transport-security` header.",
            evidence: evidenceOf(ctx, "http.headers"),
            impact:
              "Browsers may still try plain HTTP first (cookies and redirects included), letting an attacker downgrade the connection on open networks.",
            confidence: "high",
            recommendation:
              "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `; preload` only after reviewing the HSTS preload requirements).",
            verification: `${ADD_AND_RESCAN} ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    }
    const maxAge = parseMaxAge(value);
    if (maxAge !== null && maxAge < 15_552_000) {
      return [
        draft({
          subject: "hsts-max-age",
          checkId: "http.headers",
          severity: "low",
          confidence: "high",
          actionability: "planned",
          title: `HSTS max-age is short (${maxAge}s)`,
          detail: {
            observation: `HSTS is enabled but max-age is only ${maxAge} seconds (recommended: at least 15552000 — 180 days).`,
            evidence: evidenceOf(ctx, "http.headers"),
            impact: "The downgrade protection window is too short to be durable for most visitors.",
            confidence: "high",
            recommendation: "Raise max-age to 31536000 (1 year) once you are confident all subdomains serve HTTPS.",
            verification: `Update the header value, reload, then re-run \`dlos scan\`. ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    }
    return [];
  },
};

export const cspRule: Rule = {
  id: "header-csp",
  consumes: ["http.headers"],
  evaluate(ctx) {
    if (headersData(ctx) === null) return [];
    const value = headerValue(ctx, "content-security-policy");
    if (value === null) {
      return [
        draft({
          subject: "csp",
          checkId: "http.headers",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "Missing content-security-policy header (CSP)",
          detail: {
            observation: "The HTTPS response did not include a `content-security-policy` header.",
            evidence: evidenceOf(ctx, "http.headers"),
            impact:
              "CSP is the main mitigation against cross-site scripting and unwanted third-party content injection. Without it, an injected script runs unrestricted.",
            confidence: "high",
            recommendation:
              "Start with a report-only policy (`Content-Security-Policy-Report-Only`) to learn what the page loads, then enforce a policy that begins with `default-src 'self'` and adds the specific sources you need.",
            verification: `${ADD_AND_RESCAN} ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    }
    if (!/default-src/i.test(value)) {
      return [
        draft({
          subject: "csp-default-src",
          checkId: "http.headers",
          severity: "low",
          confidence: "high",
          actionability: "planned",
          title: "CSP is present but has no default-src directive",
          detail: {
            observation: "A `content-security-policy` header was sent, but it does not define `default-src`, so most fallback protections are inactive.",
            evidence: evidenceOf(ctx, "http.headers"),
            impact: "Directive gaps fall back to 'allow', which weakens the policy considerably.",
            confidence: "high",
            recommendation: "Add `default-src 'self'` and extend the policy from there.",
            verification: `Update the policy, reload, then re-run \`dlos scan\`. ${VERIFICATION_RESCAN}`,
          },
        }),
      ];
    }
    return [];
  },
};

export const xContentTypeOptionsRule = makeHeaderRule({
  id: "header-x-content-type-options",
  header: "x-content-type-options",
  subject: "x-content-type-options",
  severity: "low",
  confidence: "high",
  actionability: "planned",
  title: "Missing x-content-type-options header",
  impact:
    "Browsers may sniff file types and execute an uploaded/served file as script even when the Content-Type says otherwise. The fix is one line: `X-Content-Type-Options: nosniff`.",
  recommendation: "Send `X-Content-Type-Options: nosniff` on all responses.",
});

export const xFrameOptionsRule = makeHeaderRule({
  id: "header-x-frame-options",
  header: "x-frame-options",
  subject: "x-frame-options",
  severity: "low",
  confidence: "high",
  actionability: "planned",
  title: "Missing x-frame-options header",
  impact:
    "The page can be embedded in iframes on other sites (clickjacking risk).",
  recommendation:
    "Send `X-Frame-Options: DENY` (or SAMEORIGIN) — or use `frame-ancestors 'none'` in CSP, which supersedes it.",
  downgrade: (ctx) => {
    const csp = headerValue(ctx, "content-security-policy");
    if (csp !== null && /frame-ancestors/i.test(csp)) {
      return { severity: "info", note: "(CSP frame-ancestors already covers framing control.)" };
    }
    return null;
  },
});

export const referrerPolicyRule = makeHeaderRule({
  id: "header-referrer-policy",
  header: "referrer-policy",
  subject: "referrer-policy",
  severity: "low",
  confidence: "high",
  actionability: "planned",
  title: "Missing referrer-policy header",
  impact:
    "Outbound links may leak full URLs (including query strings with tokens or personal data) to third-party sites.",
  recommendation: "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
});

export const permissionsPolicyRule = makeHeaderRule({
  id: "header-permissions-policy",
  header: "permissions-policy",
  subject: "permissions-policy",
  severity: "info",
  confidence: "high",
  actionability: "informational",
  title: "Missing permissions-policy header",
  impact:
    "Powerful browser features (camera, microphone, geolocation, …) are not explicitly restricted, so any embedded third-party content may request them.",
  recommendation:
    "Send a `Permissions-Policy` header that denies features you do not use, e.g. `camera=(), microphone=(), geolocation=()`.",
});
