import type { PassCatalog } from "@dlos/core";
import type {
  DnsObservation,
  HeadersObservation,
  HttpsReachabilityObservation,
  RedirectObservation,
  TlsObservation,
  SpfObservation,
  DmarcObservation,
  DkimObservation,
  SecurityTxtObservation,
} from "@dlos/collectors";
import { parseDmarc, parseSpf } from "./parsers";

/**
 * Pass descriptions — how healthy checks appear in reports.
 * Same principle as findings: show the evidence ("what was verified"),
 * not just a green tick.
 */
export const passCatalog: PassCatalog = {
  "dns.records": {
    describe: (data) => {
      const d = data as unknown as DnsObservation;
      const parts: string[] = [];
      const count = (v: unknown): number | null => (Array.isArray(v) ? v.length : null);
      const a = count(d.A);
      const aaaa = count(d.AAAA);
      const mx = count(d.MX);
      const ns = count(d.NS);
      if (a !== null) parts.push(`A: ${a}`);
      if (aaaa !== null) parts.push(`AAAA: ${aaaa}`);
      if (mx !== null) parts.push(`MX: ${mx}`);
      if (ns !== null) parts.push(`NS: ${ns}`);
      if (parts.length === 0) return [];
      return [{ title: "DNS records resolved", text: parts.join(" · ") }];
    },
  },
  "http.redirect": {
    describe: (data) => {
      const d = data as unknown as RedirectObservation;
      if (!d.redirectsToHttps) return [];
      return [
        {
          title: "HTTPS redirect verified",
          text: `HTTP ${d.status} → ${d.location}`,
        },
      ];
    },
  },
  "http.https": {
    describe: (data) => {
      const d = data as unknown as HttpsReachabilityObservation;
      if (d.status >= 400) return [];
      return [{ title: "HTTPS reachable", text: `https://${new URL(d.url).host} responded ${d.status}` }];
    },
  },
  "tls.certificate": {
    describe: (data) => {
      const d = data as unknown as TlsObservation;
      const out: { title: string; text: string }[] = [];
      if (d.authorized) {
        const days = d.certificate.daysRemaining;
        out.push({
          title: "TLS certificate trusted",
          text: `issuer: ${d.certificate.issuerOrg ?? d.certificate.issuerCn ?? "unknown"} · expires ${d.certificate.validToIso?.slice(0, 10) ?? "?"}${days !== null ? ` (${days} days)` : ""}`,
        });
      }
      if (d.protocol && /^TLSv1\.[23]$/.test(d.protocol)) {
        out.push({ title: "Modern TLS protocol", text: `negotiated ${d.protocol}` });
      }
      return out;
    },
  },
  "http.headers": {
    describe: (data) => {
      const d = data as unknown as HeadersObservation;
      const out: { title: string; text: string }[] = [];
      const h = d.headers;
      const push = (present: boolean, title: string, text: string): void => {
        if (present) out.push({ title, text });
      };
      push(
        h["strict-transport-security"] !== undefined,
        "HSTS enabled",
        h["strict-transport-security"] ?? "",
      );
      push(
        h["content-security-policy"] !== undefined,
        "Content-Security-Policy present",
        h["content-security-policy"]!.length > 80
          ? `${h["content-security-policy"]!.slice(0, 77)}…`
          : h["content-security-policy"]!,
      );
      push(
        h["x-content-type-options"] !== undefined,
        "nosniff enabled",
        h["x-content-type-options"] ?? "",
      );
      push(h["referrer-policy"] !== undefined, "Referrer-Policy present", h["referrer-policy"] ?? "");
      push(
        h["permissions-policy"] !== undefined,
        "Permissions-Policy present",
        h["permissions-policy"] ?? "",
      );
      return out;
    },
  },
  "email.spf": {
    describe: (data) => {
      const d = data as unknown as SpfObservation;
      if (d.lookupError !== undefined) return [];
      const parsed = parseSpf(d.records);
      if (!parsed) return [];
      const qualifier = parsed.qualifierAll
        ? parsed.qualifierAll === "-all"
          ? "hardfail (-all)"
          : parsed.qualifierAll === "~all"
            ? "softfail (~all)"
            : parsed.qualifierAll === "?all"
              ? "neutral (?all)"
              : "pass-all (+all)"
        : "no all-mechanism";
      return [{ title: "SPF record published", text: qualifier }];
    },
  },
  "email.dmarc": {
    describe: (data) => {
      const d = data as unknown as DmarcObservation;
      if (d.lookupError !== undefined) return [];
      const parsed = parseDmarc(d.records);
      if (!parsed) return [];
      if (parsed.policy === "quarantine" || parsed.policy === "reject") {
        return [{ title: "DMARC enforcement enabled", text: `p=${parsed.policy}` }];
      }
      return [];
    },
  },
  "email.dkim": {
    describe: (data) => {
      const d = data as unknown as DkimObservation;
      if (d.skipped) return [];
      return d.selectors
        .filter((s) => s.records !== null && s.records.length > 0)
        .map((s) => ({
          title: "DKIM record found",
          text: `selector "${s.selector}" published`,
        }));
    },
  },
  "web.securitytxt": {
    describe: (data) => {
      const d = data as unknown as SecurityTxtObservation;
      if (!d.found || !d.hasContact) return [];
      return [
        {
          title: "security.txt published",
          text: `Contact field present${d.hasExpires ? " · Expires present" : ""}`,
        },
      ];
    },
  },
};
