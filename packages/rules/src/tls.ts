import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { TlsObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";

/** Parses "TLSv1.2" → 1.2 so we can compare protocol versions numerically. */
function tlsVersion(protocol: string): number | null {
  const m = /^TLSv?1\.(\d)$/i.exec(protocol.trim());
  if (m) return Number(m[1]);
  if (/^TLSv?1$/i.test(protocol.trim())) return 0;
  if (/^SSL/i.test(protocol)) return -1;
  return null;
}

/**
 * Certificate health: expired / expiring / not trusted / hostname mismatch.
 * All interpretations are direct observations of the handshake — high confidence.
 */
export const tlsCertificateRule: Rule = {
  id: "tls-certificate",
  consumes: ["tls.certificate"],
  evaluate(ctx) {
    const obs = firstObservation(ctx, "tls.certificate");
    if (!obs || obs.error !== undefined || obs.data === undefined) return [];
    const d = obs.data as unknown as TlsObservation;
    const cert = d.certificate;
    const verification =
      "Re-run `dlos scan` after acting on the certificate. " + VERIFICATION_RESCAN;

    // Expired takes precedence — an expired cert also fails chain validation,
    // and we do not want two findings for one root cause.
    if (cert.daysRemaining !== null && cert.daysRemaining < 0) {
      return [
        draft({
          subject: "certificate",
          checkId: "tls.certificate",
          severity: "critical",
          confidence: "high",
          actionability: "immediate",
          title: "TLS certificate has expired",
          detail: {
            observation: `The certificate for ${d.host} expired on ${cert.validToIso?.slice(0, 10) ?? cert.validTo} (${Math.abs(cert.daysRemaining)} days ago).`,
            evidence: evidenceOf(ctx, "tls.certificate"),
            impact:
              "Browsers and email servers reject the connection outright — visitors see a security warning, and API/integration clients may fail silently.",
            confidence: "high",
            recommendation:
              "Renew the certificate now (e.g. re-run certbot or your CA's renewal flow) and deploy it, then verify the new expiry date appears.",
            verification,
          },
        }),
      ];
    }

    if (cert.daysRemaining !== null && cert.daysRemaining < 14) {
      return [
        draft({
          subject: "certificate",
          checkId: "tls.certificate",
          severity: "high",
          confidence: "high",
          actionability: "immediate",
          title: `TLS certificate expires within ${cert.daysRemaining} day${cert.daysRemaining === 1 ? "" : "s"}`,
          detail: {
            observation: `The certificate for ${d.host} expires on ${cert.validToIso?.slice(0, 10) ?? cert.validTo} (${cert.daysRemaining} days remaining).`,
            evidence: evidenceOf(ctx, "tls.certificate"),
            impact:
              "If it is not renewed in time, every visitor and client loses access with a security warning.",
            confidence: "high",
            recommendation:
              "Renew the certificate (automate this — e.g. certbot timers or your hosting provider's auto-renewal) and confirm the new validity period.",
            verification,
          },
        }),
      ];
    }

    if (cert.daysRemaining !== null && cert.daysRemaining < 30) {
      return [
        draft({
          subject: "certificate",
          checkId: "tls.certificate",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "TLS certificate expires within 30 days",
          detail: {
            observation: `The certificate for ${d.host} expires on ${cert.validToIso?.slice(0, 10) ?? cert.validTo} (${cert.daysRemaining} days remaining).`,
            evidence: evidenceOf(ctx, "tls.certificate"),
            impact: "Renewal is due soon; if renewal is manual, schedule it now.",
            confidence: "high",
            recommendation:
              "Renew the certificate, or confirm auto-renewal is active and has enough lead time.",
            verification,
          },
        }),
      ];
    }

    if (!d.authorized && d.authorizationError !== null) {
      const err = d.authorizationError.toLowerCase();
      const [severity, title, impact, recommendation] = err.includes("altname") ||
        err.includes("hostname") || err.includes("ip address")
        ? ([
            "critical",
            "TLS certificate does not match the domain",
            "The certificate was issued for a different name — browsers reject the connection, and a mismatch like this can also indicate traffic interception.",
            "Issue a certificate that includes this exact hostname (check the SANs), deploy it, and make sure the server presents it.",
          ] as const)
        : err.includes("self-signed")
          ? ([
              "high",
              "TLS certificate is self-signed",
              "There is no trusted third party vouching for the domain, so visitors receive security warnings and man-in-the-middle detection is weakened.",
              "Replace the self-signed certificate with one from a public CA (e.g. Let's Encrypt) unless this host is intentionally internal-only.",
            ] as const)
          : ([
              "high",
              "TLS certificate chain is not trusted",
              "Visitors receive certificate warnings; the chain may be incomplete or issued by an unrecognised CA.",
              "Install the full certificate chain (intermediates included) from your CA and re-test.",
            ] as const);

      return [
        draft({
          subject: "certificate",
          checkId: "tls.certificate",
          severity,
          confidence: "high",
          actionability: "immediate",
          title,
          detail: {
            observation: `The TLS handshake for ${d.host} did not validate: ${d.authorizationError}.`,
            evidence: evidenceOf(ctx, "tls.certificate"),
            impact,
            confidence: "high",
            recommendation,
            verification,
          },
        }),
      ];
    }

    return [];
  },
};

/** Anything below TLS 1.2 is deprecated and increasingly rejected by clients. */
export const tlsProtocolRule: Rule = {
  id: "tls-protocol",
  consumes: ["tls.certificate"],
  evaluate(ctx) {
    const obs = firstObservation(ctx, "tls.certificate");
    if (!obs || obs.error !== undefined || obs.data === undefined) return [];
    const d = obs.data as unknown as TlsObservation;
    if (!d.protocol) return [];
    const version = tlsVersion(d.protocol);
    if (version === null || version >= 2) return [];

    return [
      draft({
        subject: "protocol",
        checkId: "tls.certificate",
        severity: "medium",
        confidence: "high",
        actionability: "planned",
        title: `Outdated TLS protocol negotiated (${d.protocol})`,
        detail: {
          observation: `The handshake with ${d.host} negotiated ${d.protocol}${d.cipher ? ` with cipher ${d.cipher}` : ""}. TLS 1.2 is the minimum acceptable version today.`,
          evidence: evidenceOf(ctx, "tls.certificate"),
          impact:
            "Old protocol versions have known weaknesses and are rejected by modern security tooling and compliance scans.",
          confidence: "high",
          recommendation:
            "Enable TLS 1.2 and 1.3 on the server and disable TLS 1.0/1.1 (and SSL).",
          verification:
            "Re-run `dlos scan` — the 'Modern TLS protocol' check should appear under 'verified'. " +
            VERIFICATION_RESCAN,
        },
      }),
    ];
  },
};
