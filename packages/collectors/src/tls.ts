import tls from "node:tls";
import type { Collector, CollectContext, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";

/** Parse OpenSSL-style GMT date strings ("Nov  3 12:00:00 2026 GMT"). */
export function parseGmtDate(input: string): Date | null {
  const m = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT$/.exec(
    input.replace(/\s+/g, " ").trim(),
  );
  const months: Record<string, number> = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
  };
  if (m) {
    const month = months[m[1] as string];
    if (month !== undefined) {
      return new Date(
        Date.UTC(Number(m[6]), month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])),
      );
    }
  }
  const fallback = new Date(input);
  return Number.isNaN(fallback.getTime()) ? null : fallback;
}

export type TlsObservation = {
  host: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  certificate: {
    subjectCn: string | null;
    issuerOrg: string | null;
    issuerCn: string | null;
    validFrom: string | null;
    validTo: string | null;
    validToIso: string | null;
    daysRemaining: number | null;
    subjectAltName: string | null;
  };
}

/**
 * TLS certificate inspection via a single handshake.
 * `rejectUnauthorized: false` is deliberate: we want to *observe* invalid
 * certificates and report them, not abort the check.
 */
/** Cert DN fields can be string or string[] (multi-value RDNs) — take the first. */
function firstDnValue(v: string | string[] | undefined): string | null {
  if (v === undefined) return null;
  return Array.isArray(v) ? (v[0] ?? null) : v;
}

export const tlsCollector: Collector = {
  id: "tls",
  checkIds: ["tls.certificate"],
  run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const host = ctx.asset.identifier;
    const port = 443;
    return new Promise((resolve) => {
      let settled = false;
      let socket: tls.TLSSocket | undefined;
      let attempts = 0;

      const finish = (draft: ObservationDraft): void => {
        if (settled) return;
        settled = true;
        try {
          socket?.destroy();
        } catch {
          // socket already gone
        }
        resolve([draft]);
      };

      const connect = (): void => {
        attempts++;
        try {
          socket = tls.connect(
            { host, port, servername: host, rejectUnauthorized: false },
            () => {
              try {
                const cert = socket!.getPeerCertificate();
                if (!cert || Object.keys(cert).length === 0) {
                  finish({ checkId: "tls.certificate", error: "no certificate presented" });
                  return;
                }
                const validTo = typeof cert.valid_to === "string" ? cert.valid_to : null;
                const validToDate = validTo ? parseGmtDate(validTo) : null;
                const daysRemaining =
                  validToDate !== null
                    ? Math.floor((validToDate.getTime() - Date.now()) / 86_400_000)
                    : null;
                const data: TlsObservation = {
                  host,
                  port,
                  protocol: socket!.getProtocol() ?? null,
                  cipher: socket!.getCipher()?.name ?? null,
                  authorized: socket!.authorized,
                  authorizationError:
                    typeof socket!.authorizationError === "string"
                      ? socket!.authorizationError
                      : socket!.authorizationError != null
                        ? String(socket!.authorizationError)
                        : null,
                  certificate: {
                    subjectCn: firstDnValue(cert.subject?.CN),
                    issuerOrg: firstDnValue(cert.issuer?.O),
                    issuerCn: firstDnValue(cert.issuer?.CN),
                    validFrom: typeof cert.valid_from === "string" ? cert.valid_from : null,
                    validTo: validTo,
                    validToIso: validToDate ? validToDate.toISOString() : null,
                    daysRemaining,
                    subjectAltName: cert.subjectaltname ?? null,
                  },
                };
                finish({ checkId: "tls.certificate", data });
              } catch (err) {
                finish({ checkId: "tls.certificate", error: errorText(err) });
              }
            },
          );
          socket.setTimeout(ctx.timeoutMs);
          socket.once("error", (err) => {
            // One polite retry for transient drops (e.g. socket reset mid-handshake).
            if (!settled && attempts === 1) {
              try {
                socket?.destroy();
              } catch {
                // already gone
              }
              setTimeout(() => {
                if (!settled) connect();
              }, 800);
              return;
            }
            finish({ checkId: "tls.certificate", error: errorText(err) });
          });
          socket.once("timeout", () => {
            finish({
              checkId: "tls.certificate",
              error: `TLS handshake timed out after ${ctx.timeoutMs}ms`,
            });
          });
        } catch (err) {
          finish({ checkId: "tls.certificate", error: errorText(err) });
        }
      };

      connect();
    });
  },
};
