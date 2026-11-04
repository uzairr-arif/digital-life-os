import type { Collector, CollectContext, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";
import { countSetCookies, fetchWithTimeout } from "./httpx";

/**
 * Header capture whitelist — this IS the redaction strategy.
 * Only security-relevant headers are stored; cookie values are never persisted
 * (only their count), so no session material can leak into the database or exports.
 */
export const CAPTURED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "server",
  "x-powered-by",
] as const;

export type CookieFlags = {
  /** Only flag PRESENCE is recorded — never cookie names, values or domains. */
  secure: boolean;
  httponly: boolean;
  samesite: boolean;
}

export type HeadersObservation = {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookieCount: number;
  cookies?: CookieFlags[];
}

/** Extract only the presence of security flags from Set-Cookie strings. */
export function cookieFlagsOnly(setCookies: string[]): CookieFlags[] {
  return setCookies.map((raw) => {
    const attrs = raw.toLowerCase();
    return {
      secure: /\bsecure\b/.test(attrs),
      httponly: /\bhttponly\b/.test(attrs),
      samesite: /\bsamesite=/i.test(attrs),
    };
  });
}

/** Security headers observed on the HTTPS response (after redirects). */
export const headersCollector: Collector = {
  id: "http-headers",
  checkIds: ["http.headers"],
  async run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const domain = ctx.asset.identifier;
    try {
      const res = await fetchWithTimeout(ctx.fetch, `https://${domain}/`, {
        redirect: "follow",
        timeoutMs: ctx.timeoutMs,
      });
      const headers: Record<string, string> = {};
      for (const name of CAPTURED_HEADERS) {
        const value = res.headers.get(name);
        if (value !== null) headers[name] = value;
      }
      const data: HeadersObservation = {
        url: res.url || `https://${domain}/`,
        status: res.status,
        headers,
        setCookieCount: countSetCookies(res),
        cookies: cookieFlagsOnly(getSetCookieList(res)),
      };
      return [{ checkId: "http.headers", data }];
    } catch (err) {
      return [{ checkId: "http.headers", error: errorText(err) }];
    }
  },
};

function getSetCookieList(res: Response): string[] {
  try {
    const h = res.headers as Headers & { getSetCookie?: () => string[] };
    if (typeof h.getSetCookie === "function") return h.getSetCookie();
  } catch {
    // fall through
  }
  const v = res.headers.get("set-cookie");
  return v ? [v] : [];
}
