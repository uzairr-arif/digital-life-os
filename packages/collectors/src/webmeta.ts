import type { Collector, CollectContext, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";
import { fetchWithTimeout } from "./httpx";

export type SecurityTxtObservation = {
  /** RFC 9116 lookup: /.well-known/security.txt with /security.txt fallback. */
  found: boolean;
  url: string | null;
  status: number | null;
  hasContact: boolean;
  hasExpires: boolean;
  isWellKnown: boolean | null;
};

/**
 * security.txt (RFC 9116) — where researchers should report security issues.
 * A plain GET; body is scanned for required FIELDS only, never stored verbatim.
 */
export const securityTxtCollector: Collector = {
  id: "webmeta",
  checkIds: ["web.securitytxt"],
  async run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const domain = ctx.asset.identifier;
    try {
      const wellKnownUrl = `https://${domain}/.well-known/security.txt`;
      const rootUrl = `https://${domain}/security.txt`;
      let res: Response | null = null;
      let usedWellKnown: boolean | null = null;
      let usedUrl: string | null = null;

      try {
        res = await fetchWithTimeout(ctx.fetch, wellKnownUrl, { redirect: "follow", timeoutMs: ctx.timeoutMs });
        usedWellKnown = true;
        usedUrl = wellKnownUrl;
      } catch {
        // fall through to the root path before declaring failure
      }
      if (!res || !res.ok) {
        try {
          res = await fetchWithTimeout(ctx.fetch, rootUrl, { redirect: "follow", timeoutMs: ctx.timeoutMs });
          if (res.ok) {
            usedWellKnown = false;
            usedUrl = rootUrl;
          }
        } catch (err) {
          if (!res) return [{ checkId: "web.securitytxt", error: errorText(err) }];
        }
      }
      if (!res || !res.ok) {
        const data: SecurityTxtObservation = {
          found: false,
          url: null,
          status: res ? res.status : null,
          hasContact: false,
          hasExpires: false,
          isWellKnown: null,
        };
        return [{ checkId: "web.securitytxt", data }];
      }
      const text = await res.text();
      const field = (name: string): boolean =>
        new RegExp(`^${name}\\s*:`, "im").test(text);
      const data: SecurityTxtObservation = {
        found: true,
        url: usedUrl,
        status: res.status,
        hasContact: field("Contact"),
        hasExpires: field("Expires"),
        isWellKnown: usedWellKnown,
      };
      return [{ checkId: "web.securitytxt", data }];
    } catch (err) {
      return [{ checkId: "web.securitytxt", error: errorText(err) }];
    }
  },
};
