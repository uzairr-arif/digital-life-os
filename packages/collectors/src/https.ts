import type { Collector, CollectContext, ObservationDraft } from "@dlos/core";
import { errorText } from "@dlos/core";
import { fetchWithTimeout } from "./httpx";

export type RedirectObservation = {
  url: string;
  status: number;
  location: string | null;
  redirectsToHttps: boolean;
}

export type HttpsReachabilityObservation = {
  url: string;
  status: number;
  ok: boolean;
}

/**
 * Two independent checks:
 *  - http.redirect: does plain HTTP hand visitors to HTTPS?
 *  - http.https:    is the HTTPS endpoint itself reachable?
 */
export const httpsCollector: Collector = {
  id: "https",
  checkIds: ["http.redirect", "http.https"],
  async run(ctx: CollectContext): Promise<ObservationDraft[]> {
    const domain = ctx.asset.identifier;
    const out: ObservationDraft[] = [];

    try {
      const res = await fetchWithTimeout(ctx.fetch, `http://${domain}/`, {
        redirect: "manual",
        timeoutMs: ctx.timeoutMs,
      });
      const location = res.headers.get("location");
      const data: RedirectObservation = {
        url: `http://${domain}/`,
        status: res.status,
        location: location,
        redirectsToHttps: location !== null && location.toLowerCase().startsWith("https://"),
      };
      out.push({ checkId: "http.redirect", data });
    } catch (err) {
      out.push({ checkId: "http.redirect", error: errorText(err) });
    }

    try {
      const res = await fetchWithTimeout(ctx.fetch, `https://${domain}/`, {
        redirect: "follow",
        timeoutMs: ctx.timeoutMs,
      });
      const data: HttpsReachabilityObservation = {
        url: `https://${domain}/`,
        status: res.status,
        ok: res.ok,
      };
      out.push({ checkId: "http.https", data });
    } catch (err) {
      out.push({ checkId: "http.https", error: errorText(err) });
    }

    return out;
  },
};
