import type { FetchLike } from "@dlos/core";
import { errorText } from "@dlos/core";

/**
 * Honest user agent: identifies the tool and its purpose.
 * Never pretend to be a browser.
 */
export const USER_AGENT = "dlos-scan/0.1 (local personal security assessment)";

function isAbortLike(err: unknown): boolean {
  return (
    err instanceof Error &&
    (err.name === "AbortError" || err.name === "TimeoutError")
  );
}

/**
 * Fetch with a hard timeout and ONE polite retry for transient network
 * failures (connection resets, sockets dropped mid-handshake).
 * Each attempt gets a FRESH timeout signal; timeout aborts are never retried.
 */
export async function fetchWithTimeout(
  fetchImpl: FetchLike,
  url: string,
  opts: { redirect?: "follow" | "manual" | "error"; timeoutMs: number },
): Promise<Response> {
  const attempt = (): Promise<Response> =>
    fetchImpl(url, {
      redirect: opts.redirect,
      signal: AbortSignal.timeout(opts.timeoutMs),
      headers: {
        "user-agent": USER_AGENT,
        accept: "*/*",
      },
    });
  try {
    return await attempt();
  } catch (err) {
    if (isAbortLike(err)) throw err;
    await new Promise((r) => setTimeout(r, 800));
    return attempt();
  }
}

export { errorText };

/** Count-only access to Set-Cookie — cookie VALUES must never be stored. */
export function countSetCookies(res: Response): number {
  try {
    const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
    if (typeof anyHeaders.getSetCookie === "function") {
      return anyHeaders.getSetCookie().length;
    }
  } catch {
    // fall through
  }
  return res.headers.has("set-cookie") ? 1 : 0;
}
