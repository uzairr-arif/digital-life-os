import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ScanResult, Storage } from "@dlos/core";
import { buildDigest, rankFindings, severityAtLeast } from "@dlos/core";
import { buildGraph } from "./graph";
import { createScanDeps, runScan } from "./deps";

export interface ServerOptions {
  storage: Storage;
  /** Port to bind; 0 picks a free port (default). */
  port?: number;
  /** Per-check network timeout for scans triggered from the dashboard. */
  timeoutMs?: number;
  /** Override the public dir (tests). */
  publicDir?: string;
}

export interface ServerHandle {
  url: string;
  token: string;
  port: number;
  close(): Promise<void>;
}

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve the dashboard's static assets. The location differs by context:
 *  - running from source:            packages/server/public
 *  - bundled into apps/cli/dist or apps/desktop/dist:
 *                                    ../../../packages/server/public
 *  - a copied public dir next to the bundle
 */
function resolvePublicDir(explicit?: string): string {
  if (explicit) return explicit;
  const candidates = [
    resolve(HERE, "..", "public"),
    resolve(HERE, "..", "..", "..", "packages", "server", "public"),
    resolve(HERE, "public"),
  ];
  for (const candidate of candidates) {
    if (existsSync(join(candidate, "dashboard.html"))) return candidate;
  }
  return candidates[0]!;
}
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".png": "image/png",
  ".json": "application/json; charset=utf-8",
};

function send(res: ServerResponse, code: number, body: string | Buffer, type: string): void {
  res.writeHead(code, {
    "content-type": type,
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
  });
  res.end(body);
}
const json = (res: ServerResponse, code: number, value: unknown): void =>
  send(res, code, JSON.stringify(value), MIME[".json"] ?? "application/json; charset=utf-8");

async function readBody(req: IncomingMessage, limit = 8192): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Local dashboard server. Binds 127.0.0.1 only; reads go through exact-match
 * routes; the single mutating route (scan) requires the per-boot token, which
 * a hostile webpage cannot know - that is the CSRF boundary.
 */
export async function startServer(opts: ServerOptions): Promise<ServerHandle> {
  const { storage } = opts;
  const publicDir = resolvePublicDir(opts.publicDir);
  const timeoutMs = opts.timeoutMs ?? 12_000;
  const token = randomBytes(24).toString("hex");

  const dashboardHtml = existsSync(join(publicDir, "dashboard.html"))
    ? readFileSync(join(publicDir, "dashboard.html"), "utf8").replace("__TOKEN__", token)
    : "<!doctype html><title>dlos</title><p>dashboard assets missing</p>";

  const server: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://127.0.0.1`);
      // NOTE: no path.normalize here - on Windows it rewrites "/" to "\" and
      // every route would miss. Traversal is handled by the static resolver.
      const path = decodeURIComponent(url.pathname);

      // ------------------------------------------------------------ dashboard
      if (req.method === "GET" && path === "/") {
        return send(res, 200, dashboardHtml, MIME[".html"] ?? "text/html; charset=utf-8");
      }

      // ------------------------------------------------------------ static
      if (req.method === "GET" && path.startsWith("/assets/")) {
        const file = resolve(publicDir, path.slice("/assets/".length));
        if (!file.startsWith(resolve(publicDir)) || !existsSync(file)) {
          return json(res, 404, { error: "not found" });
        }
        const type = MIME[file.slice(file.lastIndexOf("."))] ?? "application/octet-stream";
        return send(res, 200, readFileSync(file), type);
      }

      // ------------------------------------------------------------ api: state
      if (req.method === "GET" && path === "/api/state") {
        const assets = storage.listAssets().map((a) => {
          const open = rankFindings(
            storage.listFindings({ assetId: a.id, statuses: ["open", "in_progress"] }),
          );
          const accepted = storage.listFindings({ assetId: a.id, statuses: ["accepted"] });
          const scans = storage.listScans(a.id, 1);
          return {
            ...a,
            openCount: open.length,
            acceptedCount: accepted.length,
            bySeverity: open.reduce<Record<string, number>>((acc, f) => {
              acc[f.severity] = (acc[f.severity] ?? 0) + 1;
              return acc;
            }, {}),
            lastScan: scans[0] ?? null,
          };
        });
        const tracked = rankFindings(
          storage.listFindings({ statuses: ["open", "in_progress", "accepted"] }),
        );
        return json(res, 200, { version: TOOL_VERSION, assets, findings: tracked });
      }

      if (req.method === "GET" && path.startsWith("/api/asset/")) {
        const id = path.slice("/api/asset/".length);
        const asset = storage.getAsset(id);
        if (!asset) return json(res, 404, { error: "unknown asset" });
        return json(res, 200, {
          asset,
          findings: storage.listFindings({ assetId: asset.id, statuses: ["open", "in_progress", "accepted", "resolved"] }),
          events: storage.eventsForAsset(asset.id, 100),
          scans: storage.listScans(asset.id, 10),
        });
      }

      if (req.method === "GET" && path === "/api/graph") {
        const assetId = url.searchParams.get("assetId") ?? undefined;
        return json(res, 200, buildGraph(storage, assetId ?? undefined));
      }

      // ------------------------------------------------------------ api: scan (mutating, token-gated)
      if (req.method === "POST" && path === "/api/scan") {
        if (req.headers["x-dlos-token"] !== token) {
          return json(res, 403, { error: "invalid or missing token" });
        }
        const body = JSON.parse((await readBody(req)) || "{}") as { assetId?: string };
        const deps = createScanDeps(storage, timeoutMs);
        const assets = body.assetId
          ? [storage.getAsset(body.assetId)].filter((a): a is NonNullable<typeof a> => a !== null)
          : storage.listAssets().filter((a) => a.active);
        if (assets.length === 0) return json(res, 404, { error: "no matching asset" });
        const results: { assetId: string; identifier: string; summary: ScanResult["scan"]["summary"]; digest: ReturnType<typeof buildDigest> }[] = [];
        for (const asset of assets) {
          const result = await runScan(deps, asset);
          results.push({
            assetId: asset.id,
            identifier: asset.identifier,
            summary: result.scan.summary,
            digest: buildDigest(result),
          });
        }
        return json(res, 200, { scanned: results.length, results });
      }

      return json(res, 404, { error: "not found" });
    } catch (err) {
      return json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  await new Promise<void>((resolveListen) => server.listen(opts.port ?? 0, "127.0.0.1", resolveListen));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : (opts.port ?? 0);

  return {
    url: `http://127.0.0.1:${port}`,
    token,
    port,
    close: () => new Promise((resolveClose) => server.close(() => resolveClose())),
  };
}

import { TOOL_VERSION } from "./version";

// severityAtLeast is re-exported for consumers wiring --min-severity style options.
export { severityAtLeast };
