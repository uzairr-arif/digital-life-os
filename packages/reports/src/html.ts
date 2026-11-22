import type { Finding } from "@dlos/core";
import { rankFindings } from "@dlos/core";
import type { ReportJson } from "./report";

/**
 * Self-contained HTML report: inline styles, system fonts, zero external
 * requests. Safe to share by construction - the report pipeline never
 * includes secrets (header capture is whitelisted, cookie values never stored).
 */

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function esc(s: string | undefined): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

const SEV_COLOR: Record<Finding["severity"], string> = {
  critical: "#DC2626",
  high: "#D97706",
  medium: "#A16207",
  low: "#0284C7",
  info: "#6B7280",
};

export function renderReportHtml(report: ReportJson): string {
  const { asset, scan, summary, passes, erroredChecks } = report;
  const ranked = rankFindings(report.findings);
  const openTotal = summary
    ? Object.values(summary.openBySeverity).reduce((a, b) => a + b, 0)
    : 0;

  const findingBlocks = ranked
    .map(
      (f, i) => `
  <article class="finding sev-${f.severity}">
    <div class="f-head">
      <span class="f-sev">${f.severity}</span>
      <h3>${esc(f.title)}</h3>
      <span class="f-change">${f.change ? esc(f.change) : ""}</span>
    </div>
    <p class="f-meta mono">rule ${esc(f.ruleId)} · check ${esc(f.checkId)} · score ${f.priorityScore} · status ${esc(f.status)}${f.statusNote ? " (" + esc(f.statusNote) + ")" : ""} · first seen ${esc(f.firstSeenAt.slice(0, 10))}</p>
    <dl class="contract">
      <dt>observed</dt><dd>${esc(f.detail.observation)}</dd>
      <dt>impact</dt><dd>${esc(f.detail.impact)}</dd>
      <dt>recommendation</dt><dd>${esc(f.detail.recommendation)}</dd>
      <dt>verification</dt><dd>${esc(f.detail.verification)}</dd>
      <dt>confidence</dt><dd>${esc(f.detail.confidence)}</dd>
    </dl>
    <pre class="evidence">${esc(JSON.stringify(f.detail.evidence, null, 2))}</pre>
    <p class="f-idx">${i + 1} of ${ranked.length}</p>
  </article>`,
    )
    .join("\n");

  const passList = passes.length
    ? `<section><h2>Verified checks</h2><ul class="passes">${passes
        .map((p) => `<li><b>${esc(p.title)}</b> - ${esc(p.text)}</li>`)
        .join("")}</ul></section>`
    : "";

  const errorList = erroredChecks.length
    ? `<section><h2>Checks that could not run</h2><ul class="errors">${erroredChecks
        .map((e) => `<li><b class="mono">${esc(e.checkId)}</b> - ${esc(e.error)}</li>`)
        .join("")}</ul><p class="note">Errored checks are reported as inconclusive; the rules stay silent rather than guess.</p></section>`
    : "";

  const summaryLine = summary
    ? `<p class="summary">${openTotal === 0 ? "No open findings." : `${openTotal} open finding${openTotal === 1 ? "" : "s"}`} · ${summary.passCount} verified · ${summary.checksRun} ran · ${summary.checksErrored} errored${summary.acceptedCount ? ` · ${summary.acceptedCount} accepted` : ""}</p>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dlos report - ${esc(asset.identifier)}</title>
<style>
  :root{--bg:#F6F6F4;--surface:#FFFFFF;--border:#DBDBD6;--text:#15151A;--muted:#55555E;--dim:#82828B;--accent:#0B9E66;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;padding:40px 24px;}
  main{max-width:860px;margin:0 auto;}
  .mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;}
  h1{font-size:26px;letter-spacing:-0.02em;}
  h2{font-size:18px;margin:34px 0 10px;}
  .meta{color:var(--dim);font-size:13px;margin-top:6px;}
  .summary{margin:14px 0 0;font-size:15px;}
  .summary b{color:var(--accent);}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px 24px;margin:14px 0 26px;}
  .finding{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--border);border-radius:12px;padding:18px 22px;margin:14px 0;}
  .finding.sev-critical{border-left-color:${SEV_COLOR.critical};}
  .finding.sev-high{border-left-color:${SEV_COLOR.high};}
  .finding.sev-medium{border-left-color:${SEV_COLOR.medium};}
  .finding.sev-low{border-left-color:${SEV_COLOR.low};}
  .finding.sev-info{border-left-color:${SEV_COLOR.info};}
  .f-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;}
  .f-head h3{font-size:16.5px;}
  .f-sev{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;font-weight:700;text-transform:uppercase;color:#fff;background:${SEV_COLOR.high};border-radius:5px;padding:1px 8px;}
  .finding.sev-critical .f-sev{background:${SEV_COLOR.critical};}
  .finding.sev-medium .f-sev{background:${SEV_COLOR.medium};}
  .finding.sev-low .f-sev{background:${SEV_COLOR.low};}
  .finding.sev-info .f-sev{background:${SEV_COLOR.info};}
  .f-change{margin-left:auto;color:var(--dim);font-size:12px;}
  .f-meta{color:var(--dim);font-size:12px;margin:6px 0 10px;}
  .contract dt{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--accent);margin-top:10px;text-transform:uppercase;letter-spacing:.04em;}
  .contract dd{color:var(--muted);font-size:13.5px;margin-top:2px;}
  .evidence{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px;font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--dim);white-space:pre-wrap;word-break:break-word;margin-top:12px;}
  .f-idx{color:var(--dim);font-size:11px;text-align:right;margin-top:8px;}
  .passes li,.errors li{margin:6px 0 6px 18px;font-size:13.5px;}
  .note{color:var(--dim);font-size:12.5px;margin-top:8px;}
  footer{margin-top:40px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);padding-top:14px;}
</style>
</head>
<body>
<main>
  <h1>dlos report - ${esc(asset.identifier)}</h1>
  <p class="meta">scan ${esc(scan.id.slice(0, 8))} · ${esc(scan.finishedAt || scan.startedAt)} · ${esc(scan.status)} · generated ${esc(report.generatedAt.slice(0, 19).replace("T", " "))}</p>
  <div class="card">${summaryLine}
  <p class="meta">Assets are scanned only after explicit ownership confirmation. All data is local; this file contains no cookies, tokens or secrets.</p>
  </div>
  <section><h2>Findings (by priority)</h2>${ranked.length ? findingBlocks : '<p class="note">No findings.</p>'}</section>
  ${passList}
  ${errorList}
  <footer>dlos v${esc(report.version)} · local-first, evidence-driven personal security · <span class="mono">github.com/uzairr-arif/digital-life-os</span></footer>
</main>
</body>
</html>`;
}
