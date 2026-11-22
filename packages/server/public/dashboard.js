/* dlos local dashboard - vanilla JS, no build step, no external calls.
   Talks only to this 127.0.0.1 server; the scan trigger carries the boot token. */
(function () {
  "use strict";

  var TOKEN = window.__DLOS_TOKEN__;
  var state = {
    route: "overview",
    assets: [],
    findings: [],
    version: "",
    selectedAssetId: null,
    graph: null,
    graphAssetFilter: null,
    _gw: 1400,
    _gh: 520,
    _sel: null,
    _dragged: false,
  };

  // ---------------------------------------------------------------- helpers
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtDate(iso) {
    if (!iso) return "-";
    var d = new Date(iso);
    var p = function (n) { return String(n).padStart(2, "0"); };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  function relDays(iso) {
    if (!iso) return "never";
    var days = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
    if (days <= 0) return "today";
    return days === 1 ? "1 day ago" : days + " days ago";
  }
  /* Severity colors come from CSS variables so both themes stay in sync. */
  function sevColors() {
    var cs = getComputedStyle(document.documentElement);
    return {
      critical: cs.getPropertyValue("--sev-critical").trim(),
      high: cs.getPropertyValue("--sev-high").trim(),
      medium: cs.getPropertyValue("--sev-medium").trim(),
      low: cs.getPropertyValue("--sev-low").trim(),
      info: cs.getPropertyValue("--sev-info").trim(),
    };
  }
  var SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  function toast(msg, isError) {
    var t = $("#toast");
    t.textContent = msg;
    t.classList.toggle("error", Boolean(isError));
    t.hidden = false;
    clearTimeout(t._timer);
    t._timer = setTimeout(function () { t.hidden = true; }, 3600);
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "x-dlos-token": TOKEN }, opts.headers || {});
    return fetch(path, opts).then(function (r) {
      if (!r.ok) return r.json().then(function (j) { throw new Error(j.error || r.status); });
      return r.json();
    });
  }

  // ---------------------------------------------------------------- theme
  function isLight() { return document.documentElement.classList.contains("light"); }
  function applyTheme(light) {
    document.documentElement.classList.toggle("light", light);
    $("#btn-theme").textContent = light ? "Dark theme" : "Light theme";
  }
  $("#btn-theme").addEventListener("click", function () {
    var light = !isLight();
    try { localStorage.setItem("dlos-theme", light ? "light" : "dark"); } catch (e) { /* private mode */ }
    applyTheme(light);
    if (state.route === "graph") drawGraph(); // re-read severity colors
  });
  applyTheme(isLight());

  // ---------------------------------------------------------------- data
  function loadState() {
    return api("/api/state").then(function (s) {
      state.assets = s.assets;
      state.findings = s.findings;
      state.version = s.version;
      $("#version").textContent = "v" + s.version;
      render();
    });
  }

  function scan(assetId, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
    $("#btn-scan-all").disabled = true;
    return api("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(assetId ? { assetId: assetId } : {}),
    }).then(function (r) {
      var notable = 0, regressed = 0;
      r.results.forEach(function (res) {
        notable += res.digest.length;
        regressed += res.digest.filter(function (d) { return d.event === "regressed"; }).length;
      });
      if (notable === 0) toast("Scan complete - nothing new.");
      else toast("Scan complete - " + notable + " notable change" + (notable === 1 ? "" : "s") + (regressed ? " (" + regressed + " regressed)" : "") + ".", regressed > 0);
      return loadState();
    }).catch(function (e) {
      toast("Scan failed: " + e.message, true);
    }).finally(function () {
      $("#btn-scan-all").disabled = false;
    });
  }

  // ---------------------------------------------------------------- routing
  function setRoute(route) {
    state.route = route;
    $$(".nav-btn").forEach(function (b) { b.classList.toggle("active", b.dataset.route === route); });
    render();
  }

  function render() {
    closeDrawer();
    var main = $("#main");
    if (state.route === "overview") renderOverview(main);
    else if (state.route === "graph") { renderGraphShell(main); drawGraph(); }
    else renderHistory(main);
  }

  // ---------------------------------------------------------------- overview
  function renderOverview(main) {
    main.innerHTML =
      '<h2>Overview</h2>' +
      '<p class="kicker">' + state.assets.length + ' asset' + (state.assets.length === 1 ? "" : "s") + ' tracked · ' + state.findings.length + ' open finding' + (state.findings.length === 1 ? "" : "s") + '</p>' +
      '<div class="asset-grid" id="asset-grid"></div>' +
      '<div class="filters">' +
      '<select id="f-sev"><option value="">all severities</option>' + SEV_ORDER.map(function (s) { return '<option value="' + s + '">' + s + '</option>'; }).join("") + '</select>' +
      '<select id="f-status"><option value="">open + accepted</option><option value="open">open</option><option value="in_progress">in progress</option><option value="accepted">accepted</option><option value="resolved">resolved</option></select>' +
      '<input id="f-q" placeholder="Search findings…" type="search">' +
      '</div>' +
      '<table><thead><tr><th></th><th>Finding</th><th>Rule</th><th>Status</th><th>Score</th><th>Seen</th></tr></thead><tbody id="f-rows"></tbody></table>' +
      '<div id="f-empty" class="empty" hidden>Nothing matches the current filters.</div>';

    $("#asset-grid").innerHTML = state.assets.map(function (a) {
      var chips = SEV_ORDER.filter(function (s) { return a.bySeverity[s]; }).map(function (s) {
        return '<span class="sev-chip ' + s + '">' + a.bySeverity[s] + ' ' + s + '</span>';
      }).join("");
      if (!chips) chips = '<span class="sev-chip" style="color:var(--accent);border-color:var(--accent)">clean</span>';
      return '<div class="acard">' +
        '<div class="row1"><span class="ident">' + esc(a.identifier) + '</span>' +
        (a.group ? '<span class="group">' + esc(a.group) + '</span>' : '') + '</div>' +
        '<div class="sevline">' + chips + (a.acceptedCount ? '<span class="sev-chip">' + a.acceptedCount + ' accepted</span>' : '') + '</div>' +
        '<div class="meta"><span>last scan ' + esc(relDays(a.lastCheckedAt)) + '</span>' +
        '<button class="scan-btn" data-asset="' + esc(a.id) + '">Scan</button></div></div>';
    }).join("") || '<div class="empty">No assets yet - add one with <span class="mono">dlos asset add &lt;domain&gt; --confirm</span>.</div>';

    $$("#asset-grid .scan-btn").forEach(function (b) {
      b.addEventListener("click", function () { scan(b.dataset.asset, b); });
    });

    var sevSel = $("#f-sev"), statusSel = $("#f-status"), q = $("#f-q");
    function rows() {
      var minSev = sevSel.value, st = statusSel.value, query = q.value.trim().toLowerCase();
      var list = state.findings.filter(function (f) {
        if (st) { if (f.status !== st) return false; }
        else if (f.status !== "open" && f.status !== "in_progress" && f.status !== "accepted") return false;
        if (minSev && SEV_ORDER.indexOf(f.severity) > SEV_ORDER.indexOf(minSev)) return false;
        if (query && (f.title + " " + f.ruleId).toLowerCase().indexOf(query) === -1) return false;
        return true;
      });
      $("#f-rows").innerHTML = list.map(function (f) {
        var asset = state.assets.find(function (a) { return a.id === f.assetId; });
        return '<tr class="clickable" data-finding="' + esc(f.id) + '">' +
          '<td><span class="sev-dot c-' + f.severity + '"></span><span class="t-' + f.severity + ' mono">' + f.severity + '</span></td>' +
          '<td><b>' + esc(f.title) + '</b><br><span class="mono" style="color:var(--dim);font-size:11.5px">' + esc(asset ? asset.identifier : f.assetId.slice(0, 8)) + '</span></td>' +
          '<td class="mono" style="color:var(--dim);font-size:12px">' + esc(f.ruleId) + '</td>' +
          '<td class="mono" style="font-size:12px">' + esc(f.status) + '</td>' +
          '<td class="mono">' + f.priorityScore + '</td>' +
          '<td style="color:var(--dim)">' + esc(relDays(f.lastSeenAt)) + '</td></tr>';
      }).join("");
      $("#f-empty").hidden = list.length > 0;
      $$("#f-rows tr").forEach(function (tr) {
        tr.addEventListener("click", function () { openFinding(tr.dataset.finding); });
      });
    }
    sevSel.addEventListener("change", rows);
    statusSel.addEventListener("change", rows);
    q.addEventListener("input", rows);
    rows();
  }

  // ---------------------------------------------------------------- drawer
  function openDrawer(title, bodyHtml) {
    $("#drawer-title").innerHTML = title;
    $("#drawer-body").innerHTML = bodyHtml;
    $("#drawer").hidden = false;
  }
  function closeDrawer() { $("#drawer").hidden = true; }
  $("#drawer-close").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });

  function openFinding(id) {
    var f = state.findings.find(function (x) { return x.id === id; });
    if (!f) return;
    openDrawer('<span class="t-' + f.severity + '">' + esc(f.title) + '</span>',
      '<dl class="contract">' +
      '<dt>rule</dt><dd class="mono">' + esc(f.ruleId) + ' · check ' + esc(f.checkId) + ' · score ' + f.priorityScore + '</dd>' +
      '<dt>observation</dt><dd>' + esc(f.detail.observation) + '</dd>' +
      '<dt>impact</dt><dd>' + esc(f.detail.impact) + '</dd>' +
      '<dt>recommendation</dt><dd>' + esc(f.detail.recommendation) + '</dd>' +
      '<dt>verification</dt><dd>' + esc(f.detail.verification) + '</dd>' +
      '<dt>confidence</dt><dd>' + esc(f.detail.confidence) + '</dd>' +
      '<dt>status</dt><dd class="mono">' + esc(f.status) + (f.statusNote ? ' - ' + esc(f.statusNote) : '') + '</dd>' +
      '</dl>' +
      '<div class="evidence">' + esc(JSON.stringify(f.detail.evidence, null, 2)) + '</div>');
    api("/api/asset/" + encodeURIComponent(f.assetId)).then(function (d) {
      var evs = d.events.filter(function (e) { return e.findingId === f.id; });
      var el = document.createElement("div");
      el.innerHTML = '<h3 style="font-size:14px;margin:18px 0 4px;">History</h3>' +
        (evs.length ? '<ul class="timeline">' + evs.map(function (e) {
          return '<li class="k-' + esc(e.event) + '"><div class="t">' + fmtDate(e.at) + '</div><div class="k">' + esc(e.event) + (e.detail ? ' - ' + esc(e.detail) : '') + '</div></li>';
        }).join("") + "</ul>" : '<p class="kicker">no recorded changes</p>');
      $("#drawer-body").appendChild(el);
    });
  }

  // ---------------------------------------------------------------- graph
  function renderGraphShell(main) {
    main.innerHTML =
      '<h2>Relationship graph</h2>' +
      '<p class="kicker">Assets and the checks that produced evidence, and the findings attached to them. Dashed boxes are checks that could not run. Scroll to zoom, drag to pan, click any node.</p>' +
      '<div class="graph-tools">' +
      '<select id="g-asset" style="background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:6px 10px;font:inherit;font-size:13px;">' +
      '<option value="">all assets</option>' +
      state.assets.map(function (a) { return '<option value="' + esc(a.id) + '">' + esc(a.identifier) + '</option>'; }).join("") +
      '</select>' +
      '<button class="graph-btn" id="g-zin" title="Zoom in">+</button>' +
      '<button class="graph-btn" id="g-zout" title="Zoom out">−</button>' +
      '<button class="graph-btn" id="g-zreset">Reset view</button>' +
      '<div class="legend">' +
      SEV_ORDER.map(function (s) { return '<span><i style="background:' + sevColors()[s] + '"></i>' + s + '</span>'; }).join("") +
      '</div></div>' +
      '<div id="graph-wrap"><svg id="graph-svg" role="img"></svg></div>';

    $("#g-asset").addEventListener("change", function () {
      state.graphAssetFilter = $("#g-asset").value || null;
      loadGraph();
    });
    $("#g-zin").addEventListener("click", function () { zoomAt(state._gw / 2, state._gh / 2, 1.25); });
    $("#g-zout").addEventListener("click", function () { zoomAt(state._gw / 2, state._gh / 2, 0.8); });
    $("#g-zreset").addEventListener("click", function () { resetView(); });

    wireGraphPointer();
    loadGraph();
  }

  function loadGraph() {
    api("/api/graph" + (state.graphAssetFilter ? "?assetId=" + encodeURIComponent(state.graphAssetFilter) : ""))
      .then(function (g) { state.graph = g; drawGraph(); });
  }

  /* ---- zoom + pan (viewBox coordinates; applied to a viewport <g>) ---- */
  var vz = { x: 0, y: 0, k: 1 };
  function applyView() {
    var vp = $("#graph-viewport");
    if (vp) vp.setAttribute("transform", "translate(" + vz.x + " " + vz.y + ") scale(" + vz.k + ")");
  }
  function resetView() { vz = { x: 0, y: 0, k: 1 }; applyView(); }
  function zoomAt(cx, cy, factor) {
    var k = Math.min(4, Math.max(0.4, vz.k * factor));
    var ratio = k / vz.k;
    vz.x = cx - (cx - vz.x) * ratio;
    vz.y = cy - (cy - vz.y) * ratio;
    vz.k = k;
    applyView();
  }

  function wireGraphPointer() {
    var svg = $("#graph-svg");
    svg.addEventListener("wheel", function (e) {
      e.preventDefault();
      var rect = svg.getBoundingClientRect();
      var px = (e.clientX - rect.left) / rect.width * state._gw;
      var py = (e.clientY - rect.top) / rect.height * state._gh;
      zoomAt(px, py, e.deltaY < 0 ? 1.15 : 1 / 1.15);
    }, { passive: false });

    var pan = null;
    svg.addEventListener("pointerdown", function (e) {
      pan = { sx: e.clientX, sy: e.clientY, vx: vz.x, vy: vz.y, moved: false };
      svg.classList.add("panning");
      try { svg.setPointerCapture(e.pointerId); } catch (err) { /* older engines */ }
    });
    svg.addEventListener("pointermove", function (e) {
      if (!pan) return;
      var rect = svg.getBoundingClientRect();
      var dx = (e.clientX - pan.sx) / rect.width * state._gw;
      var dy = (e.clientY - pan.sy) / rect.height * state._gh;
      if (Math.abs(dx) + Math.abs(dy) > 4) pan.moved = true;
      vz.x = pan.vx + dx;
      vz.y = pan.vy + dy;
      applyView();
    });
    var endPan = function () {
      svg.classList.remove("panning");
      if (pan && pan.moved) state._dragged = true; // suppress the click-select after a drag
      pan = null;
    };
    svg.addEventListener("pointerup", endPan);
    svg.addEventListener("pointercancel", endPan);
  }

  function drawGraph() {
    var g = state.graph;
    var svg = $("#graph-svg");
    if (!g || !svg) return;
    var colors = sevColors();

    var byKind = { asset: [], check: [], finding: [] };
    g.nodes.forEach(function (n) { byKind[n.kind].push(n); });
    var W = Math.max(900, $("#graph-wrap").clientWidth);
    var colX = { asset: 190, check: W * 0.48, finding: W - 190 };
    var PAD = 70, rowGap = 96;

    var pos = {};
    var maxRows = Math.max(byKind.asset.length, byKind.check.length, byKind.finding.length, 1);
    var H = Math.max(520, PAD * 2 + maxRows * rowGap);
    state._gw = W; state._gh = H;
    function place(list, kind) {
      var span = H - PAD * 2;
      list.forEach(function (n, i) {
        var y = list.length === 1 ? H / 2 : PAD + (span / (list.length - 1)) * i;
        pos[n.id] = { x: colX[kind], y: y };
      });
    }
    place(byKind.asset, "asset"); place(byKind.check, "check"); place(byKind.finding, "finding");

    function edgePath(a, b) {
      var dx = (b.x - a.x) * 0.45;
      return "M " + a.x + " " + a.y + " C " + (a.x + dx) + " " + a.y + ", " + (b.x - dx) + " " + b.y + ", " + b.x + " " + b.y;
    }

    var parts = [];
    g.links.forEach(function (l) {
      var a = pos[l.source], b = pos[l.target];
      if (!a || !b) return;
      var target = g.nodes.find(function (n) { return n.id === l.target; });
      var cls = "gedge" + (l.kind === "check-finding" ? " sev" : "");
      if (l.kind === "check-finding" && target && target.severity) {
        parts.push('<path class="' + cls + '" d="' + edgePath(a, b) + '" stroke="' + colors[target.severity] + '" data-s="' + esc(l.source) + '" data-t="' + esc(l.target) + '"/>');
      } else {
        parts.push('<path class="' + cls + '" d="' + edgePath(a, b) + '" data-s="' + esc(l.source) + '" data-t="' + esc(l.target) + '"/>');
      }
    });

    byKind.check.forEach(function (n) {
      var p = pos[n.id];
      var w = Math.max(120, n.label.length * 7.4 + 26);
      parts.push('<g class="gnode" data-id="' + esc(n.id) + '" transform="translate(' + (p.x - w / 2) + ',' + (p.y - 17) + ')">' +
        '<rect class="gbox' + (n.errored ? ' errored' : '') + '" width="' + w + '" height="34" rx="8"/>' +
        '<text class="glabel mono" x="' + w / 2 + '" y="21.5" text-anchor="middle">' + esc(n.label) + '</text></g>');
    });
    byKind.asset.forEach(function (n) {
      var p = pos[n.id];
      var w = Math.max(130, n.label.length * 8.4 + 30);
      parts.push('<g class="gnode" data-id="' + esc(n.id) + '" transform="translate(' + (p.x - w / 2) + ',' + (p.y - 20) + ')">' +
        '<rect class="gbox" width="' + w + '" height="40" rx="10" style="stroke:var(--accent);stroke-opacity:.55"/>' +
        '<text class="glabel" x="' + w / 2 + '" y="25" text-anchor="middle" style="font-weight:600">' + esc(n.label) + '</text></g>');
    });
    byKind.finding.forEach(function (n) {
      var p = pos[n.id];
      parts.push('<g class="gnode" data-id="' + esc(n.id) + '">' +
        '<circle cx="' + p.x + '" cy="' + p.y + '" r="7.5" fill="' + (colors[n.severity] || colors.info) + '"/>' +
        '<text class="glabel" x="' + (p.x - 16) + '" y="' + (p.y + 4) + '" text-anchor="end">' + esc(n.label) + '</text></g>');
    });

    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.innerHTML = '<g id="graph-viewport">' + parts.join("") + "</g>";
    applyView();

    function select(nodeId) {
      var keep = {};
      if (nodeId) {
        keep[nodeId] = true;
        g.links.forEach(function (l) {
          if (l.source === nodeId) keep[l.target] = true;
          if (l.target === nodeId) keep[l.source] = true;
        });
      }
      $$("#graph-svg .gnode, #graph-svg .gedge").forEach(function (el) {
        var id = el.classList.contains("gnode") ? el.dataset.id : null;
        var connected = !nodeId || keep[id] || keep[el.dataset.s] || keep[el.dataset.t];
        el.classList.toggle("dim", !connected);
        if (id) {
          var box = el.querySelector(".gbox");
          if (box) box.classList.toggle("sel", id === nodeId);
        }
      });
      if (nodeId) {
        var n = g.nodes.find(function (x) { return x.id === nodeId; });
        if (n && n.kind === "finding") { openFinding(n.id.replace("finding:", "")); return; }
        if (n) {
          openDrawer(esc(n.kind) + ": " + esc(n.label),
            n.kind === "asset"
              ? '<p class="kicker">Use the Overview tab for details, or click one of its findings in the graph.</p>'
              : '<dl class="contract"><dt>check</dt><dd class="mono">' + esc(n.checkId) + '</dd>' +
                '<dt>state</dt><dd>' + (n.errored ? "could not run in the latest scan" : "produced evidence in the latest scan") + '</dd></dl>');
        }
      } else closeDrawer();
    }
    $$("#graph-svg .gnode").forEach(function (el) {
      el.addEventListener("click", function () {
        if (state._dragged) { state._dragged = false; return; }
        var id = el.dataset.id;
        select(id === state._sel ? null : id);
        state._sel = id === state._sel ? null : id;
      });
    });
    state._sel = null;
    state._dragged = false;
  }

  // ---------------------------------------------------------------- history
  function renderHistory(main) {
    main.innerHTML =
      '<h2>History</h2>' +
      '<p class="kicker">Every scan and every recorded change, append-only.</p>' +
      '<div class="filters"><select id="h-asset">' +
      state.assets.map(function (a) { return '<option value="' + esc(a.id) + '">' + esc(a.identifier) + '</option>'; }).join("") +
      '</select></div><div id="h-body"></div>';
    var sel = $("#h-asset");
    if (!sel) return;
    sel.addEventListener("change", function () { renderHistoryBody(sel.value); });
    if (state.assets.length) renderHistoryBody(state.assets[0].id);
    else $("#h-body").innerHTML = '<div class="empty">No assets yet.</div>';
  }

  function renderHistoryBody(assetId) {
    api("/api/asset/" + encodeURIComponent(assetId)).then(function (d) {
      $("#h-body").innerHTML =
        '<h3 style="font-size:14px;margin-bottom:8px;">Scans</h3>' +
        '<table class="scanlist"><thead><tr><th>Scan</th><th>Started</th><th>Status</th><th>Summary</th></tr></thead><tbody>' +
        d.scans.map(function (s) {
          var sum = s.summary;
          var open = sum ? Object.values(sum.openBySeverity).reduce(function (a, b) { return a + b; }, 0) : null;
          return '<tr><td class="mono" style="color:var(--dim)">' + esc(s.id.slice(0, 8)) + '</td>' +
            '<td>' + fmtDate(s.finishedAt || s.startedAt) + '</td>' +
            '<td class="mono" style="font-size:12px">' + esc(s.status) + '</td>' +
            '<td style="color:var(--dim)">' + (sum ? open + ' open · ' + sum.passCount + ' passed · ' + sum.checksErrored + ' errored' : '-') + '</td></tr>';
        }).join("") + "</tbody></table>" +
        '<h3 style="font-size:14px;margin-bottom:8px;">Changes</h3>' +
        (d.events.length
          ? '<ul class="timeline">' + d.events.map(function (e) {
              return '<li class="k-' + esc(e.event) + '"><div class="t">' + fmtDate(e.at) + '</div><div class="k">' + esc(e.event) + (e.detail ? ' - ' + esc(e.detail) : '') + '</div></li>';
            }).join("") + "</ul>"
          : '<div class="empty">no recorded changes yet</div>');
    });
  }

  // ---------------------------------------------------------------- boot
  $$(".nav-btn").forEach(function (b) { b.addEventListener("click", function () { setRoute(b.dataset.route); }); });
  $("#btn-refresh").addEventListener("click", function () { loadState().then(function () { toast("Refreshed."); }); });
  $("#btn-scan-all").addEventListener("click", function () { scan(null, null); });
  loadState().catch(function (e) { toast("Failed to load state: " + e.message, true); });
})();
