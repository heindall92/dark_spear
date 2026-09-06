(function () {
  var RUN_KEY = "ds-engine-run";
  var TOKEN_KEY = "ds-engine-token";

  function page() {
    return (location.pathname.split("/").pop() || "").toLowerCase();
  }

  function scanDisplayName(s) {
    if (!s) return "—";
    return s.name || s.objective || s.label || s.target || s.id || "—";
  }

  function scanSearchHay(s) {
    return [
      s && s.name,
      s && s.objective,
      s && s.target,
      s && s.scope,
      s && s.id,
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function bridgeBase() {
    var port = window.location.port;
    if (port === "8080" || port === "8081") {
      return window.location.origin + "/bridge";
    }
    return sessionStorage.getItem("ds-engine-url") || "http://127.0.0.1:8420";
  }

  function ensureToken() {
    var cached = sessionStorage.getItem(TOKEN_KEY);
    if (cached) return Promise.resolve(cached);
    return fetch(bridgeBase() + "/session", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (data && data.token) {
          sessionStorage.setItem(TOKEN_KEY, data.token);
          return data.token;
        }
        return null;
      })
      .catch(function () { return null; });
  }

  function fetchStatus() {
    return ensureToken().then(function (token) {
      if (!token) return { active: false };
      return fetch(bridgeBase() + "/status", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Auditor-Token": token },
        body: "{}",
      }).then(function (r) {
        if (r.status === 401 || r.status === 403) {
          sessionStorage.removeItem(TOKEN_KEY);
          return ensureToken().then(function (t2) {
            if (!t2) return { active: false };
            return fetch(bridgeBase() + "/status", {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Auditor-Token": t2 },
              body: "{}",
            }).then(function (r2) { return r2.ok ? r2.json() : { active: false }; });
          });
        }
        return r.ok ? r.json() : { active: false };
      }).catch(function () { return { active: false }; });
    });
  }

  function bridgePost(path, body, _retrying) {
    // Antes leía el token directo de sessionStorage sin esperar a
    // ensureToken(): en la primera carga de página (o tras que bridge.py
    // rota el token al reiniciar) esto disparaba la petición sin cabecera
    // o con un token viejo -> 401 -> se devolvía null sin reintentar, y
    // paneles como OSINT/MITRE/Grafo de ataque quedaban "vacíos" aunque el
    // engagement sí tuviera hallazgos.
    return ensureToken().then(function (token) {
      var headers = { "Content-Type": "application/json" };
      if (token) headers["X-Auditor-Token"] = token;
      return fetch(bridgeBase() + path, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body || {}),
      }).then(function (r) {
        if ((r.status === 401 || r.status === 403) && !_retrying) {
          sessionStorage.removeItem(TOKEN_KEY);
          return bridgePost(path, body, true);
        }
        return r.json().catch(function () { return null; }).then(function (data) {
          if (!data) return null;
          if (!r.ok && data.error === "bridge_unreachable") {
            return { bridge: "down", hint: data.detail || data.hint, engagements: data.engagements || [] };
          }
          return data;
        });
      }).catch(function () { return null; });
    });
  }

  function loadFindings() {
    return whenFindingsReady().then(function () {
      return window.DarkSpearFindings ? DarkSpearFindings.fetchEngine() : Promise.resolve([]);
    });
  }

  function whenFindingsReady() {
    if (window.DarkSpearFindings) return Promise.resolve();
    return new Promise(function (resolve) {
      var n = 0;
      var t = setInterval(function () {
        if (window.DarkSpearFindings || ++n > 60) {
          clearInterval(t);
          resolve();
        }
      }, 50);
    });
  }

  function loadRun() {
    try { return JSON.parse(sessionStorage.getItem(RUN_KEY) || "null"); }
    catch (e) { return null; }
  }

  function countBySeverity(items, sevs) {
    return items.filter(function (f) {
      return sevs.indexOf(String(f.severity || "").toLowerCase()) >= 0;
    }).length;
  }

  function sevCounts(findings) {
    return {
      critical: countBySeverity(findings, ["critical"]),
      high: countBySeverity(findings, ["high"]),
      medium: countBySeverity(findings, ["medium"]),
      low: countBySeverity(findings, ["low"]),
      info: countBySeverity(findings, ["info"]),
    };
  }

  function normalizeTs(ts) {
    if (window.DarkSpearFindings && DarkSpearFindings.normalizeTs) {
      return DarkSpearFindings.normalizeTs(ts);
    }
    if (ts == null || ts === "") return null;
    var n = Number(ts);
    if (!isFinite(n) || n <= 0) return null;
    return n < 1e12 ? n * 1000 : n;
  }

  function findingHref(f, scanId) {
    if (window.DarkSpearFindings && DarkSpearFindings.hrefForFinding) {
      return DarkSpearFindings.hrefForFinding(f, scanId);
    }
    var sid = scanId || (f && (f.scan_id || f.engagement_dir)) || "";
    try {
      if (!sid) sid = new URLSearchParams(location.search).get("scan") || "";
    } catch (e) { /* */ }
    var q = [];
    if (f && f.id) q.push("id=" + encodeURIComponent(f.id));
    if (sid) q.push("scan=" + encodeURIComponent(sid));
    return q.length ? "finding-detail.html?" + q.join("&") : "finding-detail.html";
  }

  function renderTrendsChart(findings) {
    var live = document.getElementById("trends-chart-live");
    var empty = document.getElementById("trends-chart-empty");
    var svg = document.getElementById("trends-chart-svg");
    if (!svg) return;

    var days = 30;
    var now = Date.now();
    var dayMs = 86400000;
    var buckets = [];
    var i;
    for (i = days - 1; i >= 0; i--) {
      buckets.push({
        start: now - (i + 1) * dayMs,
        end: now - i * dayMs,
        critical: 0,
        other: 0,
      });
    }

    (findings || []).forEach(function (f) {
      var ts = normalizeTs(f.created_at) || now;
      for (i = 0; i < buckets.length; i++) {
        if (ts >= buckets[i].start && ts < buckets[i].end) {
          var s = String(f.severity || "").toLowerCase();
          if (s === "critical") buckets[i].critical++;
          else buckets[i].other++;
          break;
        }
      }
    });

    var total = buckets.reduce(function (acc, b) {
      return acc + b.critical + b.other;
    }, 0);

    if (!total) {
      if (empty) empty.hidden = false;
    } else {
      if (empty) empty.hidden = true;
    }

    var maxVal = 1;
    buckets.forEach(function (b) {
      maxVal = Math.max(maxVal, b.critical, b.other, b.critical + b.other);
    });
    var yMax = total ? (maxVal <= 5 ? 5 : maxVal <= 10 ? 10 : maxVal <= 25 ? 25 : Math.ceil(maxVal / 10) * 10) : 50;

    var x0 = 48;
    var x1 = 632;
    var yTop = 12;
    var yBase = 148;
    var plotH = yBase - yTop;

    function scaleY(v) {
      return yBase - (v / yMax) * plotH;
    }

    function scaleX(idx) {
      if (buckets.length <= 1) return x0;
      return x0 + (idx / (buckets.length - 1)) * (x1 - x0);
    }

    function smoothLine(values) {
      var pts = values.map(function (v, idx) {
        return { x: scaleX(idx), y: scaleY(v) };
      });
      if (!pts.length) return "";
      var d = "M" + pts[0].x.toFixed(1) + "," + pts[0].y.toFixed(1);
      for (i = 1; i < pts.length; i++) {
        var prev = pts[i - 1];
        var curr = pts[i];
        var cpx = ((prev.x + curr.x) / 2).toFixed(1);
        d += " C" + cpx + "," + prev.y.toFixed(1) + " " + cpx + "," + curr.y.toFixed(1) + " " + curr.x.toFixed(1) + "," + curr.y.toFixed(1);
      }
      return d;
    }

    function areaPath(values) {
      var line = smoothLine(values);
      if (!line) return "";
      var lastX = scaleX(buckets.length - 1).toFixed(1);
      return line + " L" + lastX + "," + yBase + " L" + x0 + "," + yBase + " Z";
    }

    var critVals = buckets.map(function (b) { return b.critical; });
    var otherVals = buckets.map(function (b) { return b.other; });

    function fmtDay(ts) {
      var d = new Date(ts);
      try {
        return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
      } catch (e) {
        return d.getMonth() + 1 + "/" + d.getDate();
      }
    }

    var labelStart = fmtDay(buckets[0].start);
    var labelMid = fmtDay(buckets[Math.floor(buckets.length / 2)].start);
    var labelEnd = fmtDay(buckets[buckets.length - 1].start);
    var yMid = Math.round(yMax / 2);

    svg.innerHTML =
      '<g font-family="JetBrains Mono, monospace" font-size="11" fill="#717783">' +
      '<text x="36" y="18" text-anchor="end">' + yMax + '</text>' +
      '<text x="36" y="84" text-anchor="end">' + yMid + '</text>' +
      '<text x="36" y="150" text-anchor="end">0</text>' +
      '<text x="48" y="166">' + escapeHtml(labelStart) + '</text>' +
      '<text x="344" y="166" text-anchor="middle">' + escapeHtml(labelMid) + '</text>' +
      '<text x="628" y="166" text-anchor="end">' + escapeHtml(labelEnd) + '</text>' +
      '</g>' +
      '<line x1="48" y1="12" x2="48" y2="148" stroke="#c0c7d4" stroke-opacity="0.45"/>' +
      '<line x1="48" y1="148" x2="632" y2="148" stroke="#c0c7d4" stroke-opacity="0.45"/>' +
      '<line x1="48" y1="80" x2="632" y2="80" stroke="#c0c7d4" stroke-opacity="0.25"/>' +
      '<line x1="48" y1="12" x2="632" y2="12" stroke="#c0c7d4" stroke-opacity="0.18"/>' +
      '<path d="' + areaPath(otherVals) + '" fill="#0a8575" fill-opacity="0.16"/>' +
      '<path d="' + smoothLine(otherVals) + '" fill="none" stroke="#0a8575" stroke-opacity="0.45" stroke-width="1.5" vector-effect="non-scaling-stroke"/>' +
      '<path d="' + areaPath(critVals) + '" fill="#ba1a1a" fill-opacity="0.12"/>' +
      '<path d="' + smoothLine(critVals) + '" fill="none" stroke="#ba1a1a" stroke-width="2" vector-effect="non-scaling-stroke"/>';
  }

  function toggleViews(emptyId, liveId, hasData) {
    var empty = document.getElementById(emptyId);
    var live = document.getElementById(liveId);
    if (empty) empty.hidden = !!hasData;
    if (live) live.hidden = !hasData;
  }

  function escapeHtml(s) {
    return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function tKey(key, fallback) {
    if (window.DarkSpear && DarkSpear.t) {
      var v = DarkSpear.t(key);
      if (v && v !== key) return v;
    }
    return fallback;
  }

  function findingStatus(f) {
    return String((f && f.status) || "proposed").toLowerCase();
  }

  function isFindingRemediated(f) {
    var st = findingStatus(f);
    return st === "remediated" || st === "verified" || st === "closed";
  }

  function isFindingOpen(f) {
    var st = findingStatus(f);
    return st !== "rejected" && !isFindingRemediated(f);
  }

  function mttrDaysOf(f) {
    var created = normalizeTs(f.created_at);
    var reviewed = normalizeTs(f.reviewed_at);
    if (!created || !reviewed) return null;
    return Math.max(0, (reviewed - created) / 86400000);
  }

  function avgMttrLabel(findings) {
    var vals = (findings || []).filter(isFindingRemediated).map(mttrDaysOf).filter(function (d) {
      return d != null;
    });
    if (!vals.length) return "—";
    var avg = vals.reduce(function (a, b) { return a + b; }, 0) / vals.length;
    if (avg < 1) return (avg * 24).toFixed(1) + "h";
    return avg.toFixed(1) + "d";
  }

  function formatEngagementStarted(ts) {
    if (!ts) return "—";
    var ms = ts < 1e12 ? ts * 1000 : ts;
    try {
      return new Date(ms).toLocaleString();
    } catch (e) {
      return "—";
    }
  }

  function normalizeTargetKey(target) {
    var t = String(target || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/$/, "");
    /* dirname id: 127.0.0.1_8888_2026-08-30t... */
    if (/_20\d{2}/.test(t)) t = t.split(/_20\d{2}/)[0];
    t = t.replace(/_/g, ".");
    /* 127.0.0.1.8888 → 127.0.0.1:8888 */
    var m = t.match(/^(.+)\.(\d{1,5})$/);
    if (m) t = m[1] + ":" + m[2];
    return t;
  }

  function dedupeEngagementScans(rows) {
    var best = {};
    var order = [];
    (rows || []).forEach(function (row, idx) {
      var name = String((row && (row.name || row.objective)) || "").trim().toLowerCase();
      var rawTarget = (row && row.target) || "";
      /* si target parece id de carpeta, normalizar igual */
      if (!rawTarget || /_20\d{2}/.test(String(rawTarget))) {
        rawTarget = (row && row.id) || rawTarget;
      }
      var key = name || ("t:" + normalizeTargetKey(rawTarget || (row && row.id) || ""));
      if (!key || key === "t:") key = "id:" + ((row && row.id) || idx);
      var prev = best[key];
      if (!prev) {
        best[key] = Object.assign({}, row, { run_count: 1 });
        order.push(key);
        return;
      }
      var runs = (prev.run_count || 1) + 1;
      var prevN = Number(prev.findings_count) || 0;
      var curN = Number(row.findings_count) || 0;
      var pick = row;
      if (prev.active && !row.active) pick = prev;
      else if (row.active && !prev.active) pick = row;
      else if (curN > prevN) pick = row;
      else if (curN < prevN) pick = prev;
      else {
        var prevTs = Number(prev.started_at) || 0;
        var curTs = Number(row.started_at) || 0;
        pick = curTs >= prevTs ? row : prev;
      }
      best[key] = Object.assign({}, pick, {
        run_count: runs,
        findings_count: Math.max(prevN, curN),
        name: pick.name || prev.name || row.name || "",
        target: normalizeTargetKey(pick.target || prev.target || "").replace(/^(.+):(\d+)$/, function (_, h, p) {
          return h + ":" + p;
        }) || pick.target || prev.target,
      });
      /* display target: prefer form with colon */
      var disp = best[key].target || "";
      if (/\.\d{1,5}$/.test(disp) && disp.indexOf(":") < 0) {
        best[key].target = disp.replace(/\.(\d{1,5})$/, ":$1");
      }
      if (best[key].scope && String(best[key].scope).indexOf(".8888") >= 0) {
        best[key].scope = String(best[key].scope).replace(/\.(\d{1,5})$/, "") || best[key].scope;
      }
    });
    return order.map(function (k) { return best[k]; });
  }

  function loadEngagementScans() {
    return bridgePost("/engagements/list", {}).then(function (data) {
      var rows = (data && data.engagements) || [];
      if (rows.length) return dedupeEngagementScans(rows);
      // Lista vacía tras borrar: no inventar tarjetas desde sessionStorage / inbox.
      return fetchStatus().then(function (status) {
        status = status || {};
        if (!status.active || !status.engagement_dir) {
          try {
            sessionStorage.removeItem(RUN_KEY);
            sessionStorage.removeItem("ds-engagement-id");
            sessionStorage.removeItem("ds-findings-inbox");
            sessionStorage.removeItem("ds-findings-read");
          } catch (e) { /* */ }
          return [];
        }
        var run = loadRun() || {};
        return [{
          id: status.engagement_dir,
          engagement_dir: status.engagement_dir,
          name: status.name || run.name || "",
          objective: status.objective || run.objective || "",
          target: status.target,
          scope: status.scope,
          started_at: status.started_at || (run && run.startedAt ? run.startedAt / 1000 : null) ||
            (Date.now() / 1000 - (status.elapsed_seconds || 0)),
          status: "running",
          phase: status.phase,
          findings_count: (status.findings_accepted || 0) + (status.findings_pending || 0),
          step_count: status.step_count,
          active: true,
          run_count: 1,
        }];
      });
    }).catch(function () { return []; });
  }

  function loadScanFindings(id) {
    if (!id || id === "inbox") return loadFindings();
    return bridgePost("/engagements/findings", { engagement_dir: id }).then(function (payload) {
      var list = [];
      if (payload && Array.isArray(payload.findings)) list = payload.findings;
      else if (payload && (payload.error === "engagement_not_found" || payload.error === "invalid_engagement_dir")) {
        list = [];
      }
      var hasWaf = list.some(function (f) {
        return /WAF activo:|WAF\/CDN identificado:/i.test((f && f.title) || "");
      });
      if (hasWaf) {
        list = list.filter(function (f) {
          return !/Sin WAF\/CDN identificable/i.test((f && f.title) || "");
        });
      }
      return list;
    }).catch(function () { return []; });
  }

  function mergeFindingLists(a, b) {
    var by = {};
    function add(f) {
      if (!f || !f.title) return;
      var key = [f.engagement_dir || f.scan_id || "", f.id || "", f.title, f.asset || ""].join("|");
      if (!by[key]) by[key] = f;
    }
    (a || []).forEach(add);
    (b || []).forEach(add);
    var list = Object.keys(by).map(function (k) { return by[k]; });
    var hasWaf = list.some(function (f) {
      return /WAF activo:|WAF\/CDN identificado:/i.test((f && f.title) || "");
    });
    if (!hasWaf) return list;
    return list.filter(function (f) {
      return !/Sin WAF\/CDN identificable/i.test((f && f.title) || "");
    });
  }

  function loadFindingsFromScans(scans) {
    var ids = (scans || []).map(function (s) { return s.id || s.engagement_dir; }).filter(Boolean);
    if (!ids.length) return Promise.resolve([]);
    return Promise.all(ids.map(function (id) {
      return loadScanFindings(id).then(function (list) {
        return (list || []).map(function (f) {
          var out = Object.assign({}, f);
          if (!out.scan_id) out.scan_id = id;
          if (!out.engagement_dir) out.engagement_dir = id;
          return out;
        });
      });
    })).then(function (chunks) {
      return chunks.reduce(function (acc, arr) { return acc.concat(arr || []); }, []);
    });
  }

  /** Lista de tarjetas por análisis → detalle con ?scan= */
  function scanEngagementUrl(meta) {
    var target = (meta && meta.target) || "";
    var scope = (meta && meta.scope) || target;
    return "start-engagement.html?target=" + encodeURIComponent(target) + "&scope=" + encodeURIComponent(scope);
  }

  function bootScanHub(cfg) {
    var listView = document.getElementById(cfg.listViewId);
    var detailView = document.getElementById(cfg.detailViewId);
    var cardsEl = document.getElementById(cfg.cardsId);
    var emptyEl = document.getElementById(cfg.emptyId);
    if (!listView || !detailView || !cardsEl) return null;

    var state = { scans: [], listSearch: "", scanId: null, findings: [], meta: null };
    var scanId = new URLSearchParams(location.search).get("scan");

    function setView(mode) {
      var isList = mode === "list";
      listView.hidden = !isList;
      detailView.hidden = isList;
      listView.style.display = isList ? "" : "none";
      detailView.style.display = isList ? "none" : "";
      if (cfg.footerId) {
        var foot = document.getElementById(cfg.footerId);
        if (foot) {
          foot.hidden = isList;
          foot.style.display = isList ? "none" : "";
        }
      }
      (cfg.hideOnListIds || []).forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.hidden = isList;
      });
    }

    function renderCards() {
      var q = state.listSearch;
      var list = (state.scans || []).filter(function (s) {
        if (!q) return true;
        return scanSearchHay(s).indexOf(q) >= 0;
      });
      cardsEl.innerHTML = "";
      if (!list.length) {
        if (emptyEl) emptyEl.hidden = false;
        cardsEl.hidden = true;
        return;
      }
      if (emptyEl) emptyEl.hidden = true;
      cardsEl.hidden = false;
      list.forEach(function (s) {
        var badge = s.active
          ? '<span class="bg-primary-container/15 text-primary font-label-md text-label-md px-sm py-xs rounded shrink-0">' +
            tKey("scan.running", "En curso") + "</span>"
          : '<span class="bg-surface-container-high text-on-surface-variant font-label-md text-label-md px-sm py-xs rounded shrink-0">' +
            escapeHtml(s.status || tKey("scan.done", "completado")) + "</span>";
        var hint = (s.findings_count != null ? s.findings_count : 0) + " " + tKey("scan.findings", "hallazgos");
        var title = scanDisplayName(s);
        var sub = (s.name || s.objective)
          ? "Target: " + (s.target || "—") + " · Scope: " + (s.scope || "—")
          : "Scope: " + (s.scope || "—");
        var runs = Number(s.run_count) || 1;
        var card = document.createElement("article");
        card.className = "glass-panel rounded-xl p-md flex flex-col gap-md";
        card.innerHTML =
          '<div class="flex justify-between items-start gap-md">' +
          '<div class="min-w-0">' +
          '<h3 class="font-headline-md text-headline-md text-on-surface truncate">' + escapeHtml(title) + "</h3>" +
          '<p class="font-mono-md text-mono-md text-secondary mt-xs truncate">' + escapeHtml(sub) + "</p>" +
          "</div>" + badge + "</div>" +
          '<div class="flex flex-wrap gap-md font-body-sm text-on-surface-variant border-t border-outline-variant/30 pt-sm">' +
          "<span>" + escapeHtml(formatEngagementStarted(s.started_at)) + "</span>" +
          (s.phase ? "<span>Fase " + escapeHtml(String(s.phase)) + "</span>" : "") +
          (s.use_ai === false
            ? "<span>" + escapeHtml(tKey("scan.playbook", "Playbook")) + "</span>"
            : "") +
          (runs > 1
            ? "<span>" + runs + " " + escapeHtml(tKey("scan.runs", "ejecuciones")) + "</span>"
            : "") +
          "<span>" + escapeHtml(hint) + "</span></div>" +
          '<div class="flex flex-wrap justify-end gap-sm">' +
          (cfg.scanTargetCta
            ? '<a class="px-md py-sm bg-primary-container text-on-primary-container rounded-lg font-label-md flex items-center gap-xs hover:bg-primary transition-colors shadow-sm" href="' +
              scanEngagementUrl(s) + '">' +
              '<i data-lucide="radar" class="icon-sm"></i><span>' +
              escapeHtml(tKey("osint.scanTarget", "Escanear este target")) + "</span></a>" +
              '<a class="px-md py-sm rounded-lg border border-outline-variant/50 bg-surface-container-lowest text-on-surface font-label-md flex items-center gap-xs hover:bg-surface-container-low transition-colors" href="' +
              cfg.pageFile + "?scan=" + encodeURIComponent(s.id) + '">' +
              '<i data-lucide="' + (cfg.ctaIcon || "arrow-right") + '" class="icon-sm"></i><span>' +
              escapeHtml(cfg.ctaLabel || tKey("scan.open", "Abrir")) + "</span></a>"
            : '<a class="px-md py-sm bg-primary-container text-on-primary-container rounded-lg font-label-md flex items-center gap-xs hover:bg-primary transition-colors" href="' +
              cfg.pageFile + "?scan=" + encodeURIComponent(s.id) + '">' +
              '<i data-lucide="' + (cfg.ctaIcon || "arrow-right") + '" class="icon-sm"></i><span>' +
              escapeHtml(cfg.ctaLabel || tKey("scan.open", "Abrir")) + "</span></a>") +
          "</div>";
        cardsEl.appendChild(card);
      });
      if (window.lucide) lucide.createIcons();
    }

    function showList() {
      state.scanId = null;
      setView("list");
      loadEngagementScans().then(function (rows) {
        state.scans = rows || [];
        renderCards();
      });
    }

    function showDetail(id) {
      state.scanId = id;
      setView("detail");
      Promise.all([loadScanFindings(id), loadEngagementScans(), fetchStatus()]).then(function (res) {
        var findings = res[0] || [];
        var scans = res[1] || [];
        var status = res[2] || {};
        state.scans = scans;
        var meta = scans.find(function (e) { return e.id === id; }) || {
          id: id,
          target: status.target || (loadRun() && loadRun().target) || id,
          scope: status.scope || (loadRun() && loadRun().scope) || "—",
        };
        if (typeof cfg.filterFindings === "function") {
          findings = cfg.filterFindings(findings) || findings;
        }
        state.findings = findings;
        state.meta = meta;
        var titleEl = cfg.titleId ? document.getElementById(cfg.titleId) : null;
        var subEl = cfg.subtitleId ? document.getElementById(cfg.subtitleId) : null;
        if (titleEl) {
          titleEl.textContent = cfg.pageTitle || tKey("scan.open", "Análisis");
        }
        if (subEl) {
          var scanName = scanDisplayName(meta) || id;
          subEl.textContent =
            scanName +
            " · Target: " + (meta.target || "—") +
            (meta.scope ? " · Scope: " + meta.scope : "") +
            " · " + findings.length + " " + tKey("scan.findings", "hallazgos");
        }
        if (typeof cfg.onDetail === "function") cfg.onDetail(findings, meta, id, status);
      });
    }

    var searchEl = cfg.searchId ? document.getElementById(cfg.searchId) : null;
    if (searchEl) {
      searchEl.addEventListener("input", function (e) {
        state.listSearch = String(e.target.value || "").toLowerCase().trim();
        renderCards();
      });
    }

    if (scanId) showDetail(scanId);
    else showList();

    return {
      state: state,
      showList: showList,
      showDetail: showDetail,
      reloadDetail: function () {
        if (state.scanId) showDetail(state.scanId);
      },
    };
  }

  function renderSevStatsGrid(containerId, findings) {
    var el = document.getElementById(containerId);
    if (!el) return;
    var c = sevCounts(findings || []);
    el.innerHTML = ["critical", "high", "medium", "low", "info"].map(function (k) {
      return '<div class="glass-panel rounded-lg p-md text-center"><p class="font-label-md text-on-surface-variant uppercase">' +
        k + '</p><p class="font-headline-xl">' + c[k] + "</p></div>";
    }).join("");
  }

  var REPORT_CHAPTER_LINKS = [
    { href: "comprehensive-report.html", key: "comp.title", fallback: "Informe integral", icon: "file-text" },
    { href: "executive-summary.html", key: "exec.title", fallback: "Resumen ejecutivo", icon: "chart-pie" },
    { href: "findings-summary.html", key: "summary.title", fallback: "Resumen de hallazgos", icon: "layout-list" },
    { href: "remediation-plan.html", key: "remplan.title", fallback: "Plan de remediación", icon: "list-checks" },
    { href: "gdpr-alignment.html", key: "gdpr.title", fallback: "Alineación RGPD", icon: "scale" },
    { href: "maturity-index.html", key: "maturity.title", fallback: "Índice de madurez", icon: "target" },
    { href: "kill-chain.html", key: "killchain.title", fallback: "Kill Chain", icon: "git-branch" },
  ];

  function renderChapterNav(containerId, scanId, currentPage) {
    var el = document.getElementById(containerId);
    if (!el) return;
    var q = scanId ? ("?scan=" + encodeURIComponent(scanId)) : "";
    el.innerHTML = REPORT_CHAPTER_LINKS.filter(function (ch) {
      return ch.href !== currentPage;
    }).map(function (ch) {
      return '<a href="' + ch.href + q + '" class="px-md py-sm rounded-lg border border-outline-variant/50 bg-surface-container-lowest text-on-surface font-label-md flex items-center gap-xs hover:bg-surface-container-low transition-colors">' +
        '<i data-lucide="' + ch.icon + '" class="icon-sm"></i><span>' +
        escapeHtml(tKey(ch.key, ch.fallback)) + "</span></a>";
    }).join("");
    if (window.lucide) lucide.createIcons();
  }

  function bootReportChapter(cfg) {
    var prefix = cfg.prefix;
    if (!document.getElementById(prefix + "-list-view")) return null;
    return bootScanHub({
      pageFile: cfg.pageFile || page(),
      listViewId: prefix + "-list-view",
      detailViewId: prefix + "-detail-view",
      cardsId: prefix + "-scans-cards",
      emptyId: prefix + "-empty",
      searchId: prefix + "-list-search",
      titleId: prefix + "-detail-title",
      subtitleId: prefix + "-detail-subtitle",
      ctaLabel: tKey(cfg.ctaKey, cfg.ctaFallback || tKey("scan.open", "Abrir")),
      ctaIcon: cfg.ctaIcon || "arrow-right",
      pageTitle: tKey(cfg.titleKey || (cfg.prefix ? cfg.prefix + ".title" : ""), cfg.titleFallback || cfg.ctaFallback || ""),
      hideOnListIds: cfg.hideOnListIds,
      footerId: cfg.footerId,
      onDetail: cfg.onDetail,
    });
  }

  function gdprFindingBlob(f) {
    return ((f && f.title) || "") + " " + ((f && f.description) || "") + " " +
      ((f && f.remediation) || "") + " " + ((f && f.asset) || "");
  }

  function gdprIsArt30(f) {
    return /ropa|registro de actividades|art\.?\s*30|data.?map|inventario de tratamientos/.test(
      gdprFindingBlob(f).toLowerCase()
    );
  }

  function gdprIsArt32(f) {
    var s = String((f && f.severity) || "").toLowerCase();
    if (s === "info") return false;
    var title = String((f && f.title) || "");
    if (/robots\.txt|security\.txt|sitemap/i.test(title) && (s === "low" || s === "medium")) return false;
    if (s === "critical" || s === "high" || s === "medium") return true;
    return /injection|xss|csrf|credential|secret|backup|\.bak|encrypt|tls|cookie|session|upload|inclusion|rce|sqli|cwe-|default cred|phpinfo|allow_url/i.test(
      gdprFindingBlob(f).toLowerCase()
    );
  }

  function gdprIsArt33(f) {
    return /secretos de aplicaci[oó]n|db_password|config\.inc\.php\.bak|credenciales por defecto|admin\/password|data.?breach|breach notification|datos personales|\bpii\b|filtraci[oó]n de (datos|secretos)|application secrets|hardcodead[oa] en bundle|viva confirmada|access key id|arn aws/i.test(
      gdprFindingBlob(f).toLowerCase()
    );
  }

  function gdprRelevantFindings(findings) {
    return (findings || []).filter(function (f) {
      return gdprIsArt30(f) || gdprIsArt32(f) || gdprIsArt33(f);
    });
  }

  function gdprArt32View(hits) {
    var open = (hits || []).filter(isFindingOpen);
    if (!(hits || []).length) {
      return { display: tKey("gdpr.notEvaluated", "No evaluado"), pct: 0, tone: "tertiary", score: null };
    }
    if (!open.length) {
      return { display: "100%", pct: 100, tone: "tertiary", score: 100 };
    }
    var c = sevCounts(open);
    if (c.critical) {
      return {
        display: tKey("gdpr.art32NotDemonstrable", "No demostrable"),
        pct: 8,
        tone: "error",
        score: 8,
      };
    }
    var penalty = c.high * 10 + c.medium * 5 + c.low * 2;
    var score = Math.max(12, Math.min(90, 90 - penalty));
    return {
      display: score + "%",
      pct: score,
      tone: score < 40 ? "error" : "primary",
      score: score,
    };
  }

  function gdprArticleScores(findings) {
    var all = findings || [];
    return {
      art30Hits: all.filter(gdprIsArt30),
      art32Hits: all.filter(gdprIsArt32),
      art33Hits: all.filter(gdprIsArt33),
      gdpr: gdprRelevantFindings(all),
    };
  }

  function gdprProgressBar(label, display, pct, tone) {
    var color = tone === "error" ? "bg-error" : tone === "primary" ? "bg-primary" : "bg-tertiary";
    var textColor = tone === "error" ? "text-error" : tone === "primary" ? "text-primary" : "text-tertiary";
    var width = typeof pct === "number" ? Math.max(0, Math.min(100, pct)) : 0;
    return '<div><div class="flex justify-between font-label-md text-label-md mb-xs">' +
      '<span class="text-on-surface">' + escapeHtml(label) + "</span>" +
      '<span class="' + textColor + '">' + escapeHtml(display) + "</span></div>" +
      '<div class="w-full bg-surface-container h-2 rounded-full overflow-hidden">' +
      '<div class="' + color + ' h-full rounded-full transition-all" style="width:' + width + '%"></div></div></div>';
  }

  function renderGdprComplianceDashboard(findings, meta, scanId) {
    var scores = gdprArticleScores(findings);
    var gdpr = scores.gdpr;
    var art32Hits = scores.art32Hits;
    var art33Hits = scores.art33Hits;
    var art32View = gdprArt32View(art32Hits);
    var art32Pct = art32View.score;
    var bars = document.getElementById("gdpr-progress-bars");
    if (bars) {
      bars.innerHTML =
        gdprProgressBar(
          tKey("gdpr.art30", "Mapeo de datos (Art. 30)"),
          tKey("gdpr.notEvaluated", "No evaluado"),
          0,
          "tertiary"
        ) +
        gdprProgressBar(
          tKey("gdpr.art32", "Seguridad del tratamiento (Art. 32)"),
          art32View.display,
          art32View.pct,
          art32View.tone
        ) +
        gdprProgressBar(
          tKey("gdpr.art33", "Notificación de brechas (Art. 33)"),
          art33Hits.length
            ? tKey("gdpr.art33Evaluate", "Evaluar")
            : tKey("gdpr.art33None", "Sin indicios"),
          art33Hits.length ? 12 : 0,
          art33Hits.length ? "error" : "tertiary"
        );
    }
    var cards = document.getElementById("gdpr-art-cards");
    if (cards) {
      var q = scanId ? ("?scan=" + encodeURIComponent(scanId)) : "";
      var art32Open = art32Hits.filter(isFindingOpen).length;
      cards.innerHTML =
        '<article class="glass-panel rounded-xl p-md flex flex-col gap-sm">' +
        '<div class="flex justify-between items-start"><div class="flex items-center gap-sm">' +
        '<i data-lucide="shield" class="text-primary"></i><span class="font-label-md text-secondary">Art. 32</span></div>' +
        '<span class="px-2 py-0.5 bg-secondary-container/50 text-on-secondary-container rounded font-label-md text-[10px]">' +
        escapeHtml(art32Pct != null && art32Pct < 50
          ? tKey("gdpr.art32BadgeGap", "Hueco de control")
          : tKey("gdpr.art32Badge", "En revisión")) + "</span></div>" +
        '<h4 class="font-headline-md text-on-surface">' + escapeHtml(tKey("gdpr.art32Title", "Medidas técnicas")) + "</h4>" +
        '<p class="font-body-sm text-secondary">' + art32Hits.length + " " + tKey("scan.findings", "hallazgos") +
        " · " + escapeHtml(art32View.display) +
        (art32View.score != null && art32View.score < 50
          ? " · " + tKey("gdpr.art32ScoreHint", "los críticos abiertos impiden demostrar Art. 32")
          : "") +
        ".</p>" +
        '<div class="flex justify-between items-center pt-sm border-t border-outline-variant/20 mt-auto">' +
        '<span class="font-mono-md text-secondary">' + art32Open + " " + tKey("chapter.openFindings", "abiertos") + "</span>" +
        '<a class="font-label-md text-primary hover:underline" href="critical-findings.html' + q + '">' +
        escapeHtml(tKey("gdpr.viewDetails", "Ver detalles")) + "</a></div></article>" +
        '<article class="glass-panel rounded-xl p-md flex flex-col gap-sm">' +
        '<div class="flex justify-between items-start"><div class="flex items-center gap-sm">' +
        '<i data-lucide="triangle-alert" class="text-error"></i><span class="font-label-md text-secondary">Art. 33</span></div>' +
        '<span class="px-2 py-0.5 ' + (art33Hits.length ? "bg-error-container/50 text-on-error-container" : "bg-secondary-container/50 text-on-secondary-container") +
        ' rounded font-label-md text-[10px]">' +
        escapeHtml(art33Hits.length ? tKey("gdpr.art33Badge", "Evaluar") : tKey("gdpr.art33None", "Sin indicios")) + "</span></div>" +
        '<h4 class="font-headline-md text-on-surface">' + escapeHtml(tKey("gdpr.art33Title", "Evaluación de notificación")) + "</h4>" +
        '<p class="font-body-sm text-secondary">' +
        escapeHtml(art33Hits.length
          ? tKey("gdpr.art33LeadHits", "Hallazgos de secretos o compromiso de cuenta: evaluar si hay datos personales y el reloj de 72 h. El pentest no audita el IRP.")
          : tKey("gdpr.art33LeadNone", "Sin fuga de secretos ni compromiso de cuenta en este análisis. El protocolo IRP no se ha auditado.")) +
        "</p>" +
        '<div class="flex justify-between items-center pt-sm border-t border-outline-variant/20 mt-auto">' +
        '<span class="font-mono-md ' + (art33Hits.length ? "text-error" : "text-secondary") + '">' +
        art33Hits.length + " " + tKey("scan.findings", "hallazgos") + "</span>" +
        '<a class="font-label-md text-primary hover:underline" href="remediation-plan.html' + q + '">' +
        escapeHtml(tKey("gdpr.resolve", "Resolver")) + "</a></div></article>";
    }
    var sanction = document.getElementById("gdpr-sanction");
    if (sanction) {
      sanction.innerHTML =
        '<div class="font-headline-md text-on-surface mb-1">' + escapeHtml(tKey("gdpr.sanctionCeil", "Art. 83.4 / 83.5")) + "</div>" +
        '<div class="font-body-md text-error mb-xs">' + escapeHtml(tKey("gdpr.sanctionRange", "Hasta 10 M€ o 2 % · hasta 20 M€ o 4 %")) + "</div>" +
        '<div class="font-label-md text-secondary">' + escapeHtml(tKey("gdpr.sanctionRisk", "Techo legal, no multa calculada")) + "</div>";
    }
    var matrix = document.getElementById("gdpr-risk-matrix");
    if (matrix) {
      var art33Cell = art33Hits.length ? "Art.33" : "";
      var art32Cell = art32Pct != null && art32Pct < 70 ? "Art.32" : "";
      matrix.innerHTML =
        '<div class="absolute -left-8 top-1/2 -translate-y-1/2 -rotate-90 font-label-md text-secondary tracking-widest text-[10px]">' +
        escapeHtml(tKey("gdpr.matrixImpact", "Impacto")) + "</div>" +
        '<div class="absolute -bottom-8 left-1/2 -translate-x-1/2 font-label-md text-secondary tracking-widest text-[10px]">' +
        escapeHtml(tKey("gdpr.matrixProb", "Probabilidad")) + "</div>" +
        '<div class="flex-1 flex gap-1"><div class="flex-1 bg-tertiary/20 rounded-sm heatmap-cell"></div>' +
        '<div class="flex-1 bg-[#ffd54f]/40 rounded-sm heatmap-cell flex items-center justify-center font-mono-md text-xs">' +
        (art32Cell ? "" : "2") + "</div>" +
        '<div class="flex-1 bg-error/40 rounded-sm heatmap-cell flex items-center justify-center font-mono-md text-xs font-bold' +
        (art33Cell ? " border-2 border-error" : "") + '">' + escapeHtml(art33Cell) + "</div></div>" +
        '<div class="flex-1 flex gap-1"><div class="flex-1 bg-tertiary/20 rounded-sm heatmap-cell"></div>' +
        '<div class="flex-1 bg-tertiary/40 rounded-sm heatmap-cell"></div>' +
        '<div class="flex-1 bg-[#ffd54f]/40 rounded-sm heatmap-cell flex items-center justify-center font-mono-md text-xs">' +
        escapeHtml(art32Cell) + "</div></div>" +
        '<div class="flex-1 flex gap-1"><div class="flex-1 bg-tertiary/10 rounded-sm heatmap-cell"></div>' +
        '<div class="flex-1 bg-tertiary/20 rounded-sm heatmap-cell"></div>' +
        '<div class="flex-1 bg-tertiary/40 rounded-sm heatmap-cell"></div></div>';
    }
    var matLink = document.getElementById("gdpr-btn-maturity");
    if (matLink && scanId) matLink.href = "maturity-index.html?scan=" + encodeURIComponent(scanId);
    renderChapterNav("gdpr-chapters", scanId, "gdpr-alignment.html");
    var exportBtn = document.getElementById("gdpr-btn-export");
    if (exportBtn && !exportBtn.dataset.bound) {
      exportBtn.dataset.bound = "1";
      exportBtn.addEventListener("click", function () {
        if (window.DarkSpearExport && DarkSpearExport.run) {
          DarkSpearExport.run("html", {
            findings: gdpr.length ? gdpr : (findings || []),
            target: meta && meta.target,
            scope: meta && meta.scope,
            engagementId: scanId,
          });
        }
      });
    }
    if (window.lucide) lucide.createIcons();
  }

  function maturityFromFindings(findings) {
    var c = sevCounts(findings || []);
    var total = (findings || []).length || 1;
    var risk = (c.critical * 4 + c.high * 3 + c.medium * 2 + c.low + c.info * 0.5) / total;
    var score = Math.max(0, Math.min(100, Math.round(100 - risk * 15)));
    var level = score >= 80
      ? tKey("maturity.levelOpt", "Optimización")
      : score >= 60
        ? tKey("maturity.levelDef", "Definido")
        : score >= 40
          ? tKey("maturity.levelMan", "Gestionado")
          : tKey("maturity.levelInit", "Inicial");
    return { score: score, level: level, counts: c };
  }

  var KILL_CHAIN_STAGES = [
    { stage: "Reconnaissance", key: "killchain.recon", re: /nmap|whois|robots|phpinfo|header|directory|enumer|osint|fingerprint|whatweb|listado de directorio|cabecera server|spf|dmarc|tenant|workspace|rdap|asn|wayback|openid|saml|índice de exposición|nueva desde última|nuevo desde última|arn aws|decodifica a account|prefijo|hyperscaler|anunciada por/i },
    { stage: "Weaponization", key: "killchain.weapon", re: /payload|weaponiz|malware|cve-\d{4}|spoofing|p=none|sin hard fail|\+all/i },
    { stage: "Delivery", key: "killchain.delivery", re: /upload|dvwa expuesta|damn vulnerable|security.?low|m[oó]dulos vulnerables|panel de m[oó]dulos|hackable\/uploads/i },
    { stage: "Exploitation", key: "killchain.exploit", re: /injection|xss|csrf|sql|rce|secret|credencial|hardcodead|bak|credential|allow_url|cookie|session|command injection|inclusi[oó]n|brute|listable|ssrf|viva confirmada/i },
    { stage: "Installation", key: "killchain.install", re: /web.?shell|backdoor|persist|implant/i },
    { stage: "C2", key: "killchain.c2", re: /c2|command.?control|beacon|callback/i },
    { stage: "Actions", key: "killchain.actions", re: /privilege|lateral|exfil|data.?loss|escalat/i },
  ];

  function killChainBuckets(findings) {
    var buckets = KILL_CHAIN_STAGES.map(function (k) {
      return { stage: k.stage, label: tKey(k.key, k.stage), items: [] };
    });
    (findings || []).forEach(function (f) {
      var blob = ((f.title || "") + " " + (f.description || "")).toLowerCase();
      for (var i = 0; i < KILL_CHAIN_STAGES.length; i++) {
        if (KILL_CHAIN_STAGES[i].re.test(blob)) {
          buckets[i].items.push(f);
          return;
        }
      }
      buckets[3].items.push(f);
    });
    return buckets;
  }

  function renderFindingsChapterDetail(findings, listId, statsId, summaryId) {
    renderSevStatsGrid(statsId, findings);
    if (summaryId) {
      var sumEl = document.getElementById(summaryId);
      if (sumEl) {
        var c = sevCounts(findings || []);
        var open = (findings || []).filter(isFindingOpen).length;
        sumEl.innerHTML =
          '<p class="font-body-md text-on-surface-variant">' +
          escapeHtml(tKey("chapter.totalFindings", "Total")) + ": <strong>" + (findings || []).length + "</strong> · " +
          escapeHtml(tKey("chapter.openFindings", "Abiertos")) + ": <strong>" + open + "</strong> · " +
          "Critical: <strong>" + c.critical + "</strong> · High: <strong>" + c.high + "</strong></p>";
      }
    }
    var list = document.getElementById(listId);
    if (list && window.DarkSpearFindings) {
      DarkSpearFindings.renderList(list, findings || [], "all");
    }
  }

  /* Cobertura Reconnaissance alineada al playbook OSINT (fase 1, sin LLM). */
  var MITRE_MATRIX = [
    {
      tactic: "Reconnaissance",
      count: 10,
      techniques: [
        {
          id: "T1589",
          name: "Gather Victim Identity Information",
          coverage: "high",
          re: /credential|leak|breach|email|password|identity|empleado|filtrada|pastebin|hibp|tenant|workspace|entra id|saml/i,
        },
        {
          id: "T1590",
          name: "Gather Victim Network Information",
          coverage: "high",
          re: /\bdns\b|dig |nslookup|whois|rdap|mx\b|nameserver|spf|dmarc|aaaa?\b|network.?info/i,
        },
        {
          id: "T1591",
          name: "Gather Victim Org Information",
          coverage: "high",
          re: /registrant|organization|org.?info|empresa|rdap|whois.?org|business|anunciada por|prefijo/i,
        },
        {
          id: "T1592",
          name: "Gather Victim Host Information",
          coverage: "high",
          re: /server:|x-powered-by|ssl.?cert|tls|fingerprint|whatweb|banner|host.?info|certificate/i,
        },
        {
          id: "T1593",
          name: "Search Open Websites/Domains",
          coverage: "high",
          re: /wayback machine|archive\.org|google.?dork|search.?engine|social.?media|open.?web|osint.?search/i,
        },
        {
          id: "T1594",
          name: "Search Victim-Owned Websites",
          coverage: "high",
          re: /robots\.txt|sitemap|security\.txt|\.well-known|victim.?owned|site.?map/i,
        },
        {
          id: "T1595",
          name: "Active Scanning",
          coverage: "high",
          re: /nmap|active.?scan|scan|recon|whatweb|nikto|gobuster|ffuf|subdomain.?probe|head request/i,
        },
        {
          id: "T1596",
          name: "Search Open Technical Databases",
          coverage: "high",
          re: /crt\.sh|certificate.?transparency|\bct\b|shodan|censys|technical.?database|san\b/i,
        },
      ],
    },
    {
      tactic: "Initial Access",
      count: 9,
      techniques: [
        { id: "T1189", name: "Drive-by Compromise", coverage: "high", re: /xss|cross.site|drive.?by/i },
        { id: "T1190", name: "Exploit Public-Facing Application", coverage: "high", re: /sql|injection|sqli|rce|public.?facing/i },
        { id: "T1133", name: "External Remote Services", coverage: "high", re: /vpn|rdp|ssh|remote.?service|expuesto a internet/i },
        { id: "T1566", name: "Phishing", coverage: "none", re: /phish|spear/i },
      ],
    },
    {
      tactic: "Execution",
      count: 14,
      techniques: [
        { id: "T1059", name: "Command and Scripting Interpreter", coverage: "high", re: /exec|command|rce|shell|script/i },
        { id: "T1203", name: "Exploitation for Client Execution", coverage: "partial", re: /client.?exec|browser.?exploit/i },
        { id: "T1053", name: "Scheduled Task/Job", coverage: "none", re: /cron|scheduled|task/i },
        { id: "T1059.007", name: "JavaScript", coverage: "partial", re: /xss \(dom\)|xss_d|dom.?based xss/i },
      ],
    },
    {
      tactic: "Persistence",
      count: 20,
      techniques: [
        { id: "T1098", name: "Account Manipulation", coverage: "partial", re: /account.?manip|user.?add/i },
        { id: "T1197", name: "BITS Jobs", coverage: "none", re: /bits/i },
        { id: "T1543", name: "Create or Modify System Process", coverage: "none", re: /service|systemd|persistence/i },
        { id: "T1505.003", name: "Web Shell", coverage: "partial", re: /file upload|hackable\/uploads/i },
      ],
    },
    {
      tactic: "Privilege Escalation",
      count: 14,
      techniques: [
        { id: "T1548", name: "Abuse Elevation Control Mechanism", coverage: "partial", re: /privilege|escalat|sudo|uac/i },
        { id: "T1134", name: "Access Token Manipulation", coverage: "none", re: /token|impersonat/i },
      ],
    },
    {
      tactic: "Defense Evasion",
      count: 43,
      techniques: [
        { id: "T1548", name: "Abuse Elevation Control Mechanism", coverage: "partial", re: /privilege|escalat|sudo|uac/i },
        { id: "T1140", name: "Deobfuscate/Decode Files or Information", coverage: "partial", re: /obfuscat|decode|base64/i },
        { id: "T1070", name: "Indicator Removal", coverage: "none", re: /log.?clear|indicator.?remov/i },
        { id: "T1202", name: "Indirect Command Execution", coverage: "partial", re: /indirect.?command/i },
        { id: "T1539", name: "Steal Web Session Cookie", coverage: "high", re: /cookie|session|httponly|security=low/i },
        { id: "T1562.004", name: "Disable or Modify System Firewall", coverage: "high", re: /ufw inactivo|pol[ií]tica accept|policy accept|pol[ií]tica por defecto allow/i },
      ],
    },
    {
      tactic: "Credential Access",
      count: 17,
      techniques: [
        { id: "T1110", name: "Brute Force", coverage: "partial", re: /brute|password|credential|hydra/i },
        { id: "T1606", name: "Forge Web Credentials", coverage: "high", re: /jwt alg=none|secreto jwt|jwt d[ée]bil|forjado/i },
        { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", coverage: "high", re: /\.env expuesto|config\.inc\.php\.bak|db_password|secretos de aplicaci|hardcodead[oa] en bundle js|secreto hardcodeado en bundle|viva confirmada/i },
        { id: "T1552.005", name: "Unsecured Credentials: Cloud Instance Metadata API", coverage: "high", re: /metadata aws|169\.254\.169\.254|ssrf.*metadata/i },
      ],
    },
    {
      tactic: "Discovery",
      count: 12,
      techniques: [
        { id: "T1046", name: "Network Service Discovery", coverage: "high", re: /port.?scan|service.?discover|nmap.?-s[vc]|open.?port|filtered|expuesto a internet|perímetro con filtrado/i },
        { id: "T1082", name: "System Information Discovery", coverage: "partial", re: /system.?info|phpinfo|server.?info|banner/i },
        { id: "T1083", name: "File and Directory Discovery", coverage: "high", re: /gobuster|ffuf|feroxbuster|directory.?discover|forbidden|not.?found.?probe|dirbust|listable|listado de directorio|index of/i },
        { id: "T1518", name: "Software Discovery", coverage: "high", re: /versi[oó]n en cabecera|revela versi[oó]n|cabecera server|whatweb/i },
        { id: "T1518.001", name: "Security Software Discovery", coverage: "high", re: /waf\/cdn identificado|waf activo|sin waf\/cdn|ufw activo/i },
        { id: "T1526", name: "Cloud Service Discovery", coverage: "high", re: /infraestructura identificada como aws/i },
      ],
    },
    {
      tactic: "Lateral Movement",
      count: 9,
      techniques: [
        { id: "T1210", name: "Exploitation of Remote Services", coverage: "none", re: /lateral|pivot|smb.?relay|remote.?exploit/i },
        { id: "T1021", name: "Remote Services", coverage: "none", re: /rdp|winrm|ssh.?lateral|remote.?service.?login/i },
      ],
    },
    {
      tactic: "Collection",
      count: 17,
      techniques: [
        { id: "T1539", name: "Steal Web Session Cookie", coverage: "high", re: /cookie|session|httponly|security=low/i },
        { id: "T1213", name: "Data from Information Repositories", coverage: "partial", re: /\.git|repositor|swagger|actuator|phpmyadmin|\.env\b/i },
        { id: "T1005", name: "Data from Local System", coverage: "none", re: /local.?file.?collect|filesystem.?dump/i },
        { id: "T1530", name: "Data from Cloud Storage", coverage: "high", re: /bucket s3.*listable|listbucketresult|azure blob.*listable|gcs.*listable/i },
      ],
    },
    {
      tactic: "Command and Control",
      count: 16,
      techniques: [
        { id: "T1071", name: "Application Layer Protocol", coverage: "none", re: /c2|command.?control|beacon|callback/i },
        { id: "T1105", name: "Ingress Tool Transfer", coverage: "partial", re: /upload|file.?transfer|wget|curl.*upload/i },
      ],
    },
    {
      tactic: "Exfiltration",
      count: 9,
      techniques: [
        { id: "T1041", name: "Exfiltration Over C2 Channel", coverage: "none", re: /exfil.*c2|exfiltration.?channel/i },
        { id: "T1567", name: "Exfiltration Over Web Service", coverage: "none", re: /exfil.*web.?service|paste.?exfil/i },
      ],
    },
    {
      tactic: "Impact",
      count: 13,
      techniques: [
        { id: "T1499", name: "Endpoint Denial of Service", coverage: "none", re: /\bdos\b|denial.?of.?service|flood/i },
        { id: "T1490", name: "Inhibit System Recovery", coverage: "none", re: /inhibit.?recovery|delete.?backup|shadow.?copy/i },
      ],
    },
  ];

  var MITRE_MAP = [];
  MITRE_MATRIX.forEach(function (col) {
    col.techniques.forEach(function (t) {
      MITRE_MAP.push({ re: t.re, id: t.id, name: t.name, tactic: col.tactic });
    });
  });

  function mitreForFinding(f) {
    var blob = ((f.title || "") + " " + (f.description || "") + " " + (f.asset || "")).toLowerCase();
    var out = [];
    MITRE_MAP.forEach(function (m) {
      if (m.re.test(blob)) out.push(m);
    });
    if (!out.length) out.push({ id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" });
    return out;
  }

  function collectMitreObserved(findings) {
    var map = {};
    (findings || []).forEach(function (f) {
      if (f && f.status === "rejected") return;
      mitreForFinding(f).forEach(function (t) {
        if (!map[t.id]) map[t.id] = { count: 0, findings: [], name: t.name, tactic: t.tactic };
        map[t.id].count += 1;
        map[t.id].findings.push(f);
      });
    });
    return map;
  }

  function maturityDomainsFromFindings(findings) {
    var defs = [
      { key: "iam", es: "Gestión de identidad (IAM)", en: "Identity (IAM)", re: /credential|login|session|cookie|mfa|brute|password|admin\/password|php.?sess|tenant|workspace|entra|oidc|saml/i },
      { key: "net", es: "Seguridad de red", en: "Network security", re: /tls|ssl|header|server:|port|nmap|httponly|samesite|spf|dmarc|asn|rdap/i },
      { key: "data", es: "Protección de datos", en: "Data protection", re: /secret|bak|sql|encrypt|config\.inc|db_password|phpinfo|hardcodeada|bucket|listable|arn aws|access key/i },
      { key: "ir", es: "Respuesta a incidentes", en: "Incident response", re: /command injection|rce|allow_url|file inclusion|upload/i },
      { key: "aware", es: "Concienciación", en: "Awareness", re: /dvwa|damn vulnerable|security.?low|debug|display_errors/i },
      { key: "assets", es: "Gestión de activos", en: "Asset management", re: /robots|sitemap|directory|directorio|listable|listado|document root/i },
    ];
    var langEn = (window.DarkSpear && DarkSpear.lang && DarkSpear.lang() === "en");
    return defs.map(function (d) {
      var hits = (findings || []).filter(function (f) {
        return d.re.test(((f.title || "") + " " + (f.description || "")).toLowerCase());
      });
      var penalty = 0;
      hits.filter(isFindingOpen).forEach(function (f) {
        var s = String(f.severity || "").toLowerCase();
        if (s === "critical") penalty += 1.6;
        else if (s === "high") penalty += 0.9;
        else if (s === "medium") penalty += 0.4;
        else penalty += 0.15;
      });
      var actual = Math.max(1, Math.min(5, Math.round((5 - penalty) * 10) / 10));
      var examples = hits.slice(0, 3).map(function (f) { return f.title || ""; }).filter(Boolean);
      return {
        key: d.key,
        label: langEn ? d.en : d.es,
        actual: actual,
        target: 4,
        hits: hits.length,
        examples: examples,
      };
    });
  }

  var maturityRadarCharts = {};
  function renderMaturityRadar(domains, canvasId) {
    var id = canvasId || "maturity-radar";
    var canvas = document.getElementById(id);
    if (!canvas || typeof Chart === "undefined") return;
    if (maturityRadarCharts[id]) {
      maturityRadarCharts[id].destroy();
      maturityRadarCharts[id] = null;
    }
    var labels = domains.map(function (d) { return d.label; });
    var actual = domains.map(function (d) { return d.actual; });
    var target = domains.map(function (d) { return d.target; });
    maturityRadarCharts[id] = new Chart(canvas, {
      type: "radar",
      data: {
        labels: labels,
        datasets: [
          {
            label: tKey("maturity.actual", "Actual"),
            data: actual,
            fill: true,
            backgroundColor: "rgba(0, 120, 212, 0.22)",
            borderColor: "#0078d4",
            borderWidth: 2,
            pointBackgroundColor: "#0078d4",
            pointRadius: 4,
          },
          {
            label: tKey("maturity.target", "Objetivo"),
            data: target,
            fill: false,
            borderColor: "#0a8575",
            borderWidth: 2,
            borderDash: [6, 4],
            pointBackgroundColor: "#0a8575",
            pointRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          r: {
            min: 0,
            max: 5,
            ticks: { stepSize: 1, showLabelBackdrop: false },
            pointLabels: { font: { family: "Public Sans", size: 11, weight: "600" } },
          },
        },
      },
    });
  }

  function coverageClass(level) {
    if (level === "high") return "tech-high";
    if (level === "partial") return "tech-partial";
    return "tech-none";
  }

  function bootMitre() {
    var listView = document.getElementById("mitre-list-view");
    var detailView = document.getElementById("mitre-detail-view");
    var headers = document.getElementById("mitre-headers");
    var matrix = document.getElementById("mitre-matrix");
    var cardsEl = document.getElementById("mitre-scans-cards");
    var emptyEl = document.getElementById("mitre-scans-empty");
    if (!listView || !detailView) return;

    var params = new URLSearchParams(location.search);
    var scanId = params.get("scan") || "";
    var state = {
      view: scanId === "program" ? "cobertura" : "observadas",
      search: "",
      listSearch: "",
      observed: {},
      scanId: scanId,
      scans: [],
    };

    function collectObserved(findings) {
      var map = {};
      (findings || []).forEach(function (f) {
        if (f && f.status === "rejected") return;
        mitreForFinding(f).forEach(function (t) {
          if (!map[t.id]) map[t.id] = { count: 0, findings: [], name: t.name, tactic: t.tactic };
          map[t.id].count += 1;
          map[t.id].findings.push(f);
        });
      });
      return map;
    }

    function observedCountForFindings(findings) {
      return Object.keys(collectObserved(findings)).length;
    }

    function levelFor(tech) {
      var obs = state.observed[tech.id];
      if (state.view === "observadas") {
        if (!obs) return "none";
        if (obs.count >= 2 || (obs.findings[0] && /critical|high/i.test(obs.findings[0].severity || ""))) return "high";
        return "partial";
      }
      if (state.view === "inteligencia") {
        if (obs) {
          if (obs.count >= 2 || (obs.findings[0] && /critical|high/i.test(obs.findings[0].severity || ""))) return "high";
          return "partial";
        }
        return tech.coverage === "none" ? "partial" : tech.coverage;
      }
      return tech.coverage || "none";
    }

    function setActiveViewBtn() {
      document.querySelectorAll(".mitre-view-btn").forEach(function (b) {
        var on = b.getAttribute("data-view") === state.view;
        b.classList.toggle("active", on);
        b.classList.toggle("text-on-surface-variant", !on);
      });
    }

    function renderMatrix() {
      if (!headers || !matrix) return;
      headers.innerHTML = "";
      matrix.innerHTML = "";
      var q = state.search;
      var observedOnly = state.view === "observadas" && state.scanId !== "program";

      MITRE_MATRIX.forEach(function (col, colIdx) {
        var shown = col.techniques.filter(function (t) {
          if (q) {
            var hay = (t.id + " " + t.name).toLowerCase();
            if (hay.indexOf(q) < 0) return false;
          }
          if (observedOnly && !state.observed[t.id]) return false;
          return true;
        });

        var covered = col.techniques.filter(function (t) {
          return t.coverage === "high" || t.coverage === "partial";
        }).length;
        var foundInCol = col.techniques.filter(function (t) {
          return !!state.observed[t.id];
        }).length;

        var head = document.createElement("div");
        head.className = "flex-1 min-w-[200px] p-sm" + (colIdx < MITRE_MATRIX.length - 1 ? " border-r border-outline-variant" : "");
        var sub =
          state.view === "observadas" && state.scanId !== "program"
            ? foundInCol + " observada" + (foundInCol === 1 ? "" : "s")
            : covered + " cubiertas · " + col.count + " en marco";
        head.innerHTML = "<h3 class=\"font-label-md text-label-md text-on-surface\">" + escapeHtml(col.tactic) +
          "</h3><span class=\"font-body-sm text-body-sm text-on-surface-variant\">" +
          escapeHtml(sub) + "</span>";
        headers.appendChild(head);

        var column = document.createElement("div");
        column.className = "flex-1 min-w-[184px] flex flex-col gap-xs self-start";
        shown.forEach(function (t) {
          var lvl = levelFor(t);
          var card = document.createElement("button");
          card.type = "button";
          card.className = coverageClass(lvl) + " rounded-md p-xs border shadow-sm cursor-pointer hover:brightness-110 transition-all text-left";
          var obs = state.observed[t.id];
          card.innerHTML =
            "<div class=\"flex justify-between items-start mb-1\">" +
            "<span class=\"font-label-md text-label-md\">" + escapeHtml(t.id) + "</span>" +
            (obs ? "<span class=\"font-mono-md text-[10px] opacity-80\">×" + obs.count + "</span>" : "") +
            "</div><span class=\"font-body-sm text-body-sm leading-tight block\">" + escapeHtml(t.name) + "</span>";
          card.addEventListener("click", function () {
            var first = obs && obs.findings[0];
            if (first) location.href = findingHref(first);
            else location.href = "vulnerabilities.html";
          });
          column.appendChild(card);
        });
        if (!shown.length) {
          column.innerHTML = "<p class=\"font-body-sm text-on-surface-variant italic p-xs\">" +
            (observedOnly ? "Ninguna observada en este escaneo" : "Sin técnicas") + "</p>";
        }
        matrix.appendChild(column);
      });

      var n = Object.keys(state.observed).length;
      var countEl = document.getElementById("mitre-observed-count");
      if (countEl) {
        if (state.scanId === "program" || state.view === "cobertura") {
          countEl.textContent = "Cobertura del programa";
        } else if (state.view === "inteligencia") {
          countEl.textContent = "Capacidad + hallazgos del escaneo";
        } else {
          countEl.textContent = n + " técnica" + (n === 1 ? "" : "s") + " en este escaneo";
        }
      }
      var legendHint = document.getElementById("mitre-legend-hint");
      if (legendHint) {
        if (state.scanId === "program" || state.view === "cobertura") {
          legendHint.textContent = "Colores = lo que Dark Spear puede cubrir.";
        } else if (state.view === "inteligencia") {
          legendHint.textContent = "Mezcla capacidad del producto y hallazgos de este escaneo.";
        } else {
          legendHint.textContent = "Colores = técnicas encontradas en este escaneo.";
        }
      }
    }

    function formatStarted(ts) {
      if (!ts) return "—";
      var ms = ts < 1e12 ? ts * 1000 : ts;
      try {
        return new Date(ms).toLocaleString();
      } catch (e) {
        return "—";
      }
    }

    function renderScanCards() {
      if (!cardsEl || !emptyEl) return;
      var q = state.listSearch;
      var list = (state.scans || []).filter(function (s) {
        if (!q) return true;
        return scanSearchHay(s).indexOf(q) >= 0;
      });
      cardsEl.innerHTML = "";
      if (!list.length) {
        emptyEl.hidden = false;
        cardsEl.hidden = true;
        return;
      }
      emptyEl.hidden = true;
      cardsEl.hidden = false;
      list.forEach(function (s) {
        var badge = s.active
          ? '<span class="bg-primary-container/15 text-primary font-label-md text-label-md px-sm py-xs rounded shrink-0">En curso</span>'
          : '<span class="bg-surface-container-high text-on-surface-variant font-label-md text-label-md px-sm py-xs rounded shrink-0">' +
            escapeHtml(s.status || "completado") + "</span>";
        var techHint = typeof s.techniques_observed === "number"
          ? s.techniques_observed + " técnicas MITRE"
          : (s.findings_count || 0) + " hallazgos";
        var title = scanDisplayName(s);
        var sub = (s.name || s.objective)
          ? "Target: " + (s.target || "—") + " · Scope: " + (s.scope || "—")
          : "Scope: " + (s.scope || "—");
        var card = document.createElement("article");
        card.className = "glass-panel rounded-xl p-md flex flex-col gap-md";
        card.innerHTML =
          '<div class="flex justify-between items-start gap-md">' +
          '<div class="min-w-0">' +
          '<h3 class="font-headline-md text-headline-md text-on-surface truncate">' + escapeHtml(title) + "</h3>" +
          '<p class="font-mono-md text-mono-md text-secondary mt-xs truncate">' + escapeHtml(sub) + "</p>" +
          "</div>" + badge + "</div>" +
          '<div class="flex flex-wrap gap-md font-body-sm text-on-surface-variant border-t border-outline-variant/30 pt-sm">' +
          "<span>" + escapeHtml(formatStarted(s.started_at)) + "</span>" +
          (s.phase ? "<span>Fase " + escapeHtml(String(s.phase)) + "</span>" : "") +
          "<span>" + escapeHtml(techHint) + "</span>" +
          "</div>" +
          '<div class="flex justify-end">' +
          '<a class="px-md py-sm bg-primary-container text-on-primary-container rounded-lg font-label-md flex items-center gap-xs hover:bg-primary transition-colors" href="mitre.html?scan=' +
          encodeURIComponent(s.id) + '">' +
          '<i data-lucide="swords" class="icon-sm"></i><span>Ver matriz MITRE</span></a></div>';
        cardsEl.appendChild(card);
      });
      if (window.lucide) lucide.createIcons();
    }

    function showList() {
      listView.hidden = true;
      detailView.hidden = true;
      listView.hidden = false;
      detailView.hidden = true;
      listView.style.display = "";
      detailView.style.display = "none";
      bridgePost("/engagements/list", {}).then(function (data) {
        var rows = (data && data.engagements) || [];
        // Enriquecer técnicas observadas (async por tarjeta sería lento; count findings basta + fetch light)
        state.scans = rows;
        renderScanCards();
        // Contar técnicas MITRE por escaneo (solo activos / con pocos hallazgos vía findings endpoint es caro;
        // usar findings_count en tarjeta; para activos enriquecer con loadFindings)
        if (!rows.length) {
          return Promise.all([fetchStatus(), loadFindings()]).then(function (res) {
            var status = res[0] || {};
            var findings = res[1] || [];
            if (status.active && status.engagement_dir) {
              state.scans = [{
                id: status.engagement_dir,
                target: status.target,
                scope: status.scope,
                started_at: Date.now() / 1000 - (status.elapsed_seconds || 0),
                status: "running",
                phase: status.phase,
                findings_count: findings.length,
                techniques_observed: observedCountForFindings(findings),
                active: true,
              }];
              renderScanCards();
            } else if (findings.length) {
              state.scans = [{
                id: "inbox",
                target: (loadRun() && loadRun().target) || "Sesión actual",
                scope: (loadRun() && loadRun().scope) || "—",
                started_at: Date.now() / 1000,
                status: "local",
                findings_count: findings.length,
                techniques_observed: observedCountForFindings(findings),
                active: false,
              }];
              renderScanCards();
            }
          });
        }
        // Enriquecer técnicas del activo
        rows.forEach(function (row) {
          if (!row.active) return;
          loadFindings().then(function (findings) {
            row.techniques_observed = observedCountForFindings(findings);
            row.findings_count = findings.length;
            renderScanCards();
          });
        });
      });
    }

    function showDetail(id) {
      listView.hidden = true;
      detailView.hidden = false;
      listView.style.display = "none";
      detailView.style.display = "";
      setActiveViewBtn();

      var titleEl = document.getElementById("mitre-detail-title");
      var subEl = document.getElementById("mitre-detail-subtitle");
      var toggles = document.getElementById("mitre-view-toggles");

      if (id === "program") {
        if (titleEl) titleEl.textContent = "Cobertura del programa";
        if (subEl) subEl.textContent = "Capacidad Dark Spear · MITRE ATT&CK v14.1";
        if (toggles) toggles.hidden = true;
        state.view = "cobertura";
        state.observed = {};
        renderMatrix();
        return;
      }

      if (toggles) toggles.hidden = false;
      state.view = "observadas";
      setActiveViewBtn();

      function applyMeta(meta, findings) {
        if (titleEl) titleEl.textContent = scanDisplayName(meta) || id;
        if (subEl) {
          subEl.textContent =
            (meta.scope ? "Scope: " + meta.scope + " · " : "") +
            (findings.length || 0) + " hallazgos · " +
            Object.keys(state.observed).length + " técnicas MITRE";
        }
        renderMatrix();
      }

      if (id === "inbox") {
        loadFindings().then(function (findings) {
          state.observed = collectObserved(findings);
          applyMeta({ target: "Sesión actual", scope: "" }, findings);
        });
        return;
      }

      Promise.all([
        bridgePost("/engagements/findings", { engagement_dir: id }),
        bridgePost("/engagements/list", {}),
      ]).then(function (res) {
        var payload = res[0] || {};
        var list = ((res[1] && res[1].engagements) || []).find(function (e) {
          return e.id === id;
        }) || { target: id, scope: "" };
        var findings = payload.findings || [];
        state.observed = collectObserved(findings);
        applyMeta(list, findings);
      });
    }

    document.querySelectorAll(".mitre-view-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.view = btn.getAttribute("data-view") || "observadas";
        setActiveViewBtn();
        renderMatrix();
      });
    });

    var matrixSearch = document.getElementById("mitre-matrix-search");
    if (matrixSearch) {
      matrixSearch.addEventListener("input", function (e) {
        state.search = String(e.target.value || "").toLowerCase().trim();
        renderMatrix();
      });
    }

    var listSearch = document.getElementById("mitre-list-search");
    if (listSearch) {
      listSearch.addEventListener("input", function (e) {
        state.listSearch = String(e.target.value || "").toLowerCase().trim();
        renderScanCards();
      });
    }

    var exportBtn = document.getElementById("mitre-export-btn");
    if (exportBtn) {
      exportBtn.addEventListener("click", function () {
        var rows = [];
        MITRE_MATRIX.forEach(function (col) {
          col.techniques.forEach(function (t) {
            var o = state.observed[t.id];
            rows.push({
              id: t.id,
              name: t.name,
              tactic: col.tactic,
              program_coverage: t.coverage,
              observed_count: o ? o.count : 0,
              scan: state.scanId || null,
            });
          });
        });
        var blob = new Blob([JSON.stringify({ product: "Dark Spear", scan: state.scanId, mitre: rows }, null, 2)], {
          type: "application/json",
        });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "dark-spear-mitre-" + (state.scanId || "export") + ".json";
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    if (scanId) showDetail(scanId);
    else showList();
  }

  function relativeTime(ts) {
    if (!ts) return "—";
    var ms = normalizeTs(ts);
    if (!ms) return "—";
    var sec = Math.max(0, Math.floor(Date.now() / 1000 - ms / 1000));
    if (sec < 60) return "ahora";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    return Math.floor(sec / 86400) + "d";
  }

  function phaseLabel(status) {
    var names = {
      1: "Intelligence",
      2: "Enum & Vuln",
      3: "Exploitation",
      4: "Post-Exploit",
    };
    return status.status_badge || names[status.phase] || status.phase_name || "—";
  }

  function renderEngagementsTable(status, run, engagements) {
    var body = document.getElementById("panel-engagements-body");
    var empty = document.getElementById("panel-engagements-empty");
    var table = body ? body.closest("table") : null;
    if (!body) return;
    var rows = Array.isArray(engagements) ? engagements.slice() : [];
    if (!rows.length && status && status.active) {
      rows = [{
        id: status.engagement_dir || "",
        name: status.name || (run && run.name) || "",
        objective: status.objective || (run && run.objective) || "",
        target: status.target || (run && run.target) || "",
        active: true,
        phase: status.phase,
        status: status.status_badge || "running",
        findings_count: (status.findings_accepted || 0) + (status.findings_pending || 0),
        progress_pct: status.progress_pct || 0,
      }];
    }
    if (!rows.length) {
      body.innerHTML = "";
      if (table) table.hidden = true;
      if (empty) empty.hidden = false;
      return;
    }
    if (table) table.hidden = false;
    if (empty) empty.hidden = true;
    body.innerHTML = rows.slice(0, 10).map(function (e) {
      var label = (e.name || e.objective || e.target || "—").trim() || "—";
      var target = e.target || "—";
      var isActive = !!e.active;
      var pct = isActive
        ? (e.progress_pct != null
          ? Number(e.progress_pct)
          : (status && status.active && status.engagement_dir === (e.engagement_dir || e.id)
            ? (status.progress_pct || 0)
            : 10))
        : 100;
      if (!isFinite(pct)) pct = 0;
      pct = Math.max(0, Math.min(100, Math.round(pct)));
      var phase = isActive
        ? phaseLabel(Object.assign({}, status || {}, { phase: e.phase, status_badge: e.status_badge || e.status }))
        : (e.status || "completed");
      var sid = e.id || e.engagement_dir || "";
      var href = sid
        ? "reporting.html?scan=" + encodeURIComponent(sid)
        : (isActive ? "engagement.html" : "active-scans.html");
      return '<tr class="border-b border-outline-variant/10 hover:bg-surface-container-low/50 transition-colors">' +
        '<td class="py-sm"><a class="text-primary hover:underline font-label-md" href="' + href + '">' +
        escapeHtml(label) + "</a>" +
        (e.findings_count != null
          ? '<span class="block font-body-sm text-on-surface-variant mt-xs">' +
            Number(e.findings_count) + " hallazgos</span>"
          : "") +
        "</td>" +
        '<td class="py-sm pr-md"><div class="flex items-center gap-xs">' +
        '<div class="w-full bg-surface-variant rounded-full h-1.5"><div class="bg-primary h-1.5 rounded-full" style="width:' + pct + '%"></div></div>' +
        '<span class="font-mono-md text-mono-md text-on-surface-variant">' + pct + "%</span></div></td>" +
        '<td class="py-sm"><span class="font-mono-md text-mono-md">' + escapeHtml(target) + "</span></td>" +
        '<td class="py-sm"><span class="px-2 py-1 bg-surface-variant text-on-surface-variant rounded-md text-[10px] font-semibold tracking-wide uppercase">' +
        escapeHtml(String(phase)) + "</span></td></tr>";
    }).join("");
  }

  function renderCriticalFindings(findings, status, run) {
    var list = document.getElementById("panel-critical-list");
    var empty = document.getElementById("panel-critical-empty");
    var allLink = document.getElementById("panel-critical-all");
    if (!list) return;
    var critical = (findings || []).filter(function (f) {
      return String(f.severity || "").toLowerCase() === "critical";
    }).slice(0, 3);
    if (!critical.length) {
      list.innerHTML = "";
      if (empty) empty.hidden = false;
      if (allLink) allLink.classList.add("hidden");
      return;
    }
    if (empty) empty.hidden = true;
    if (allLink) {
      allLink.classList.remove("hidden");
      var critTotal = countBySeverity(findings, ["critical"]);
      allLink.textContent = tKey("dash.viewAllCritical", "Ver todos los críticos") + " (" + critTotal + ")";
    }
    var engagement = (run && run.label) || status.target || "";
    list.innerHTML = critical.map(function (f) {
      var sev = String(f.severity || "critical").toUpperCase();
      return '<a class="bg-surface-container-lowest border border-outline-variant/30 rounded-lg p-sm hover:border-error/50 transition-colors cursor-pointer group block" href="' +
        escapeHtml(findingHref(f, status && (status.engagement_dir || status.id))) + '">' +
        '<div class="flex justify-between items-start mb-xs">' +
        '<span class="px-2 py-0.5 bg-error/10 text-error rounded text-[10px] font-bold tracking-wider">' + escapeHtml(sev) + "</span>" +
        '<span class="font-mono-md text-[10px] text-outline">' + escapeHtml(relativeTime(f.created_at)) + "</span></div>" +
        '<h4 class="font-body-md text-body-md font-semibold text-on-surface leading-tight mb-xs group-hover:text-primary transition-colors">' +
        escapeHtml(f.title || "Finding") + "</h4>" +
        '<p class="font-mono-md text-mono-md text-on-surface-variant truncate">Target: ' + escapeHtml(f.asset || "—") + "</p>" +
        (engagement ? '<p class="font-body-sm text-[11px] text-secondary mt-xs">' + escapeHtml(engagement) + "</p>" : "") +
        "</a>";
    }).join("");
  }

  function formatElapsed(sec) {
    sec = sec || 0;
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }

  /** Derive progress/time/steps when bridge status omits or zeroes them. */
  function enrichEngineStatus(status, engagements) {
    if (!status || !status.active) return status || { active: false };
    var out = Object.assign({}, status);
    var phase = Number(out.phase) || 1;
    var maxPhase = Number(out.max_phase) || 4;
    var steps = Number(out.step_count);
    if (!isFinite(steps)) steps = 0;

    var eng = null;
    if (Array.isArray(engagements) && engagements.length) {
      eng = engagements.find(function (e) { return e.active; }) ||
        (out.engagement_dir
          ? engagements.find(function (e) { return e.id === out.engagement_dir; })
          : null);
    }
    if (eng && eng.started_at && !out.started_at) out.started_at = eng.started_at;
    if (steps === 0 && eng && eng.step_count != null) {
      steps = Number(eng.step_count) || 0;
    }

    var elapsed = Number(out.elapsed_seconds);
    if (!isFinite(elapsed)) elapsed = 0;
    if (!elapsed && out.started_at) {
      var started = Number(out.started_at);
      if (isFinite(started) && started > 0) {
        var startedMs = started < 1e12 ? started * 1000 : started;
        elapsed = Math.max(0, Math.floor((Date.now() - startedMs) / 1000));
      }
    }
    if (!elapsed) {
      var run = loadRun();
      if (run && run.startedAt) {
        elapsed = Math.max(0, Math.floor((Date.now() - Number(run.startedAt)) / 1000));
      }
    }
    out.elapsed_seconds = elapsed;

    var phaseFloor = Math.round(((phase - 1) / maxPhase) * 100);
    var phaseSpan = Math.max(1, Math.round(100 / maxPhase));
    var stepBonus = Math.min(steps, 12) * 2;
    var computed = phaseFloor + Math.min(stepBonus, Math.max(0, phaseSpan - 1));
    if (phase > 1 || steps > 0) {
      computed = Math.min(99, Math.max(computed, phase > 1 ? Math.max(5, phaseFloor) : 5));
    } else {
      computed = 0;
    }

    var pct = Number(out.progress_pct);
    if (!isFinite(pct) || (pct === 0 && (phase > 1 || steps > 0))) {
      pct = computed;
    } else {
      pct = Math.max(pct, phaseFloor);
    }
    out.progress_pct = pct;
    out.step_count = steps;
    out.max_phase = maxPhase;

    if (!out.status_badge) {
      out.status_badge = phase <= 1 ? "Scanning" : phase <= 2 ? "Analyzing" : phase <= 3 ? "Exploiting" : "Active";
    }
    return out;
  }

  function renderEngineHealth(status) {
    var progressBar = document.getElementById("panel-engine-progress-bar");
    var progressLabel = document.getElementById("panel-engine-progress-label");
    var stepsBar = document.getElementById("panel-engine-steps-bar");
    var stepsLabel = document.getElementById("panel-engine-steps-label");
    var sync = document.getElementById("panel-engine-sync");
    var dot = document.getElementById("panel-engine-status-dot");
    var phaseEl = document.getElementById("panel-engine-phase");
    var badgeEl = document.getElementById("panel-engine-badge");
    var elapsedEl = document.getElementById("panel-engine-elapsed");
    var findingsEl = document.getElementById("panel-engine-findings");
    var active = status && status.active;
    var run = loadRun();
    var hasRun = !!(run && run.target);

    if (!active && hasRun) {
      if (phaseEl) phaseEl.textContent = "Esperando motor…";
      if (badgeEl) badgeEl.textContent = "—";
      if (progressLabel) progressLabel.textContent = "—";
      if (progressBar) progressBar.style.width = "0%";
      if (stepsLabel) stepsLabel.textContent = "—";
      if (stepsBar) stepsBar.style.width = "0%";
      if (sync) sync.textContent = "Sin conexión al bridge";
      if (elapsedEl) elapsedEl.textContent = "—";
      if (findingsEl) findingsEl.textContent = "—";
      if (dot) dot.className = "w-2 h-2 rounded-full bg-error";
      return;
    }

    if (!active) {
      if (phaseEl) phaseEl.textContent = "Sin engagement activo";
      if (badgeEl) badgeEl.textContent = "Idle";
      if (progressLabel) progressLabel.textContent = "0%";
      if (progressBar) progressBar.style.width = "0%";
      if (stepsLabel) stepsLabel.textContent = "0";
      if (stepsBar) stepsBar.style.width = "0%";
      if (sync) sync.textContent = "—";
      if (elapsedEl) elapsedEl.textContent = "—";
      if (findingsEl) findingsEl.textContent = "—";
      if (dot) dot.className = "w-2 h-2 rounded-full bg-outline";
      return;
    }

    var pct = status.progress_pct || 0;
    var steps = status.step_count || 0;
    var maxPhase = status.max_phase || 4;
    var phase = status.phase || 1;
    var stepsPct = Math.min(100, Math.round((steps / 20) * 100));

    if (phaseEl) {
      phaseEl.textContent = "Fase " + phase + "/" + maxPhase + " — " + (status.phase_name || "—");
    }
    if (badgeEl) badgeEl.textContent = status.status_badge || "Active";
    if (progressBar) progressBar.style.width = pct + "%";
    if (progressLabel) progressLabel.textContent = pct + "%";
    if (stepsBar) stepsBar.style.width = stepsPct + "%";
    if (stepsLabel) stepsLabel.textContent = String(steps) + " pasos";
    if (sync) {
      var act = status.current_activity || "—";
      sync.textContent = act.length > 42 ? act.slice(0, 42) + "…" : act;
      sync.title = status.current_activity || "";
    }
    if (elapsedEl) elapsedEl.textContent = formatElapsed(status.elapsed_seconds);
    if (findingsEl) {
      findingsEl.textContent = (status.findings_accepted || 0) + " acept. · " + (status.findings_pending || 0) + " pend.";
    }
    if (dot) dot.className = "w-2 h-2 rounded-full bg-tertiary-container animate-pulse";
  }

  function bootDashboard() {
    var kpis = document.querySelectorAll("[data-kpi]");
    if (!kpis.length) return;

    function render(findings, status, engagements) {
      var run = loadRun();
      var list = Array.isArray(engagements) ? engagements : [];
      var active = status && status.active ? 1 : 0;
      var critCount = countBySeverity(findings, ["critical"]);
      var map = {
        engagements: list.length || active,
        critical: critCount,
        scans: active,
        mttr: avgMttrLabel(findings),
      };
      kpis.forEach(function (el) {
        var key = el.getAttribute("data-kpi");
        if (map[key] != null) el.textContent = String(map[key]);
      });
      renderTrendsChart(findings);
      renderEngagementsTable(status, run, list);
      renderCriticalFindings(findings, status, run);
      renderEngineHealth(status);
      if (window.lucide) lucide.createIcons();
    }

    function refresh() {
      Promise.all([loadFindings(), fetchStatus(), loadEngagementScans()]).then(function (res) {
        var inbox = res[0] || [];
        var engagements = res[2] || [];
        var status = enrichEngineStatus(res[1] || {}, engagements);
        return loadFindingsFromScans(engagements).then(function (disk) {
          var live = status && status.active ? inbox : [];
          render(mergeFindingLists(disk, live), status, engagements);
        });
      });
    }
    refresh();
    setInterval(refresh, 5000);
  }

  function formatFindingDate(ts) {
    var ms = normalizeTs(ts);
    if (!ms) return "—";
    try {
      return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    } catch (e) {
      return "—";
    }
  }

  function severityBadgeHtml(sev) {
    var s = String(sev || "info").toLowerCase();
    if (s === "critical") {
      return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-error text-on-error">Critical</span>';
    }
    if (s === "high") {
      return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-[#ffe0b2] text-[#e65100]">High</span>';
    }
    if (s === "medium") {
      return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-surface-variant text-on-surface-variant">Medium</span>';
    }
    if (s === "low") {
      return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-tertiary-container text-on-tertiary-container">Low</span>';
    }
    return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-primary-container/15 text-primary">Info</span>';
  }

  function statusCellHtml(f) {
    var st = findingStatus(f);
    if (isFindingRemediated(f)) {
      return '<span class="inline-flex items-center gap-1 text-tertiary"><i data-lucide="circle-check" class="icon-sm"></i> ' +
        escapeHtml(tKey("finding.statusRemediated", "Remediado")) + "</span>";
    }
    if (st === "rejected") {
      return '<span class="inline-flex items-center gap-1 text-on-surface-variant"><i data-lucide="ban" class="icon-sm"></i> ' +
        escapeHtml(tKey("finding.statusRejected", "Rechazado")) + "</span>";
    }
    if (st === "edited" || st === "in_progress") {
      return '<span class="inline-flex items-center gap-1 text-[#e65100]"><i data-lucide="clock" class="icon-sm"></i> ' +
        escapeHtml(tKey("finding.statusInProgress", "En progreso")) + "</span>";
    }
    if (st === "accepted") {
      var sevA = String(f.severity || "").toLowerCase();
      var colorA = sevA === "critical" || sevA === "high" ? "text-error" : "text-on-surface";
      return '<span class="inline-flex items-center gap-1 ' + colorA + '"><i data-lucide="circle-alert" class="icon-sm"></i> ' +
        escapeHtml(tKey("finding.statusOpen", "Abierto")) + "</span>";
    }
    var sev = String(f.severity || "").toLowerCase();
    var color = sev === "critical" || sev === "high" ? "text-error" : "text-on-surface-variant";
    return '<span class="inline-flex items-center gap-1 ' + color + '"><i data-lucide="circle-alert" class="icon-sm"></i> ' +
      escapeHtml(tKey("finding.statusPending", "Pendiente")) + "</span>";
  }

  function bootVulnerabilities() {
    var tableWrap = document.getElementById("panel-findings-list");
    var empty = document.getElementById("panel-findings-list-empty");
    var tbody = document.getElementById("vulns-tbody");
    if (!tbody) return;

    var state = { sev: "all", search: "", page: 1, pageSize: 8, all: [] };
    var hub = null;

    function filtered() {
      return state.all.filter(function (f) {
        var s = String(f.severity || "").toLowerCase();
        if (state.sev !== "all" && s !== state.sev) return false;
        if (state.search) {
          var hay = ((f.title || "") + " " + (f.asset || "") + " " + (f.description || "")).toLowerCase();
          if (hay.indexOf(state.search) < 0) return false;
        }
        return true;
      });
    }

    function updateTabs() {
      var counts = { all: state.all.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      state.all.forEach(function (f) {
        var s = String(f.severity || "info").toLowerCase();
        if (counts[s] != null) counts[s]++;
        else counts.info++;
      });
      document.querySelectorAll(".vuln-tab").forEach(function (btn) {
        var key = btn.getAttribute("data-sev");
        var label = key.charAt(0).toUpperCase() + key.slice(1);
        if (key === "all") label = "All";
        btn.textContent = label + " (" + (counts[key] || 0) + ")";
        btn.classList.toggle("active", state.sev === key);
        btn.classList.toggle("text-on-surface", state.sev === key);
        btn.classList.toggle("text-on-surface-variant", state.sev !== key);
      });
    }

    function renderPage() {
      var list = filtered();
      var pages = Math.max(1, Math.ceil(list.length / state.pageSize) || 1);
      if (state.page > pages) state.page = pages;
      var start = (state.page - 1) * state.pageSize;
      var slice = list.slice(start, start + state.pageSize);
      tbody.innerHTML = "";
      if (!slice.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="py-lg px-4 text-center text-on-surface-variant italic">Sin hallazgos en este filtro.</td></tr>';
      } else {
        slice.forEach(function (f) {
          var tr = document.createElement("tr");
          tr.className = "border-b border-outline-variant/20 hover:bg-surface-container-low/50 transition-colors";
          var href = findingHref(f);
          tr.innerHTML =
            "<td class=\"py-3 px-4\">" + severityBadgeHtml(f.severity) + "</td>" +
            "<td class=\"py-3 px-4\"><a href=\"" + escapeHtml(href) + "\" class=\"font-semibold text-primary hover:underline\">" +
            escapeHtml(f.title || "Finding") + "</a></td>" +
            "<td class=\"py-3 px-4 font-mono-md text-mono-md text-on-surface-variant\">" + escapeHtml(f.asset || "—") + "</td>" +
            "<td class=\"py-3 px-4 text-on-surface-variant\">" + escapeHtml(formatFindingDate(f.created_at)) + "</td>" +
            "<td class=\"py-3 px-4\">" + statusCellHtml(f) + "</td>" +
            "<td class=\"py-3 px-4 text-right\"><a href=\"" + escapeHtml(href) +
            "\" class=\"inline-flex text-secondary hover:text-primary transition-colors p-1 rounded\" aria-label=\"Ver detalle\"><i data-lucide=\"ellipsis-vertical\" class=\"icon-md\"></i></a></td>";
          tbody.appendChild(tr);
        });
      }
      var endN = Math.min(start + state.pageSize, list.length);
      var pageLabel = document.getElementById("vulns-page-label");
      if (pageLabel) {
        pageLabel.textContent = list.length
          ? "Showing " + (list.length ? start + 1 : 0) + " to " + endN + " of " + list.length + " entries"
          : "Showing 0 entries";
      }
      var nums = document.getElementById("vulns-page-nums");
      if (nums) {
        nums.innerHTML = "";
        var maxButtons = Math.min(pages, 5);
        var from = Math.max(1, Math.min(state.page - 2, pages - maxButtons + 1));
        for (var i = from; i < from + maxButtons; i++) {
          var b = document.createElement("button");
          b.type = "button";
          b.textContent = String(i);
          b.className = i === state.page
            ? "px-3 py-1 bg-primary-container text-on-primary-container rounded font-label-md text-label-md"
            : "px-3 py-1 border border-outline-variant/50 rounded text-secondary hover:bg-surface-container-low font-label-md text-label-md";
          b.setAttribute("data-page", String(i));
          b.addEventListener("click", function (ev) {
            state.page = parseInt(ev.currentTarget.getAttribute("data-page"), 10);
            renderPage();
          });
          nums.appendChild(b);
        }
      }
      var prev = document.getElementById("vulns-prev");
      var next = document.getElementById("vulns-next");
      if (prev) prev.disabled = state.page <= 1;
      if (next) next.disabled = state.page >= pages;
      if (window.lucide) lucide.createIcons();
    }

    function applyFindings(items) {
      state.all = items || [];
      state.page = 1;
      if (empty) empty.hidden = true;
      if (tableWrap) tableWrap.hidden = false;
      updateTabs();
      renderPage();
    }

    document.querySelectorAll(".vuln-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.sev = btn.getAttribute("data-sev") || "all";
        state.page = 1;
        updateTabs();
        renderPage();
      });
    });

    function onSearch(val) {
      state.search = String(val || "").toLowerCase().trim();
      state.page = 1;
      renderPage();
    }
    var ts = document.getElementById("vulns-table-search");
    if (ts) ts.addEventListener("input", function (e) { onSearch(e.target.value); });
    var prevBtn = document.getElementById("vulns-prev");
    if (prevBtn) prevBtn.addEventListener("click", function () {
      if (state.page > 1) { state.page--; renderPage(); }
    });
    var nextBtn = document.getElementById("vulns-next");
    if (nextBtn) nextBtn.addEventListener("click", function () {
      state.page++;
      renderPage();
    });
    var exp = document.getElementById("vulns-export-btn");
    if (exp) exp.addEventListener("click", function () {
      var extra = { findings: state.all };
      if (hub && hub.state.meta) {
        extra.target = hub.state.meta.target;
        extra.scope = hub.state.meta.scope;
        extra.engagementId = hub.state.scanId;
      }
      if (window.DarkSpearExport && DarkSpearExport.csv) DarkSpearExport.csv(extra);
      else if (window.DarkSpearExport && DarkSpearExport.json) DarkSpearExport.json(extra);
    });

    if (document.getElementById("vulns-list-view")) {
      hub = bootScanHub({
        pageFile: "vulnerabilities.html",
        listViewId: "vulns-list-view",
        detailViewId: "vulns-detail-view",
        cardsId: "vulns-scans-cards",
        emptyId: "vulns-scans-empty",
        searchId: "vulns-list-search",
        titleId: "vulns-detail-title",
        subtitleId: "vulns-detail-subtitle",
        ctaLabel: tKey("vulns.open", "Ver vulnerabilidades"),
        ctaIcon: "bug",
        onDetail: function (findings) { applyFindings(findings); },
      });
    } else {
      loadFindings().then(applyFindings);
      setInterval(function () { loadFindings().then(applyFindings); }, 8000);
    }
  }

  var TECH_MEASURE_TITLE_RE = /WAF activo:|WAF\/CDN identificado:|Per[ií]metro con filtrado|HSTS (presente|activo|habilitado)|CSP (enforced|activa|presente)|firewall del host en (DROP|DENY)|INPUT (DROP|DENY)/i;
  var TECH_MEASURE_DESC_RE = /no es vulnerabilidad:\s*documenta que hay|hay un filtro delante del host|control activo delante de la app/i;
  var TECH_MEASURE_SKIP_RE = /[ií]ndice de exposici[oó]n|sin registro SPF|sin pol[ií]tica DMARC|Sin WAF\/CDN identificable|sin HSTS|CSP d[eé]bil|sin flag/i;

  function isObservedTechnicalMeasure(f) {
    if (!f || !f.title) return false;
    if (TECH_MEASURE_SKIP_RE.test(f.title)) return false;
    if (TECH_MEASURE_TITLE_RE.test(f.title)) return true;
    return TECH_MEASURE_DESC_RE.test(f.description || "");
  }

  function bootCriticalFindings() {
    var root = document.getElementById("panel-findings-list");
    var empty = document.getElementById("panel-findings-list-empty");
    var noneEl = document.getElementById("panel-findings-none");
    var measuresWrap = document.getElementById("panel-measures");
    var measuresList = document.getElementById("panel-measures-list");
    if (!root) return;

    function apply(allFindings, meta) {
      var all = allFindings || [];
      var crit = all.filter(function (f) {
        var s = String(f.severity || "").toLowerCase();
        return s === "critical" || s === "high";
      });
      var measures = all.filter(isObservedTechnicalMeasure);

      if (empty) empty.hidden = crit.length > 0 || measures.length > 0;
      if (noneEl) noneEl.hidden = !(crit.length === 0 && measures.length > 0);

      root.hidden = crit.length === 0;
      if (crit.length && window.DarkSpearFindings) DarkSpearFindings.renderList(root, crit, "all");
      else root.innerHTML = "";

      if (measuresWrap) {
        measuresWrap.hidden = measures.length === 0;
        if (measures.length && measuresList && window.DarkSpearFindings) {
          DarkSpearFindings.renderList(measuresList, measures, "all");
        } else if (measuresList) {
          measuresList.innerHTML = "";
        }
      }

      var sub = document.getElementById("critical-detail-subtitle");
      if (sub && meta) {
        sub.textContent =
          (scanDisplayName(meta) || meta.id || "") +
          " · Target: " + (meta.target || "—") +
          (meta.scope ? " · Scope: " + meta.scope : "") +
          " · " + crit.length + " " + tKey("critical.critCount", "críticos/altos") +
          " · " + measures.length + " " + tKey("critical.measuresCount", "medidas técnicas");
      }
      if (window.lucide) lucide.createIcons();
    }

    if (document.getElementById("critical-list-view")) {
      bootScanHub({
        pageFile: "critical-findings.html",
        listViewId: "critical-list-view",
        detailViewId: "critical-detail-view",
        cardsId: "critical-scans-cards",
        emptyId: "critical-scans-empty",
        searchId: "critical-list-search",
        titleId: "critical-detail-title",
        subtitleId: "critical-detail-subtitle",
        pageTitle: tKey("critical.title", "Hallazgos críticos"),
        ctaLabel: tKey("critical.open", "Ver hallazgos críticos"),
        ctaIcon: "triangle-alert",
        onDetail: function (findings, meta) { apply(findings, meta); },
      });
    } else {
      loadFindings().then(function (items) { apply(items || [], null); });
    }
  }

  function bootFindingsPage(containerId, filter) {
    if (filter === "critical") {
      bootCriticalFindings();
      return;
    }
    var root = document.getElementById(containerId);
    if (!root) return;
    if (document.getElementById("vulns-tbody")) return;

    function refresh() {
      loadFindings().then(function (items) {
        var list = items || [];
        toggleViews(containerId + "-empty", containerId, list.length > 0);
        if (!list.length) { root.innerHTML = ""; return; }
        if (window.DarkSpearFindings) DarkSpearFindings.renderList(root, list, filter || "all");
      });
    }
    refresh();
    setInterval(refresh, 8000);
  }

  function assetsKpiCard(icon, label, value, tone) {
    var toneCls = tone === "error"
      ? "text-error"
      : tone === "ok"
        ? "text-tertiary"
        : "text-on-surface";
    var labelCls = tone === "error" ? "text-error font-bold" : "text-on-surface-variant";
    return (
      '<div class="acrylic-panel rounded-xl p-md flex flex-col gap-sm ambient-shadow relative overflow-hidden min-h-[7.5rem]">' +
      '<div class="absolute -right-4 -top-4 w-24 h-24 ' +
      (tone === "error" ? "bg-error/5" : "bg-primary/5") +
      ' rounded-full blur-xl"></div>' +
      '<div class="flex items-center justify-between z-10">' +
      '<span class="font-label-md text-label-md uppercase tracking-wider ' + labelCls + '">' + escapeHtml(label) + "</span>" +
      '<span class="' + (tone === "error" ? "text-error" : "text-outline") + '"><i data-lucide="' + icon + '" class="icon-md"></i></span></div>' +
      '<p class="font-headline-xl text-[36px] font-bold leading-none ' + toneCls + ' z-10">' + escapeHtml(String(value)) + "</p></div>"
    );
  }

  function isHighSeverity(sev) {
    var s = String(sev || "").toLowerCase();
    return s === "critical" || s === "high";
  }

  function assetsInferType(asset, relatedFindings) {
    var blob = (asset || "").toLowerCase();
    (relatedFindings || []).forEach(function (f) {
      blob += " " + ((f.title || "") + " " + (f.description || "")).toLowerCase();
    });
    if (/aws|azure|gcp|s3|arn:|bucket|cloud|blob\.|storage\.googleapis/.test(blob)) {
      return { icon: "cloud", label: tKey("assets.typeCloud", "Almacenamiento cloud") };
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$|dns|subdomain|subdominio|mx record|ns record|server|host|port \d|nmap/.test(blob)) {
      return { icon: "server", label: tKey("assets.typeServer", "Servidor / DNS") };
    }
    if (/endpoint|workstation|wkst|laptop|desktop|computer|user device/.test(blob)) {
      return { icon: "monitor", label: tKey("assets.typeEndpoint", "Endpoint de usuario") };
    }
    if (/\.[a-z]{2,}$|domain|api\.|internal\.|corp|language|web app|http/.test(blob)) {
      return { icon: "globe", label: tKey("assets.typeDomain", "Dominio / aplicación web") };
    }
    return { icon: "server", label: tKey("assets.typeUnknown", "Activo") };
  }

  function assetsStatusForRow(assetRow, meta, status) {
    var target = ((meta && meta.target) || (status && status.target) || "").toLowerCase();
    var name = (assetRow.name || "").toLowerCase();
    var active = !!(meta && meta.active) || !!(status && status.active);
    var isTarget = !!(target && (name === target || name.indexOf(target) >= 0 || target.indexOf(name) >= 0));
    // "active" solo significa que el engagement sigue abierto (no se pulsó
    // Finalizar) — NO que el playbook siga ejecutando pasos. Una vez se
    // alcanza la última fase, el escaneo automático ya terminó aunque el
    // engagement quede abierto para revisión; dejar de mostrar "Escaneando".
    var phaseInfo = status || meta || {};
    var reachedMaxPhase = phaseInfo.phase != null && phaseInfo.max_phase != null
      && Number(phaseInfo.phase) >= Number(phaseInfo.max_phase);
    if (active && isTarget && !reachedMaxPhase) {
      return "scanning";
    }
    if (assetRow.openHighCrit > 0) return "vulnerable";
    return "protected";
  }

  function assetsStatusBadge(st) {
    if (st === "scanning") {
      return '<span class="bg-secondary-container border border-secondary-container/50 text-on-secondary-container font-label-md text-[11px] px-2 py-[2px] rounded-full inline-flex items-center gap-1">' +
        '<i data-lucide="loader-circle" class="icon-xs animate-spin"></i> ' +
        escapeHtml(tKey("assets.statusScanning", "Escaneando")) + "</span>";
    }
    if (st === "vulnerable") {
      return '<span class="bg-error-container/40 border border-error/20 text-on-error-container font-label-md text-[11px] px-2 py-[2px] rounded-full inline-flex items-center gap-1">' +
        '<span class="w-1.5 h-1.5 rounded-full bg-error"></span> ' +
        escapeHtml(tKey("assets.statusVulnerable", "Vulnerable")) + "</span>";
    }
    return '<span class="bg-tertiary-container/20 border border-tertiary-container/30 text-tertiary font-label-md text-[11px] px-2 py-[2px] rounded-full inline-flex items-center gap-1">' +
      '<span class="w-1.5 h-1.5 rounded-full bg-tertiary"></span> ' +
      escapeHtml(tKey("assets.statusProtected", "Protegido")) + "</span>";
  }

  function formatAssetLastScan(ms, scanning) {
    if (scanning) return tKey("assets.lastScanInProgress", "En curso…");
    if (!ms) return "—";
    var now = Date.now();
    var diff = now - ms;
    if (diff >= 0 && diff < 86400000) {
      var sec = Math.floor(diff / 1000);
      if (sec < 3600) {
        var mins = Math.max(1, Math.floor(sec / 60));
        return mins + " " + tKey("assets.minutesAgo", "min");
      }
      return Math.floor(sec / 3600) + " " + tKey("assets.hoursAgo", "h");
    }
    return formatFindingDate(ms);
  }

  function buildAssetInventory(findings, meta, status) {
    var map = {};
    var target = (meta && meta.target) || (status && status.target) || "";
    var scope = (meta && meta.scope) || (status && status.scope) || "";
    var engagementStart = meta && meta.started_at ? normalizeTs(meta.started_at) : null;

    function upsert(name, sub) {
      if (!name) return;
      if (!map[name]) {
        map[name] = {
          name: name,
          sub: sub || "",
          findings: [],
          lastScanMs: null,
          openHighCrit: 0,
        };
      }
      if (sub && !map[name].sub) map[name].sub = sub;
    }

    if (target) upsert(target, scope || tKey("assets.targetScope", "Target principal"));

    (findings || []).forEach(function (f) {
      var asset = (f.asset || "").trim();
      if (!asset) return;
      upsert(asset, "");
      map[asset].findings.push(f);
      var ts = normalizeTs(f.created_at || f.updated_at);
      if (ts && (!map[asset].lastScanMs || ts > map[asset].lastScanMs)) {
        map[asset].lastScanMs = ts;
      }
      if (isFindingOpen(f) && isHighSeverity(f.severity)) {
        map[asset].openHighCrit++;
      }
    });

    var rows = Object.keys(map).map(function (key) {
      var row = map[key];
      var typeInfo = assetsInferType(row.name, row.findings);
      var st = assetsStatusForRow(row, meta, status);
      if (!row.lastScanMs && engagementStart) row.lastScanMs = engagementStart;
      return {
        name: row.name,
        sub: row.sub || (row.findings.length ? row.findings.length + " " + tKey("scan.findings", "hallazgos") : ""),
        typeIcon: typeInfo.icon,
        typeLabel: typeInfo.label,
        status: st,
        lastScanMs: row.lastScanMs,
        openHighCrit: row.openHighCrit,
        findings: row.findings,
      };
    });

    rows.sort(function (a, b) {
      var order = { scanning: 0, vulnerable: 1, protected: 2 };
      var d = (order[a.status] || 9) - (order[b.status] || 9);
      if (d !== 0) return d;
      return a.name.localeCompare(b.name);
    });

    var thirtyDaysMs = 30 * 86400000;
    var now = Date.now();
    var unscanned = rows.filter(function (r) {
      if (!r.lastScanMs) return true;
      return now - r.lastScanMs > thirtyDaysMs;
    }).length;
    var vulnerable = rows.filter(function (r) { return r.status === "vulnerable"; }).length;

    return { rows: rows, total: rows.length, unscanned: unscanned, vulnerable: vulnerable };
  }

  function bootAssets() {
    var body = document.getElementById("panel-assets-body");
    var empty = document.getElementById("panel-assets-empty");
    if (!body) return;

    var hub = null;
    var uiState = { search: "", filter: "all", page: 1, pageSize: 10, rows: [] };

    function filteredRows() {
      return uiState.rows.filter(function (r) {
        if (uiState.filter !== "all" && r.status !== uiState.filter) return false;
        if (uiState.search) {
          var hay = (r.name + " " + r.sub + " " + r.typeLabel).toLowerCase();
          if (hay.indexOf(uiState.search) < 0) return false;
        }
        return true;
      });
    }

    function exportAssetsCsv(rows) {
      if (!rows.length) return;
      var lines = [[
        tKey("assets.colName", "Activo"),
        tKey("assets.colType", "Tipo"),
        tKey("assets.colStatus", "Estado"),
        tKey("assets.colLastScan", "Último escaneo"),
      ]];
      rows.forEach(function (r) {
        lines.push([
          r.name,
          r.typeLabel,
          r.status,
          formatAssetLastScan(r.lastScanMs, r.status === "scanning"),
        ]);
      });
      var csv = "\uFEFF" + lines.map(function (row) {
        return row.map(function (cell) {
          var s = String(cell == null ? "" : cell);
          if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
          return s;
        }).join(",");
      }).join("\n");
      var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "assets-" + Date.now() + ".csv";
      a.click();
      URL.revokeObjectURL(a.href);
    }

    function bindTableEvents() {
      var searchEl = document.getElementById("assets-table-search");
      if (searchEl) {
        searchEl.value = uiState.search;
        searchEl.oninput = function (e) {
          uiState.search = String(e.target.value || "").toLowerCase().trim();
          uiState.page = 1;
          renderTable();
        };
      }
      var filterBtn = document.getElementById("assets-btn-filter");
      var filterMenu = document.getElementById("assets-filter-menu");
      if (filterBtn && filterMenu) {
        filterBtn.onclick = function (e) {
          e.stopPropagation();
          filterMenu.classList.toggle("hidden");
        };
        filterMenu.querySelectorAll("[data-assets-filter]").forEach(function (opt) {
          opt.onclick = function () {
            uiState.filter = opt.getAttribute("data-assets-filter") || "all";
            uiState.page = 1;
            filterMenu.classList.add("hidden");
            renderTable();
          };
        });
      }
      var exportBtn = document.getElementById("assets-btn-export");
      if (exportBtn) {
        exportBtn.onclick = function () {
          exportAssetsCsv(filteredRows());
        };
      }
      var tableRefresh = document.getElementById("assets-btn-table-refresh");
      if (tableRefresh) {
        tableRefresh.onclick = function () {
          if (hub && hub.reloadDetail) hub.reloadDetail();
        };
      }
    }

    function renderTable() {
      var tableHost = document.getElementById("assets-table-host");
      if (!tableHost) return;
      var list = filteredRows();
      var pages = Math.max(1, Math.ceil(list.length / uiState.pageSize) || 1);
      if (uiState.page > pages) uiState.page = pages;
      var start = (uiState.page - 1) * uiState.pageSize;
      var slice = list.slice(start, start + uiState.pageSize);

      if (!slice.length) {
        tableHost.innerHTML =
          '<div class="ds-empty py-lg"><div class="ds-empty-icon"><i data-lucide="search-x" class="icon-lg"></i></div>' +
          '<p class="font-body-md text-on-surface-variant">' +
          escapeHtml(tKey("assets.noFilterMatch", "Ningún activo coincide con la búsqueda o el filtro.")) + "</p></div>";
      } else {
        tableHost.innerHTML =
          '<div class="overflow-x-auto"><table class="w-full text-left border-collapse min-w-[800px]">' +
          '<thead><tr class="border-b border-outline-variant/30 bg-surface-container-lowest/50">' +
          '<th class="font-label-md text-label-md text-on-surface-variant px-md py-sm font-semibold">' +
          escapeHtml(tKey("assets.colName", "Activo / ID")) + "</th>" +
          '<th class="font-label-md text-label-md text-on-surface-variant px-md py-sm font-semibold">' +
          escapeHtml(tKey("assets.colType", "Tipo")) + "</th>" +
          '<th class="font-label-md text-label-md text-on-surface-variant px-md py-sm font-semibold">' +
          escapeHtml(tKey("assets.colStatus", "Estado")) + "</th>" +
          '<th class="font-label-md text-label-md text-on-surface-variant px-md py-sm font-semibold">' +
          escapeHtml(tKey("assets.colLastScan", "Último escaneo")) + "</th>" +
          '<th class="font-label-md text-label-md text-on-surface-variant px-md py-sm font-semibold text-right">' +
          escapeHtml(tKey("assets.colActions", "Acciones")) + '</th></tr></thead><tbody class="font-body-sm text-body-sm divide-y divide-outline-variant/20">' +
          slice.map(function (r) {
            var scanUrl = "start-engagement.html?target=" + encodeURIComponent(r.name) +
              "&scope=" + encodeURIComponent((hub && hub.state.meta && hub.state.meta.scope) || r.name);
            return '<tr class="hover:bg-surface-container-low/50 transition-colors group">' +
              '<td class="px-md py-sm"><div class="flex items-center gap-sm">' +
              '<div class="w-8 h-8 rounded bg-surface-container flex items-center justify-center text-on-surface-variant border border-outline-variant/20">' +
              '<i data-lucide="' + r.typeIcon + '" class="icon-sm"></i></div>' +
              '<div><p class="font-medium text-on-surface">' + escapeHtml(r.name) + "</p>" +
              '<p class="text-on-surface-variant font-mono-md text-[11px]">' + escapeHtml(r.sub) + "</p></div></div></td>" +
              '<td class="px-md py-sm text-on-surface-variant">' + escapeHtml(r.typeLabel) + "</td>" +
              '<td class="px-md py-sm">' + assetsStatusBadge(r.status) + "</td>" +
              '<td class="px-md py-sm text-on-surface-variant">' +
              escapeHtml(formatAssetLastScan(r.lastScanMs, r.status === "scanning")) + "</td>" +
              '<td class="px-md py-sm text-right">' +
              '<a href="' + scanUrl + '" class="text-on-surface-variant hover:text-primary transition-colors p-1 inline-flex opacity-0 group-hover:opacity-100 focus:opacity-100" ' +
              'aria-label="' + escapeHtml(tKey("assets.scanTarget", "Escanear este target")) + '">' +
              '<i data-lucide="radar" class="icon-md"></i></a></td></tr>';
          }).join("") +
          "</tbody></table></div>";
      }

      var endN = Math.min(start + uiState.pageSize, list.length);
      var pageLabel = document.getElementById("assets-page-label");
      if (pageLabel) {
        pageLabel.textContent = list.length
          ? tKey("assets.pageShowing", "Mostrando {from}–{to} de {total} activos")
              .replace("{from}", String(list.length ? start + 1 : 0))
              .replace("{to}", String(endN))
              .replace("{total}", String(list.length))
          : tKey("assets.pageEmpty", "Sin activos");
      }
      var prevBtn = document.getElementById("assets-page-prev");
      var nextBtn = document.getElementById("assets-page-next");
      if (prevBtn) {
        prevBtn.disabled = uiState.page <= 1;
        prevBtn.onclick = function () { if (uiState.page > 1) { uiState.page--; renderTable(); } };
      }
      if (nextBtn) {
        nextBtn.disabled = uiState.page >= pages;
        nextBtn.onclick = function () { if (uiState.page < pages) { uiState.page++; renderTable(); } };
      }
      if (window.lucide) lucide.createIcons();
    }

    function renderAssets(findings, meta, scanId, status) {
      var target = (meta && meta.target) || "—";
      var scope = (meta && meta.scope) || "—";
      var inv = buildAssetInventory(findings, meta, status);
      uiState.rows = inv.rows;
      uiState.page = 1;

      var crumb = document.getElementById("assets-detail-crumb");
      var titleHidden = document.getElementById("assets-detail-title");
      var scanBtn = document.getElementById("assets-btn-scan-target");
      if (crumb) crumb.textContent = target;
      if (titleHidden) titleHidden.textContent = target;
      if (scanBtn) scanBtn.href = scanEngagementUrl(meta);

      var hasAssets = inv.rows.length > 0;
      if (empty) empty.hidden = hasAssets;
      body.hidden = !hasAssets;
      if (!hasAssets) {
        body.innerHTML = "";
        if (window.lucide) lucide.createIcons();
        return;
      }

      body.innerHTML =
        '<div class="grid grid-cols-1 md:grid-cols-3 gap-md md:gap-lg">' +
        assetsKpiCard("boxes", tKey("assets.kpiTotal", "Activos totales"), inv.total, "neutral") +
        assetsKpiCard("hourglass", tKey("assets.kpiUnscanned", "Sin escanear (30d)"), inv.unscanned, inv.unscanned ? "ok" : "neutral") +
        assetsKpiCard("triangle-alert", tKey("assets.kpiVulnerable", "Activos vulnerables"), inv.vulnerable, inv.vulnerable ? "error" : "neutral") +
        "</div>" +
        '<div class="acrylic-panel rounded-xl ambient-shadow flex flex-col flex-1 overflow-hidden">' +
        '<div class="p-md border-b border-outline-variant/30 flex flex-col sm:flex-row justify-between items-center gap-md">' +
        '<div class="relative w-full sm:w-96">' +
        '<i data-lucide="search" class="absolute left-sm top-1/2 -translate-y-1/2 text-outline-variant icon-sm pointer-events-none"></i>' +
        '<input id="assets-table-search" class="w-full bg-surface-container-lowest border border-outline-variant/50 rounded-lg pl-xl pr-sm py-sm font-body-sm text-body-sm text-on-surface focus:outline-none focus:border-b-2 focus:border-b-primary transition-all placeholder:text-outline-variant" ' +
        'placeholder="' + escapeHtml(tKey("assets.searchPlaceholder", "Buscar por nombre, ID o IP…")) + '" type="text"/></div>' +
        '<div class="flex items-center gap-sm w-full sm:w-auto relative">' +
        '<button type="button" id="assets-btn-filter" class="flex items-center gap-xs px-sm py-sm text-on-surface-variant hover:bg-surface-container-low rounded-lg transition-colors font-label-md">' +
        '<i data-lucide="list-filter" class="icon-sm"></i><span>' + escapeHtml(tKey("assets.filter", "Filtrar")) + "</span></button>" +
        '<div id="assets-filter-menu" class="hidden absolute top-full right-0 mt-xs z-20 min-w-[10rem] acrylic-panel rounded-lg shadow-lg border border-outline-variant/30 py-xs">' +
        '<button type="button" data-assets-filter="all" class="block w-full text-left px-md py-sm font-body-sm hover:bg-surface-container-low">' +
        escapeHtml(tKey("assets.filterAll", "Todos")) + "</button>" +
        '<button type="button" data-assets-filter="vulnerable" class="block w-full text-left px-md py-sm font-body-sm hover:bg-surface-container-low">' +
        escapeHtml(tKey("assets.statusVulnerable", "Vulnerable")) + "</button>" +
        '<button type="button" data-assets-filter="protected" class="block w-full text-left px-md py-sm font-body-sm hover:bg-surface-container-low">' +
        escapeHtml(tKey("assets.statusProtected", "Protegido")) + "</button>" +
        '<button type="button" data-assets-filter="scanning" class="block w-full text-left px-md py-sm font-body-sm hover:bg-surface-container-low">' +
        escapeHtml(tKey("assets.statusScanning", "Escaneando")) + "</button></div>" +
        '<div class="w-px h-6 bg-outline-variant/30 mx-xs"></div>' +
        '<button type="button" id="assets-btn-export" class="p-sm text-on-surface-variant hover:bg-surface-container-low rounded-lg transition-colors" title="' +
        escapeHtml(tKey("assets.exportCsv", "Exportar CSV")) + '"><i data-lucide="download" class="icon-md"></i></button>' +
        '<button type="button" id="assets-btn-table-refresh" class="p-sm text-on-surface-variant hover:bg-surface-container-low rounded-lg transition-colors" title="' +
        escapeHtml(tKey("assets.refresh", "Actualizar")) + '"><i data-lucide="refresh-cw" class="icon-md"></i></button></div></div>' +
        '<div id="assets-table-host"></div>' +
        '<div class="p-md border-t border-outline-variant/30 flex justify-between items-center bg-surface-container-lowest/30">' +
        '<span id="assets-page-label" class="font-body-sm text-body-sm text-on-surface-variant"></span>' +
        '<div class="flex gap-sm">' +
        '<button type="button" id="assets-page-prev" class="px-sm py-xs border border-outline-variant rounded text-on-surface-variant disabled:opacity-50 font-label-md">' +
        escapeHtml(tKey("assets.pagePrev", "Anterior")) + "</button>" +
        '<button type="button" id="assets-page-next" class="px-sm py-xs border border-outline-variant rounded text-on-surface hover:bg-surface-container-low font-label-md">' +
        escapeHtml(tKey("assets.pageNext", "Siguiente")) + "</button></div></div></div>";

      bindTableEvents();
      renderTable();
      if (window.lucide) lucide.createIcons();
      if (window.DarkSpearI18n && DarkSpearI18n.apply) DarkSpearI18n.apply(body);
    }

    document.addEventListener("click", function (e) {
      var menu = document.getElementById("assets-filter-menu");
      var btn = document.getElementById("assets-btn-filter");
      if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
        menu.classList.add("hidden");
      }
    });

    var refreshBtn = document.getElementById("assets-btn-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        if (hub && hub.reloadDetail) hub.reloadDetail();
      });
    }

    if (document.getElementById("assets-list-view")) {
      hub = bootScanHub({
        pageFile: "assets.html",
        listViewId: "assets-list-view",
        detailViewId: "assets-detail-view",
        cardsId: "assets-scans-cards",
        emptyId: "assets-scans-empty",
        searchId: "assets-list-search",
        titleId: "assets-detail-title",
        subtitleId: "assets-detail-subtitle",
        ctaLabel: tKey("assets.open", "Ver activos"),
        ctaIcon: "boxes",
        scanTargetCta: true,
        onDetail: function (findings, meta, id, status) {
          var subEl = document.getElementById("assets-detail-subtitle");
          if (subEl) {
            subEl.textContent =
              "Target: " + (meta.target || id) +
              (meta.scope ? " · Scope: " + meta.scope : "") +
              " · " + (findings.length || 0) + " " + tKey("scan.findings", "hallazgos");
          }
          renderAssets(findings, meta, id, status);
        },
      });
    } else {
      Promise.all([loadFindings(), fetchStatus()]).then(function (res) {
        renderAssets(res[0], { target: res[1].target, scope: res[1].scope }, null, res[1]);
      });
    }
  }

  function bootReporting() {
    var stats = document.getElementById("panel-report-stats");
    var findingsEl = document.getElementById("panel-report-findings");
    if (!stats && !document.getElementById("report-list-view")) return;

    var hub = null;

    function renderReport(findings) {
      var c = sevCounts(findings || []);
      if (stats) {
        stats.innerHTML = ["critical", "high", "medium", "low", "info"].map(function (k) {
          return "<div class=\"glass-panel rounded-lg p-md text-center\"><p class=\"font-label-md text-on-surface-variant uppercase\">" + k +
            "</p><p class=\"font-headline-xl\">" + c[k] + "</p></div>";
        }).join("");
      }
      if (findingsEl && window.DarkSpearFindings) {
        DarkSpearFindings.renderList(findingsEl, findings || [], "all");
      }
      var q = hub && hub.state.scanId ? ("?scan=" + encodeURIComponent(hub.state.scanId)) : "";
      var a1 = document.getElementById("report-link-comprehensive");
      var a2 = document.getElementById("report-link-executive");
      var a3 = document.getElementById("report-link-preview");
      if (a1) a1.href = "comprehensive-report.html" + q;
      if (a2) a2.href = "executive-summary.html" + q;
      if (a3) a3.href = "report-preview.html" + q;
    }

    document.querySelectorAll("[data-report-export]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-report-export");
        var extra = {
          findings: (hub && hub.state.findings) || [],
          target: hub && hub.state.meta ? hub.state.meta.target : undefined,
          scope: hub && hub.state.meta ? hub.state.meta.scope : undefined,
          engagementId: hub && hub.state.scanId,
        };
        if (window.DarkSpearExport && DarkSpearExport.run) DarkSpearExport.run(kind, extra);
      });
    });

    if (document.getElementById("report-list-view")) {
      hub = bootScanHub({
        pageFile: "reporting.html",
        listViewId: "report-list-view",
        detailViewId: "report-detail-view",
        cardsId: "report-scans-cards",
        emptyId: "panel-report-empty",
        searchId: "report-list-search",
        titleId: "report-detail-title",
        subtitleId: "report-detail-subtitle",
        footerId: "report-footer",
        ctaLabel: tKey("report.open", "Abrir informe"),
        ctaIcon: "chart-column",
        onDetail: function (findings) { renderReport(findings); },
      });
    } else if (stats) {
      loadFindings().then(function (f) { renderReport(f); });
    }
  }

  function computeExposureRisk(findings) {
    var skip = /índice de exposición|nuevo desde última auditoría|no reaparecen/i;
    var w = { critical: 1, high: 0.4, medium: 0.1, low: 0.02, info: 0 };
    var list = (findings || []).filter(function (f) {
      return f && f.status !== "rejected" && !skip.test(f.title || "");
    });
    var S = 0;
    var hasCritical = false;
    list.forEach(function (f) {
      var s = String(f.severity || "").toLowerCase();
      S += w[s] || 0;
      var blob = ((f.title || "") + " " + (f.description || "")).toLowerCase();
      if (s === "critical" && /secret|credencial|hardcodeada|bucket|listable|ssrf|viva confirmada/.test(blob)) {
        hasCritical = true;
      }
    });
    var E = Math.min(1 - Math.exp(-S / 25), 1 - 1e-15);
    if (hasCritical) E = Math.max(E, 0.5);
    var threatW = [];
    if (list.some(function (f) { return /viva confirmada|hardcodeada en bundle|access key/i.test(f.title || ""); })) threatW.push(0.8);
    if (list.some(function (f) { return /ssrf confirmado|listable públicamente/i.test(f.title || ""); })) threatW.push(0.9);
    var T = 0.05;
    if (threatW.length) {
      T = 1 - threatW.reduce(function (p, x) { return p * (1 - x); }, 1);
    }
    var I = hasCritical ? 0.9
      : list.some(function (f) { return /spf|dmarc|tenant|workspace/i.test((f.title || "").toLowerCase()); }) ? 0.4
        : 0.2;
    var likelihood = 1 - (1 - E) * (1 - T);
    var risk = Math.round(likelihood * I * 1000) / 10;
    var grade = risk >= 80 ? "F" : risk >= 60 ? "D" : risk >= 40 ? "C" : risk >= 20 ? "B" : "A";
    var eN = Math.round(E * 1000) / 10;
    var tN = Math.round(T * 1000) / 10;
    var iN = Math.round(I * 1000) / 10;
    var dominant = eN >= tN && eN >= iN ? "exposure" : tN >= iN ? "breach-likelihood" : "business-impact";
    return { risk: risk, grade: grade, exposure: eN, threat: tN, impact: iN, dominant: dominant };
  }

  function exposureRiskCardHtml(score) {
    var tone = score.grade === "A" || score.grade === "B" ? "text-tertiary"
      : score.grade === "C" ? "text-on-surface" : "text-error";
    return (
      '<div class="acrylic-panel rounded-xl p-lg ambient-shadow flex flex-col gap-sm">' +
      '<div class="flex items-start justify-between gap-md flex-wrap">' +
      '<div><p class="font-label-md text-label-md text-on-surface-variant uppercase tracking-wide">' +
      escapeHtml(tKey("osint.exposureTitle", "Índice de exposición")) + "</p>" +
      '<p class="font-headline-xl text-headline-xl ' + tone + ' mt-xs">' + escapeHtml(String(score.grade)) +
      ' <span class="font-body-md text-on-surface-variant">' + escapeHtml(String(score.risk)) + "/100</span></p></div>" +
      '<span class="text-primary"><i data-lucide="gauge" class="icon-md"></i></span></div>' +
      '<p class="font-body-sm text-on-surface-variant">' +
      escapeHtml(tKey("osint.exposureLead", "FAIR-lite sobre hallazgos de esta auditoría (exposición × amenaza × impacto). No comparable entre clientes.")) +
      "</p>" +
      '<div class="grid grid-cols-3 gap-sm font-body-sm text-on-surface-variant">' +
      "<span>E " + score.exposure + "</span><span>T " + score.threat + "</span><span>I " + score.impact + "</span></div></div>"
    );
  }

  function osintClassifyFindings(findings) {
    var creds = [];
    var appSecrets = [];
    var infra = [];
    var repos = [];
    var mentions = [];
    (findings || []).forEach(function (f) {
      var title = String(f.title || "");
      var blob = (title + " " + (f.description || "") + " " + (f.asset || "")).toLowerCase();
      if (/pastebin|haveibeenpwned|\bhibp\b|pwned.?password|credential.?dump|leak.?dump|github.?gist|gitlab.?snippet|stealer.?log/.test(blob)) {
        creds.push(f);
      } else if (/secretos de aplicaci[oó]n|db_password|credenciales por defecto|admin\/password|config\.inc\.php\.bak|\.env\b|aws_secret|application secrets|default cred|hardcodeada en bundle|viva confirmada/.test(blob)) {
        appSecrets.push(f);
      } else if (/github\.com|gitlab\.com|bitbucket\.org|repositorio p[uú]blico/.test(blob)) {
        repos.push(f);
      } else if (/\b(osint)\b/.test(blob) && /mencion|mention|exposure/.test(blob)) {
        mentions.push(f);
      } else if (/subdomain|subdominio|\bwhois\b|\brdap\b|crt\.sh|certificate transparency|registro dns|\bdig\b|nslookup|registro mx|robots\.txt|security\.txt|ssl-cert|cabeceras http|\bspf\b|\bdmarc\b|tenant|workspace|openid|saml|asn|prefijo/.test(blob)) {
        infra.push(f);
      }
    });
    return { creds: creds, appSecrets: appSecrets, infra: infra, repos: repos, mentions: mentions };
  }

  function isPrivateOrLocalTarget(target) {
    var t = String(target || "").toLowerCase().trim();
    t = t.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].replace(/^\[/, "").replace(/\]$/, "");
    if (!t || t === "localhost" || t === "::1") return true;
    if (/^127\./.test(t) || /^10\./.test(t) || /^192\.168\./.test(t)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(t)) return true;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return true;
    return false;
  }

  function osintKpiCard(icon, label, value, tone) {
    var toneCls = tone === "warn"
      ? "text-error"
      : tone === "ok"
        ? "text-tertiary"
        : "text-on-surface";
    return (
      '<div class="acrylic-panel rounded-xl p-md flex flex-col justify-between ambient-shadow min-h-[7.5rem]">' +
      '<div class="flex items-start justify-between gap-sm">' +
      '<p class="font-label-md text-label-md text-on-surface-variant uppercase tracking-wide">' + escapeHtml(label) + "</p>" +
      '<span class="text-primary"><i data-lucide="' + icon + '" class="icon-md"></i></span></div>' +
      '<p class="font-headline-xl text-headline-xl ' + toneCls + ' mt-md">' + escapeHtml(String(value)) + "</p></div>"
    );
  }

  function bootOsint() {
    var body = document.getElementById("panel-osint-body");
    if (!body) return;

    var hub = null;

    function renderOsint(findings, meta, scanId) {
      var target = (meta && meta.target) || "—";
      var scope = (meta && meta.scope) || "—";
      var groups = osintClassifyFindings(findings);
      var score = computeExposureRisk(findings);
      var kpiCreds = groups.creds.length;
      var kpiSubs = groups.infra.filter(function (f) {
        return /subdomain|subdominio|dns|crt\.sh|certificate transparency/.test(
          ((f.title || "") + " " + (f.description || "")).toLowerCase()
        );
      }).length;
      var kpiRepos = groups.repos.length;
      var kpiMentions = groups.mentions.length;

      var crumb = document.getElementById("osint-detail-crumb");
      var titleHidden = document.getElementById("osint-detail-title");
      var scanBtn = document.getElementById("osint-btn-scan-target");
      var mitreBtn = document.getElementById("osint-btn-mitre");
      if (crumb) crumb.textContent = target;
      if (titleHidden) titleHidden.textContent = target;
      if (scanBtn) scanBtn.href = scanEngagementUrl(meta);
      if (mitreBtn) {
        mitreBtn.href = scanId
          ? "mitre.html?scan=" + encodeURIComponent(scanId)
          : "mitre.html?scan=program";
      }

      var local = isPrivateOrLocalTarget(target);
      var banner = local
        ? '<div class="glass-panel rounded-xl p-md flex items-start gap-sm border-l-4 border-l-primary">' +
          '<i data-lucide="info" class="icon-md text-primary shrink-0 mt-xs"></i>' +
          '<p class="font-body-sm text-on-surface">' + escapeHtml(tKey("osint.localBanner",
            "El target es una IP o localhost. WHOIS, Certificate Transparency, subdominios y pastebin no aplican. El motor sí hace recon HTTP (cabeceras, robots, nmap). Los secretos hallados en el activo no son OSINT externo.")) +
          "</p></div>"
        : "";

      function osintFindingTable(items, emptyKey, emptyFb) {
        if (!items.length) {
          return '<div class="ds-empty py-lg"><div class="ds-empty-icon"><i data-lucide="circle-check" class="icon-lg"></i></div>' +
            '<p class="font-body-md text-on-surface-variant">' + escapeHtml(tKey(emptyKey, emptyFb)) + "</p></div>";
        }
        return '<div class="overflow-x-auto"><table class="w-full text-left border-collapse">' +
          '<thead><tr class="border-b border-outline-variant/40 font-label-md text-label-md text-on-surface-variant uppercase">' +
          "<th class=\"py-sm pr-md\">" + escapeHtml(tKey("osint.colFinding", "Hallazgo")) + "</th>" +
          "<th class=\"py-sm pr-md\">" + escapeHtml(tKey("osint.colAsset", "Activo")) + "</th>" +
          "<th class=\"py-sm\">" + escapeHtml(tKey("osint.colSeverity", "Severidad")) + "</th></tr></thead><tbody>" +
          items.slice(0, 12).map(function (f) {
            var sp = sevPill(f.severity);
            return "<tr class=\"border-b border-outline-variant/20 font-body-sm\">" +
              "<td class=\"py-sm pr-md text-on-surface\">" + escapeHtml(f.title || "—") + "</td>" +
              "<td class=\"py-sm pr-md font-mono-md text-secondary\">" + escapeHtml(f.asset || "—") + "</td>" +
              "<td class=\"py-sm\"><span class=\"" + sp.badge + " px-sm py-xs rounded font-label-md text-label-md\">" + escapeHtml(sp.label) + "</span></td></tr>";
          }).join("") +
          "</tbody></table></div>";
      }

      body.innerHTML =
        banner +
        exposureRiskCardHtml(score) +
        '<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-md">' +
        osintKpiCard("key-round", tKey("osint.kpiCreds", "Credenciales filtradas (OSINT)"), kpiCreds, kpiCreds ? "warn" : "neutral") +
        osintKpiCard("dns", tKey("osint.kpiSubdomains", "Subdominios expuestos"), kpiSubs, kpiSubs ? "warn" : "neutral") +
        osintKpiCard("folder-open", tKey("osint.kpiRepos", "Repos públicos"), kpiRepos, kpiRepos ? "warn" : "neutral") +
        osintKpiCard("megaphone", tKey("osint.kpiMentions", "Menciones críticas"), kpiMentions, kpiMentions ? "warn" : "neutral") +
        "</div>" +
        '<div class="acrylic-panel rounded-xl p-lg ambient-shadow flex flex-col gap-md">' +
        '<div class="flex items-center justify-between gap-md flex-wrap">' +
        '<h3 class="font-headline-md text-headline-md text-on-surface flex items-center gap-sm">' +
        '<i data-lucide="key-round" class="icon-md text-primary"></i>' +
        '<span>' + escapeHtml(tKey("osint.credsTable", "Credenciales en fuentes abiertas")) + "</span></h3></div>" +
        osintFindingTable(groups.creds, "osint.noCreds", "Sin credenciales filtradas en fuentes abiertas (pastebin, dumps, HIBP).") +
        "</div>" +
        (groups.appSecrets.length
          ? '<div class="acrylic-panel rounded-xl p-lg ambient-shadow flex flex-col gap-md">' +
            '<h3 class="font-headline-md text-headline-md text-on-surface flex items-center gap-sm">' +
            '<i data-lucide="lock" class="icon-md text-error"></i>' +
            '<span>' + escapeHtml(tKey("osint.appSecretsTitle", "Secretos hallados en el activo (pentest, no OSINT)")) + "</span></h3>" +
            osintFindingTable(groups.appSecrets, "osint.noCreds", "") +
            "</div>"
          : "") +
        '<div class="acrylic-panel rounded-xl p-lg ambient-shadow flex flex-col gap-md">' +
        '<div class="flex items-center justify-between gap-md flex-wrap">' +
        '<h3 class="font-headline-md text-headline-md text-on-surface flex items-center gap-sm">' +
        '<i data-lucide="server" class="icon-md text-primary"></i>' +
        '<span>' + escapeHtml(tKey("osint.infraTitle", "Infraestructura expuesta")) + "</span></h3>" +
        (scanId
          ? '<a class="font-label-md text-primary hover:underline flex items-center gap-xs" href="assets.html?scan=' +
            encodeURIComponent(scanId) + '"><i data-lucide="boxes" class="icon-sm"></i><span>' +
            escapeHtml(tKey("osint.viewAssets", "Ver mapa de activos")) + "</span></a>"
          : "") +
        "</div>" +
        (groups.infra.length
          ? '<ul class="flex flex-col gap-sm">' +
            groups.infra.slice(0, 16).map(function (f) {
              var sev = String(f.severity || "info").toLowerCase();
              var icon = sev === "critical" || sev === "high" ? "triangle-alert" : "circle-check";
              var iconCls = sev === "critical" || sev === "high" ? "text-error" : "text-tertiary";
              var sp = sevPill(f.severity);
              return '<li class="flex items-start gap-sm p-sm rounded-lg bg-surface-container-low/60 border border-outline-variant/30">' +
                '<span class="' + iconCls + ' mt-xs"><i data-lucide="' + icon + '" class="icon-sm"></i></span>' +
                '<div class="min-w-0 flex-1">' +
                '<p class="font-body-md text-on-surface">' + escapeHtml(f.title || "—") + "</p>" +
                '<p class="font-body-sm text-on-surface-variant mt-xs">' + escapeHtml((f.asset || f.description || "").slice(0, 160)) + "</p></div>" +
                '<span class="' + sp.badge + ' px-sm py-xs rounded font-label-md text-label-md shrink-0">' + escapeHtml(sp.label) + "</span></li>";
            }).join("") +
            "</ul>"
          : '<div class="ds-empty py-lg"><div class="ds-empty-icon"><i data-lucide="radar" class="icon-lg"></i></div>' +
            '<p class="font-body-md text-on-surface-variant">' + escapeHtml(tKey("osint.noInfra", "Sin infraestructura expuesta registrada. Ejecuta recon OSINT (fase 1) para poblar DNS, headers y certificados.")) + "</p></div>") +
        "</div>";

      if (window.lucide) lucide.createIcons();
      if (window.DarkSpearI18n && DarkSpearI18n.apply) DarkSpearI18n.apply(body);
    }

    var exportBtn = document.getElementById("osint-btn-export");
    if (exportBtn) {
      exportBtn.addEventListener("click", function () {
        if (!window.DarkSpearExport || !DarkSpearExport.run) return;
        DarkSpearExport.run("json", {
          findings: (hub && hub.state.findings) || [],
          target: hub && hub.state.meta ? hub.state.meta.target : undefined,
          scope: hub && hub.state.meta ? hub.state.meta.scope : undefined,
          engagementId: hub && hub.state.scanId,
        });
      });
    }

    var refreshBtn = document.getElementById("osint-btn-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        if (hub && hub.reloadDetail) hub.reloadDetail();
      });
    }

    if (document.getElementById("osint-list-view")) {
      hub = bootScanHub({
        pageFile: "osint.html",
        listViewId: "osint-list-view",
        detailViewId: "osint-detail-view",
        cardsId: "osint-scans-cards",
        emptyId: "osint-scans-empty",
        searchId: "osint-list-search",
        titleId: "osint-detail-title",
        subtitleId: "osint-detail-subtitle",
        ctaLabel: tKey("osint.open", "Ver OSINT"),
        ctaIcon: "binoculars",
        scanTargetCta: true,
        onDetail: function (findings, meta, id) {
          var subEl = document.getElementById("osint-detail-subtitle");
          if (subEl) {
            subEl.textContent =
              "Target: " + (meta.target || id) +
              (meta.scope ? " · Scope: " + meta.scope : "") +
              " · " + (findings.length || 0) + " " + tKey("scan.findings", "hallazgos");
          }
          renderOsint(findings, meta, id);
        },
      });
    } else {
      Promise.all([loadFindings(), fetchStatus()]).then(function (res) {
        renderOsint(res[0], { target: res[1].target, scope: res[1].scope }, null);
      });
    }
  }

  function adClassifyFindings(findings) {
    var domain = [];
    var users = [];
    var shares = [];
    var posture = [];
    var auth = [];
    var other = [];
    (findings || []).forEach(function (f) {
      var t = String((f && f.title) || "");
      if (!/^AD:/i.test(t) && !/SMB \(TCP\/445\)|LDAP \(TCP\/389\)|Kerberos \(TCP\/88\)|LDAPS \(TCP\/636\)/i.test(t)) return;
      if (/AS-REP|SPN|Kerberoastable|ADCS|WinRM|BloodHound|grupos privilegiados|política de contraseñas|complejidad de contraseña|delegación Kerberos|GPP |trust\(s\)|trusts de dominio/i.test(t)) auth.push(f);
      else if (/SMB signing|bind LDAP|longitud mínima|Domain Controller|escritura en C\$/i.test(t)) posture.push(f);
      else if (/usuario|RPC null|RID cycling|SAMR \(samrdump\)|netexec --users/i.test(t)) users.push(f);
      else if (/share|sesión nula|guest\/null/i.test(t)) shares.push(f);
      else if (/dominio|fingerprint|enum4linux\)|samrdump\)/i.test(t) || /TCP\/(445|389|88|636|135|5985)/.test(t)) domain.push(f);
      else if (/^AD:/i.test(t)) other.push(f);
    });
    return { domain: domain, users: users, shares: shares, posture: posture, auth: auth, other: other };
  }

  function bootAdAssessment() {
    var body = document.getElementById("panel-ad-body");
    if (!body) return;
    var hub = null;

    function renderAd(findings, meta, scanId) {
      var target = (meta && meta.target) || "—";
      var groups = adClassifyFindings(findings);
      var all = groups.domain.concat(groups.users, groups.shares, groups.posture, groups.auth, groups.other);
      var dcN = all.filter(function (f) { return /Domain Controller probable/i.test(f.title || ""); }).length;
      var crumb = document.getElementById("ad-detail-crumb");
      var scanBtn = document.getElementById("ad-btn-scan-target");
      var mitreBtn = document.getElementById("ad-btn-mitre");
      if (crumb) crumb.textContent = target;
      if (scanBtn) scanBtn.href = scanEngagementUrl(meta);
      if (mitreBtn) {
        mitreBtn.href = scanId
          ? "mitre.html?scan=" + encodeURIComponent(scanId)
          : "mitre.html?scan=program";
      }
      var graphBtn = document.getElementById("ad-btn-graph");
      if (graphBtn) {
        graphBtn.href = scanId
          ? "attack-graph.html?scan=" + encodeURIComponent(scanId)
          : "attack-graph.html";
      }

      function adTable(items) {
        if (!items.length) {
          return '<div class="ds-empty py-lg"><div class="ds-empty-icon"><i data-lucide="network" class="icon-lg"></i></div>' +
            '<p class="font-body-md text-on-surface-variant">' + escapeHtml(tKey("ad.noSignal",
              "Sin señales AD en este análisis. El playbook solo corre collection si nmap ve 445/389/88/636 o un banner SMB/AD.")) +
            "</p></div>";
        }
        return '<div class="overflow-x-auto"><table class="w-full text-left border-collapse">' +
          '<thead><tr class="border-b border-outline-variant/40 font-label-md text-label-md text-on-surface-variant uppercase">' +
          "<th class=\"py-sm pr-md\">" + escapeHtml(tKey("ad.colFinding", "Hallazgo")) + "</th>" +
          "<th class=\"py-sm pr-md\">" + escapeHtml(tKey("ad.colAsset", "Activo")) + "</th>" +
          "<th class=\"py-sm\">" + escapeHtml(tKey("ad.colSeverity", "Severidad")) + "</th></tr></thead><tbody>" +
          items.slice(0, 20).map(function (f) {
            var sp = sevPill(f.severity);
            return "<tr class=\"border-b border-outline-variant/20 font-body-sm\">" +
              "<td class=\"py-sm pr-md text-on-surface\">" + escapeHtml(f.title || "—") + "</td>" +
              "<td class=\"py-sm pr-md font-mono-md text-secondary\">" + escapeHtml(f.asset || "—") + "</td>" +
              "<td class=\"py-sm\"><span class=\"" + sp.badge + " px-sm py-xs rounded font-label-md text-label-md\">" +
              escapeHtml(sp.label) + "</span></td></tr>";
          }).join("") +
          "</tbody></table></div>";
      }

      body.innerHTML =
        '<div class="glass-panel rounded-xl p-md flex items-start gap-sm border-l-4 border-l-primary">' +
        '<i data-lucide="info" class="icon-md text-primary shrink-0 mt-xs"></i>' +
        '<p class="font-body-sm text-on-surface">' + escapeHtml(tKey("ad.banner",
          "Hallazgos AD (collection + enum). Kerberoast con -request, relay y shells requieren aprobación humana fuera del playbook automático.")) +
        "</p></div>" +
        (groups.auth.some(function (f) { return /BloodHound/i.test(f.title || ""); })
          ? '<div class="glass-panel rounded-xl p-md flex items-start gap-sm border-l-4 border-l-secondary">' +
            '<i data-lucide="share-2" class="icon-md text-secondary shrink-0 mt-xs"></i>' +
            '<p class="font-body-sm text-on-surface">' + escapeHtml(tKey("ad.bhHint",
              "BloodHound DCOnly dejó un zip en ~/.auditor/engagements/<id>/evidence/bloodhound/. Ábrelo en BloodHound CE offline; el Attack Graph del panel usa los hallazgos AD (no importa el zip todavía).")) +
            ' <a class="text-primary hover:underline font-label-md" href="' +
            (scanId ? "attack-graph.html?scan=" + encodeURIComponent(scanId) : "attack-graph.html") +
            '">' + escapeHtml(tKey("ad.viewGraph", "Ver Attack Graph")) + "</a></p></div>"
          : "") +
        '<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-md">' +
        osintKpiCard("network", tKey("ad.kpiDomain", "Dominio / fingerprint"), groups.domain.length + dcN, (groups.domain.length || dcN) ? "warn" : "neutral") +
        osintKpiCard("users", tKey("ad.kpiUsers", "Usuarios enumerados"), groups.users.length, groups.users.length ? "warn" : "neutral") +
        osintKpiCard("folder-open", tKey("ad.kpiShares", "Shares / null session"), groups.shares.length, groups.shares.length ? "warn" : "neutral") +
        osintKpiCard("shield-alert", tKey("ad.kpiPosture", "Postura (signing / LDAP / DC)"), groups.posture.length + dcN, (groups.posture.length || dcN) ? "warn" : "neutral") +
        osintKpiCard("key-round", tKey("ad.kpiAuth", "Auth (AS-REP / SPN / ADCS / WinRM)"), groups.auth.length, groups.auth.length ? "warn" : "neutral") +
        "</div>" +
        '<div class="acrylic-panel rounded-xl p-lg ambient-shadow flex flex-col gap-md">' +
        '<h3 class="font-headline-md text-headline-md text-on-surface flex items-center gap-sm">' +
        '<i data-lucide="network" class="icon-md text-primary"></i>' +
        '<span>' + escapeHtml(tKey("ad.tableTitle", "Inventario Active Directory")) + "</span></h3>" +
        adTable(all) +
        "</div>";

      if (window.lucide) lucide.createIcons();
      if (window.DarkSpearI18n && DarkSpearI18n.apply) DarkSpearI18n.apply(body);
    }

    var exportBtn = document.getElementById("ad-btn-export");
    if (exportBtn) {
      exportBtn.addEventListener("click", function () {
        if (!window.DarkSpearExport || !DarkSpearExport.run) return;
        var findings = ((hub && hub.state.findings) || []).filter(function (f) {
          return /^AD:/i.test(String(f.title || ""));
        });
        DarkSpearExport.run("json", {
          findings: findings,
          target: hub && hub.state.meta ? hub.state.meta.target : undefined,
          scope: hub && hub.state.meta ? hub.state.meta.scope : undefined,
          engagementId: hub && hub.state.scanId,
        });
      });
    }
    var refreshBtn = document.getElementById("ad-btn-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        if (hub && hub.reloadDetail) hub.reloadDetail();
      });
    }

    if (document.getElementById("ad-list-view")) {
      hub = bootScanHub({
        pageFile: "ad-assessment.html",
        listViewId: "ad-list-view",
        detailViewId: "ad-detail-view",
        cardsId: "ad-scans-cards",
        emptyId: "ad-scans-empty",
        searchId: "ad-list-search",
        titleId: "ad-detail-title",
        subtitleId: "ad-detail-subtitle",
        ctaLabel: tKey("ad.open", "Ver Active Directory"),
        ctaIcon: "network",
        scanTargetCta: true,
        onDetail: function (findings, meta, id) {
          var subEl = document.getElementById("ad-detail-subtitle");
          if (subEl) {
            var n = adClassifyFindings(findings);
            var count = n.domain.length + n.users.length + n.shares.length + n.posture.length + n.auth.length + n.other.length;
            subEl.textContent =
              "Target: " + (meta.target || id) +
              (meta.scope ? " · Scope: " + meta.scope : "") +
              " · " + count + " " + tKey("scan.findings", "hallazgos") + " AD";
          }
          renderAd(findings, meta, id);
        },
      });
    } else {
      Promise.all([loadFindings(), fetchStatus()]).then(function (res) {
        renderAd(res[0], { target: res[1].target, scope: res[1].scope }, null);
      });
    }
  }

  function bootNotifications() {
    var list = document.getElementById("notif-list");
    if (!list) return;

    var hub = null;
    var currentSev = "all";

    function apply(findings) {
      if (window.DarkSpearFindings) {
        DarkSpearFindings.renderList(list, findings || [], currentSev);
      } else {
        list.innerHTML = "";
      }
      if (window.lucide) lucide.createIcons();
    }

    var markAll = document.getElementById("mark-all");
    if (markAll) {
      markAll.addEventListener("click", function () {
        if (window.DarkSpearFindings) DarkSpearFindings.markAllRead();
        if (hub) hub.reloadDetail();
      });
    }

    var filterBtn = document.getElementById("notif-filter-btn");
    var filterMenu = document.getElementById("notif-filter-menu");
    if (filterBtn && filterMenu) {
      filterBtn.addEventListener("click", function () {
        var open = filterMenu.classList.toggle("hidden") === false;
        filterBtn.setAttribute("aria-expanded", open ? "true" : "false");
        if (window.lucide) lucide.createIcons();
      });
      filterMenu.querySelectorAll("[data-sev]").forEach(function (opt) {
        opt.addEventListener("click", function () {
          currentSev = opt.getAttribute("data-sev") || "all";
          list.setAttribute("data-filter", currentSev);
          apply((hub && hub.state.findings) || []);
          filterMenu.classList.add("hidden");
          filterBtn.setAttribute("aria-expanded", "false");
        });
      });
      document.addEventListener("click", function (e) {
        if (!filterBtn.contains(e.target) && !filterMenu.contains(e.target)) {
          filterMenu.classList.add("hidden");
          filterBtn.setAttribute("aria-expanded", "false");
        }
      });
    }

    if (document.getElementById("notif-list-view")) {
      hub = bootScanHub({
        pageFile: "notifications.html",
        listViewId: "notif-list-view",
        detailViewId: "notif-detail-view",
        cardsId: "notif-scans-cards",
        emptyId: "notif-scans-empty",
        searchId: "notif-list-search",
        titleId: "notif-detail-title",
        subtitleId: "notif-detail-subtitle",
        ctaLabel: tKey("notif.open", "Ver notificaciones"),
        /* empty copy: notif.scansEmpty */
        ctaIcon: "bell",
        onDetail: function (findings) { apply(findings); },
      });
    } else {
      loadFindings().then(apply);
    }
  }

  function hostLabel(urlOrHost) {
    var s = String(urlOrHost || "").trim();
    if (!s) return "Target";
    try {
      if (/^https?:\/\//i.test(s)) return new URL(s).host || s;
    } catch (e) { /* */ }
    return s.replace(/^https?:\/\//i, "").split("/")[0] || s;
  }

  function riskScoreFromFindings(list) {
    if (!list.length) return 0;
    var score = 0;
    list.forEach(function (f) {
      var s = String(f.severity || "").toLowerCase();
      if (s === "critical") score += 3.2;
      else if (s === "high") score += 2.4;
      else if (s === "medium") score += 1.4;
      else if (s === "low") score += 0.6;
      else score += 0.2;
    });
    return Math.min(10, Math.round(score * 10) / 10);
  }

  function sevPill(sev) {
    var s = String(sev || "info").toLowerCase();
    if (s === "critical" || s === "high") {
      return { border: "border-error", badge: "bg-error-container text-error", label: s === "critical" ? "Crítico" : "Alto" };
    }
    if (s === "medium") {
      return { border: "border-[#eab308]", badge: "bg-[#fef08a] text-[#854d0e]", label: "Medio" };
    }
    return { border: "border-outline-variant", badge: "bg-surface-variant text-on-surface-variant", label: s === "low" ? "Bajo" : "Info" };
  }

  function bootAttackGraph() {
    var stage = document.getElementById("panel-graph-stage");
    var nodesEl = document.getElementById("graph-nodes");
    var edgesEl = document.getElementById("graph-edges");
    if (!stage || !nodesEl || !edgesEl) return;

    var zoom = 1;
    var selectedId = "target";
    var graphModel = { nodes: [], edges: [], findingsByNode: {}, target: "" };

    function setZoom(z) {
      zoom = Math.max(0.6, Math.min(1.6, z));
      nodesEl.style.transform = "scale(" + zoom + ")";
      edgesEl.style.transform = "scale(" + zoom + ")";
      nodesEl.style.transformOrigin = "center center";
      edgesEl.style.transformOrigin = "center center";
    }

    document.getElementById("graph-zoom-in")?.addEventListener("click", function () { setZoom(zoom + 0.1); });
    document.getElementById("graph-zoom-out")?.addEventListener("click", function () { setZoom(zoom - 0.1); });
    document.getElementById("graph-zoom-reset")?.addEventListener("click", function () { setZoom(1); });
    document.getElementById("graph-detail-close")?.addEventListener("click", function () {
      selectedId = "internet";
      renderSelection();
    });

    var search = document.getElementById("graph-search");
    search?.addEventListener("input", function () {
      var q = (search.value || "").toLowerCase().trim();
      nodesEl.querySelectorAll("[data-node-id]").forEach(function (el) {
        var hay = (el.getAttribute("data-search") || "").toLowerCase();
        el.style.opacity = !q || hay.indexOf(q) >= 0 ? "1" : "0.25";
      });
    });

    function buildModel(findings, status) {
      var run = loadRun();
      var targetRaw = (status && status.target) || (run && run.target) || "";
      var target = hostLabel(targetRaw);
      var byAsset = {};
      (findings || []).forEach(function (f) {
        var key = hostLabel(f.asset || target);
        if (!byAsset[key]) byAsset[key] = [];
        byAsset[key].push(f);
      });
      var assets = Object.keys(byAsset);
      if (target && assets.indexOf(target) < 0) assets.unshift(target);
      if (!assets.length && target) assets = [target];

      var nodes = [
        { id: "internet", label: "Internet Externo", kind: "internet", x: 12, y: 22, icon: "globe" },
        { id: "target", label: target || "Target", kind: "server", x: 42, y: 42, icon: "server", badge: "", critical: false },
      ];
      var findingsByNode = { target: byAsset[target] || findings || [] };
      var primary = findingsByNode.target[0];
      if (primary) {
        var sev = String(primary.severity || "").toLowerCase();
        nodes[1].badge = (primary.title || "").slice(0, 22);
        nodes[1].critical = sev === "critical" || sev === "high";
      }

      var edges = [
        { from: "internet", to: "target", critical: findingsByNode.target.some(function (f) {
          var s = String(f.severity || "").toLowerCase();
          return s === "critical" || s === "high";
        }) },
      ];

      var extras = assets.filter(function (a) { return a !== target; }).slice(0, 3);
      extras.forEach(function (asset, i) {
        var id = "asset-" + i;
        var fl = byAsset[asset] || [];
        findingsByNode[id] = fl;
        var top = fl[0];
        var isCrit = fl.some(function (f) {
          var s = String(f.severity || "").toLowerCase();
          return s === "critical" || s === "high";
        });
        nodes.push({
          id: id,
          label: asset.slice(0, 28),
          kind: isCrit ? "critical" : "host",
          x: 68 + (i % 2) * 8,
          y: 28 + i * 18,
          icon: isCrit ? "database" : "laptop",
          badge: isCrit ? "Activo crítico" : (top ? (top.title || "").slice(0, 18) : ""),
          critical: isCrit,
        });
        edges.push({ from: "target", to: id, critical: isCrit });
      });

      if (extras.length === 0 && findingsByNode.target.length) {
        nodes.push({
          id: "impact",
          label: "Impacto / datos",
          kind: "critical",
          x: 72,
          y: 36,
          icon: "database",
          badge: "Activo crítico",
          critical: true,
        });
        findingsByNode.impact = findingsByNode.target.filter(function (f) {
          var s = String(f.severity || "").toLowerCase();
          return s === "critical" || s === "high";
        });
        edges.push({ from: "target", to: "impact", critical: true });
      }

      var clientFindings = (findings || []).filter(function (f) {
        return /brute|cookie|session|login|credential/i.test((f.title || "") + " " + (f.description || ""));
      });
      if (clientFindings.length) {
        nodes.push({
          id: "client",
          label: "Cliente / sesión",
          kind: "client",
          x: 12,
          y: 62,
          icon: "laptop",
          badge: "",
          critical: false,
        });
        findingsByNode.client = clientFindings;
        edges.push({ from: "client", to: "target", critical: false });
      }

      // Rama Active Directory: dominio / DC / creds GPP si hay hallazgos AD.
      var adFindings = (findings || []).filter(function (f) {
        return /^AD:/i.test(String(f.title || ""));
      });
      if (adFindings.length) {
        var domainHit = adFindings.find(function (f) {
          return /dominio |Domain Controller|--dc-list/i.test(f.title || "");
        });
        var domainLabel = "Active Directory";
        var dm = domainHit && String(domainHit.title || "").match(/dominio\s+([A-Za-z0-9._-]+)/i);
        if (dm) domainLabel = dm[1];
        else if (domainHit && /Domain Controller/i.test(domainHit.title || "")) domainLabel = "AD / DC";
        var adCrit = adFindings.some(function (f) {
          var s = String(f.severity || "").toLowerCase();
          return s === "critical" || s === "high";
        });
        nodes.push({
          id: "ad-domain",
          label: domainLabel.slice(0, 28),
          kind: adCrit ? "critical" : "host",
          x: 70,
          y: 58,
          icon: "network",
          badge: adCrit ? "AD crítico" : "AD",
          critical: adCrit,
        });
        findingsByNode["ad-domain"] = adFindings;
        edges.push({ from: "target", to: "ad-domain", critical: adCrit });
        var gppHits = adFindings.filter(function (f) {
          return /GPP /i.test(f.title || "");
        });
        if (gppHits.length) {
          nodes.push({
            id: "ad-gpp",
            label: "SYSVOL / GPP",
            kind: "critical",
            x: 88,
            y: 68,
            icon: "key-round",
            badge: "Credencial GPP",
            critical: true,
          });
          findingsByNode["ad-gpp"] = gppHits;
          edges.push({ from: "ad-domain", to: "ad-gpp", critical: true });
        }
      }

      return { nodes: nodes, edges: edges, findingsByNode: findingsByNode, target: targetRaw || target };
    }

    function drawEdges() {
      var lines = graphModel.edges.map(function (e) {
        var a = graphModel.nodes.find(function (n) { return n.id === e.from; });
        var b = graphModel.nodes.find(function (n) { return n.id === e.to; });
        if (!a || !b) return "";
        var stroke = e.critical ? "#ba1a1a" : "#c0c7d4";
        var width = e.critical ? 3 : 2;
        var dash = e.critical ? "" : ' stroke-dasharray="5 4"';
        return '<line x1="' + a.x + '%" y1="' + a.y + '%" x2="' + b.x + '%" y2="' + b.y + '%" stroke="' + stroke + '" stroke-width="' + width + '"' + dash + "/>";
      }).join("");
      edgesEl.innerHTML = lines;
    }

    function renderSelection() {
      nodesEl.querySelectorAll(".graph-node").forEach(function (el) {
        el.classList.toggle("selected", el.getAttribute("data-node-id") === selectedId);
      });
      var node = graphModel.nodes.find(function (n) { return n.id === selectedId; }) || graphModel.nodes[1];
      if (!node) return;
      var list = graphModel.findingsByNode[node.id] || [];
      var title = document.getElementById("graph-detail-title");
      var ip = document.getElementById("graph-detail-ip");
      var scoreEl = document.getElementById("graph-detail-score");
      var vulns = document.getElementById("graph-detail-vulns");
      var origin = document.getElementById("graph-detail-origin");
      var dest = document.getElementById("graph-detail-dest");
      var mitigate = document.getElementById("graph-detail-mitigate");
      if (title) title.textContent = node.label;
      if (ip) ip.textContent = node.kind === "internet" ? "Entrada externa" : (graphModel.target || node.label);
      if (scoreEl) {
        var sc = riskScoreFromFindings(list.length ? list : (graphModel.findingsByNode.target || []));
        scoreEl.textContent = typeof sc === "number" ? String(sc) : "—";
        scoreEl.className = "font-headline-xl text-headline-xl font-bold " + (sc >= 7 ? "text-error" : sc >= 4 ? "text-[#854d0e]" : "text-primary");
      }
      if (vulns) {
        if (!list.length) {
          vulns.innerHTML = '<li class="font-body-sm text-on-surface-variant italic">Sin hallazgos en este nodo.</li>';
        } else {
          vulns.innerHTML = list.slice(0, 5).map(function (f) {
            var meta = sevPill(f.severity);
            var href = findingHref(f);
            return '<li class="bg-surface-container-lowest border-l-4 ' + meta.border + ' p-sm rounded shadow-sm">' +
              '<div class="flex justify-between items-start mb-xs gap-sm">' +
              '<a href="' + escapeHtml(href) + '" class="font-mono-md text-mono-md font-bold text-on-surface hover:text-primary truncate">' +
              escapeHtml((f.title || "Finding").slice(0, 40)) + "</a>" +
              '<span class="' + meta.badge + ' px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider shrink-0">' +
              escapeHtml(meta.label) + "</span></div>" +
              '<p class="font-body-sm text-body-sm text-secondary line-clamp-2">' +
              escapeHtml((f.description || f.asset || "").slice(0, 140)) + "</p></li>";
          }).join("");
        }
      }
      if (origin) origin.textContent = "Internet Externo";
      if (dest) {
        var crit = graphModel.nodes.find(function (n) { return n.kind === "critical"; });
        dest.textContent = crit ? crit.label : (graphModel.nodes[1] && graphModel.nodes[1].label) || "—";
      }
      if (mitigate) {
        var first = list[0] || (graphModel.findingsByNode.target || [])[0];
        mitigate.href = first ? findingHref(first) : "critical-findings.html";
      }
      if (window.lucide) lucide.createIcons();
    }

    function drawNodes() {
      nodesEl.innerHTML = "";
      graphModel.nodes.forEach(function (n) {
        var wrap = document.createElement("button");
        wrap.type = "button";
        wrap.className = "graph-node absolute flex flex-col items-center cursor-pointer bg-transparent border-0 p-0";
        wrap.style.left = n.x + "%";
        wrap.style.top = n.y + "%";
        wrap.style.transform = "translate(-50%, -50%)";
        wrap.setAttribute("data-node-id", n.id);
        wrap.setAttribute("data-search", n.label + " " + (n.badge || "") + " " + (graphModel.target || ""));
        var size = n.kind === "server" ? "h-14 w-14 rounded-lg" : n.kind === "internet" ? "h-12 w-12 rounded-full" : "h-12 w-12 rounded-lg";
        var border = n.kind === "server" ? "border-2 border-primary bg-white" :
          n.kind === "critical" ? "border-2 border-error bg-surface-container-lowest" :
          n.kind === "internet" ? "border-2 border-outline-variant bg-surface-container-highest" :
          "border border-outline-variant bg-surface-container-lowest";
        var iconColor = n.kind === "server" ? "text-primary" : n.kind === "critical" ? "text-error" : "text-secondary";
        wrap.innerHTML =
          '<div class="graph-node-icon ' + size + " " + border + ' flex items-center justify-center z-10 shadow-sm">' +
          '<i data-lucide="' + n.icon + '" class="' + iconColor + '"></i></div>' +
          '<span class="mt-xs font-label-md text-on-surface ' + (n.kind === "server" ? "font-bold border border-outline-variant" : "") +
          ' bg-white/90 px-xs rounded max-w-[9rem] truncate">' + escapeHtml(n.label) + "</span>" +
          (n.badge ? '<span class="text-[10px] ' + (n.critical ? "text-error font-bold bg-error-container" : "text-on-surface-variant") +
            ' mt-0.5 px-1 rounded max-w-[9rem] truncate">' + escapeHtml(n.badge) + "</span>" : "");
        wrap.addEventListener("click", function () {
          selectedId = n.id;
          renderSelection();
        });
        nodesEl.appendChild(wrap);
      });
      if (window.lucide) lucide.createIcons();
    }

    function applyGraph(findings, meta, status) {
      var st = Object.assign({}, status || {});
      if (meta && meta.target) st.target = meta.target;
      if (meta && meta.scope) st.scope = meta.scope;
      var hasData = (findings && findings.length > 0) || !!(st.target);
      toggleViews("panel-graph-empty", "panel-graph-live", hasData);
      if (!hasData) return;
      graphModel = buildModel(findings, st);
      var critRoutes = graphModel.edges.filter(function (e) { return e.critical; }).length;
      var label = document.getElementById("graph-routes-label");
      if (label) label.textContent = "Rutas activas: " + critRoutes + " crítica" + (critRoutes === 1 ? "" : "s");
      drawEdges();
      drawNodes();
      if (!graphModel.nodes.some(function (n) { return n.id === selectedId; })) selectedId = "target";
      renderSelection();
    }

    if (document.getElementById("graph-list-view")) {
      bootScanHub({
        pageFile: "attack-graph.html",
        listViewId: "graph-list-view",
        detailViewId: "graph-detail-view",
        cardsId: "graph-scans-cards",
        emptyId: "graph-scans-empty",
        searchId: "graph-list-search",
        titleId: "graph-page-title",
        subtitleId: "graph-page-subtitle",
        ctaLabel: tKey("graph.open", "Ver grafo"),
        ctaIcon: "share-2",
        onDetail: function (findings, meta, id, status) { applyGraph(findings, meta, status); },
      });
    } else {
      function refresh() {
        Promise.all([loadFindings(), fetchStatus()]).then(function (res) {
          applyGraph(res[0], null, res[1]);
        });
      }
      refresh();
      setInterval(refresh, 8000);
    }
  }

  function bootRemediationMetrics() {
    var live = document.getElementById("panel-metrics-live");
    var empty = document.getElementById("panel-metrics-empty");
    if (!live || !document.getElementById("metrics-mttr")) return;

    var SLA_DAYS = { critical: 2, high: 7, medium: 30, low: 90, info: 90 };
    var MONTHS_ES = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
    var MONTHS_EN = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    var rangeEl = document.getElementById("metrics-range");
    var cachedFindings = [];

    function tMetrics(key, fallback) {
      if (window.DarkSpear && DarkSpear.t) {
        var v = DarkSpear.t(key);
        if (v && v !== key) return v;
      }
      return fallback;
    }

    function daysBetween(a, b) {
      return Math.max(0, (b - a) / 86400000);
    }

    function findingAgeDays(f) {
      var created = normalizeTs(f.created_at);
      if (!created) return 0;
      return daysBetween(created, Date.now());
    }

    function mttrDays(f) {
      var created = normalizeTs(f.created_at);
      var reviewed = normalizeTs(f.reviewed_at);
      if (!created || !reviewed) return null;
      return daysBetween(created, reviewed);
    }

    function metSla(f) {
      var sev = String(f.severity || "info").toLowerCase();
      var target = SLA_DAYS[sev] != null ? SLA_DAYS[sev] : 90;
      var d = mttrDays(f);
      if (d == null) return null;
      return d <= target;
    }

    function setHint(el, html, tone) {
      if (!el) return;
      el.className = "flex items-center gap-xs mt-xs " + (tone || "text-on-surface-variant");
      el.innerHTML = html;
    }

    function monthWindow() {
      var now = new Date();
      var mode = rangeEl ? rangeEl.value : "6";
      var n = 6;
      if (mode === "3") n = 3;
      else if (mode === "ytd") n = now.getMonth() + 1;
      return { now: now, n: Math.max(1, Math.min(12, n)) };
    }

    function render(findings) {
      findings = (findings || []).filter(function (f) { return f && f.status !== "rejected"; });
      cachedFindings = findings;
      if (empty) empty.hidden = true;
      live.hidden = false;

      var closed = findings.filter(isFindingRemediated);
      var open = findings.filter(isFindingOpen);

      var mttrVals = closed.map(mttrDays).filter(function (d) { return d != null; });
      var avgMttr = mttrVals.length
        ? mttrVals.reduce(function (a, b) { return a + b; }, 0) / mttrVals.length
        : null;
      var mttrEl = document.getElementById("metrics-mttr");
      var mttrHint = document.getElementById("metrics-mttr-hint");
      if (mttrEl) {
        mttrEl.textContent = avgMttr != null
          ? (avgMttr < 1 ? (avgMttr * 24).toFixed(1) + " h" : avgMttr.toFixed(1) + " " + tMetrics("metrics.daysUnit", "Days"))
          : "—";
      }
      if (avgMttr != null) {
        setHint(mttrHint,
          '<i data-lucide="trending-down" class="icon-sm"></i><span class="font-body-sm text-body-sm font-medium">' +
          escapeHtml(tMetrics("metrics.fromFindings", "Desde hallazgos remediados")) + "</span>",
          "text-tertiary");
      } else {
        setHint(mttrHint,
          '<span class="font-body-sm text-body-sm font-medium">' +
          escapeHtml(tMetrics("metrics.mttrHintEmpty", "El MTTR se calcula cuando un hallazgo pasa a Remediado, no con el tiempo de escaneo.")) + "</span>");
      }

      var slaHits = 0;
      var slaTotal = 0;
      closed.forEach(function (f) {
        var m = metSla(f);
        if (m == null) return;
        slaTotal += 1;
        if (m) slaHits += 1;
      });
      var slaPct = slaTotal ? Math.round((slaHits / slaTotal) * 100) : null;
      var slaEl = document.getElementById("metrics-sla");
      var slaBar = document.getElementById("metrics-sla-bar");
      if (slaEl) slaEl.textContent = slaPct != null ? slaPct + "%" : "—";
      if (slaBar) slaBar.style.width = (slaPct != null ? slaPct : 0) + "%";

      var expEl = document.getElementById("metrics-exposure-host");
      if (expEl) {
        var score = computeExposureRisk(findings);
        expEl.innerHTML = exposureRiskCardHtml(score);
      }

      var now = new Date();
      var monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
      var prevStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).getTime();
      var remMonth = closed.filter(function (f) {
        var r = normalizeTs(f.reviewed_at) || normalizeTs(f.created_at);
        return r && r >= monthStart;
      }).length;
      var remPrev = closed.filter(function (f) {
        var r = normalizeTs(f.reviewed_at) || normalizeTs(f.created_at);
        return r && r >= prevStart && r < monthStart;
      }).length;
      var remEl = document.getElementById("metrics-remediated");
      var remHint = document.getElementById("metrics-remediated-hint");
      if (remEl) remEl.textContent = String(remMonth);
      if (remPrev > 0) {
        var delta = Math.round(((remMonth - remPrev) / remPrev) * 100);
        var up = delta >= 0;
        setHint(remHint,
          '<i data-lucide="' + (up ? "trending-up" : "trending-down") + '" class="icon-sm"></i>' +
          '<span class="font-body-sm text-body-sm font-medium">' + (up ? "+" : "") + delta +
          "% " + escapeHtml(tMetrics("metrics.vsPrev", "vs previous month")) + "</span>",
          "text-tertiary");
      } else {
        setHint(remHint,
          '<span class="font-body-sm text-body-sm font-medium">' +
          escapeHtml(closed.length
            ? closed.length + " " + tMetrics("metrics.totalClosed", "cerrados en total")
            : tMetrics("metrics.noClosed", "Sin remediaciones aún")) + "</span>");
      }

      var openAges = open.map(findingAgeDays);
      var avgOpen = openAges.length
        ? openAges.reduce(function (a, b) { return a + b; }, 0) / openAges.length
        : null;
      var agingEl = document.getElementById("metrics-aging");
      var agingHint = document.getElementById("metrics-aging-hint");
      if (agingEl) {
        agingEl.textContent = avgOpen != null
          ? avgOpen.toFixed(0) + " " + tMetrics("metrics.daysUnit", "Days")
          : "—";
      }
      var stale = openAges.filter(function (d) { return d >= 90; }).length;
      if (stale) {
        setHint(agingHint,
          '<i data-lucide="triangle-alert" class="icon-sm"></i>' +
          '<span class="font-body-sm text-body-sm font-medium">' +
          escapeHtml(tMetrics("metrics.staleWarn", "Action required for 90+ days")) +
          " (" + stale + ")</span>",
          "text-error");
      } else {
        setHint(agingHint,
          '<span class="font-body-sm text-body-sm font-medium">' +
          escapeHtml(open.length
            ? open.length + " " + tMetrics("metrics.openCount", "abiertos")
            : tMetrics("metrics.noOpen", "Sin hallazgos abiertos")) + "</span>");
      }

      // Trends
      var trends = document.getElementById("metrics-trends");
      if (trends) {
        var win = monthWindow();
        var langEn = (window.DarkSpear && DarkSpear.lang && DarkSpear.lang() === "en");
        var labels = langEn ? MONTHS_EN : MONTHS_ES;
        var months = [];
        var i;
        for (i = win.n - 1; i >= 0; i--) {
          var d = new Date(win.now.getFullYear(), win.now.getMonth() - i, 1);
          var startTs = d.getTime();
          var endTs = new Date(d.getFullYear(), d.getMonth() + 1, 1).getTime();
          var neu = 0;
          var clo = 0;
          findings.forEach(function (f) {
            var c = normalizeTs(f.created_at);
            if (c && c >= startTs && c < endTs) neu += 1;
            var r = normalizeTs(f.reviewed_at);
            if (isFindingRemediated(f) && r && r >= startTs && r < endTs) clo += 1;
          });
          months.push({ label: labels[d.getMonth()], neu: neu, clo: clo });
        }
        var maxV = 1;
        months.forEach(function (m) { maxV = Math.max(maxV, m.neu, m.clo); });
        var axisTop = maxV >= 1000 ? "1k" : String(maxV);
        var axisMid = maxV >= 1000 ? "500" : String(Math.round(maxV / 2));
        var bars = months.map(function (m) {
          var hN = Math.max(6, Math.round((m.neu / maxV) * 100));
          var hC = Math.max(6, Math.round((m.clo / maxV) * 100));
          return '<div class="flex gap-1 h-full items-end z-10 w-12 mx-auto justify-center">' +
            '<div class="w-4 bg-outline-variant/50 rounded-t-sm" style="height:' + hN + '%" title="' + m.neu + '"></div>' +
            '<div class="w-4 bg-primary rounded-t-sm" style="height:' + hC + '%" title="' + m.clo + '"></div></div>';
        }).join("");
        var monthLabs = months.map(function (m) {
          return "<span>" + escapeHtml(m.label) + "</span>";
        }).join("");
        trends.innerHTML =
          '<div class="w-full flex justify-between h-full items-end pb-8 relative group">' +
          '<div class="absolute bottom-0 w-full flex justify-between text-on-surface-variant font-label-md text-[10px] uppercase">' +
          monthLabs + "</div>" +
          '<div class="absolute left-0 bottom-8 h-[calc(100%-2rem)] w-full flex flex-col justify-between border-l border-b border-outline-variant/30 text-on-surface-variant font-mono-md text-[10px] pl-2 z-0">' +
          '<span class="absolute -left-7 top-0">' + axisTop + "</span>" +
          '<span class="absolute -left-7 top-1/2 -translate-y-1/2">' + axisMid + "</span>" +
          '<span class="absolute -left-4 bottom-0">0</span></div>' +
          bars + "</div>";
      }

      // SLA by severity
      var sevBox = document.getElementById("metrics-sla-severity");
      if (sevBox) {
        var rows = [
          { key: "critical", label: "Critical", target: "48h", color: "bg-error", badge: "bg-error/10 text-error border-error/20" },
          { key: "high", label: "High", target: "7d", color: "bg-[#B93815]", badge: "bg-[#B93815]/10 text-[#B93815] border-[#B93815]/20" },
          { key: "medium", label: "Medium", target: "30d", color: "bg-[#B26B00]", badge: "bg-[#B26B00]/10 text-[#B26B00] border-[#B26B00]/20" },
          { key: "low", label: "Low", target: "90d", color: "bg-primary", badge: "bg-primary/10 text-primary border-primary/20" },
        ];
        sevBox.innerHTML = rows.map(function (row) {
          var subset = closed.filter(function (f) {
            return String(f.severity || "").toLowerCase() === row.key;
          });
          var hit = 0;
          var tot = 0;
          subset.forEach(function (f) {
            var m = metSla(f);
            if (m == null) return;
            tot += 1;
            if (m) hit += 1;
          });
          var pct = tot ? Math.round((hit / tot) * 100) : 0;
          var show = tot ? pct + "% SLA" : "—";
          return '<div><div class="flex justify-between items-center mb-xs font-body-sm text-body-sm">' +
            '<div class="flex items-center gap-sm"><div class="px-2 py-0.5 rounded ' + row.badge +
            ' font-label-md text-[10px] uppercase border">' + row.label + '</div>' +
            '<span class="text-on-surface">Target: ' + row.target + "</span></div>" +
            '<span class="font-medium">' + show + "</span></div>" +
            '<div class="w-full bg-surface-container h-2 rounded-full overflow-hidden">' +
            '<div class="' + row.color + ' h-full rounded-full transition-all" style="width:' + pct + '%"></div></div></div>';
        }).join("");
      }

      // Teams (assets) — Closed / Avg MTTR / SLA %
      var body = document.getElementById("metrics-assets-body");
      if (body) {
        var byAsset = {};
        findings.forEach(function (f) {
          var a = f.asset || "—";
          if (!byAsset[a]) byAsset[a] = { closed: 0, mttrSum: 0, mttrN: 0, slaHit: 0, slaTot: 0 };
          if (isFindingRemediated(f)) {
            byAsset[a].closed += 1;
            var d = mttrDays(f);
            if (d != null) {
              byAsset[a].mttrSum += d;
              byAsset[a].mttrN += 1;
            }
            var m = metSla(f);
            if (m != null) {
              byAsset[a].slaTot += 1;
              if (m) byAsset[a].slaHit += 1;
            }
          }
        });
        var assets = Object.keys(byAsset).map(function (k) {
          return { name: k, stats: byAsset[k] };
        }).sort(function (a, b) {
          return b.stats.closed - a.stats.closed;
        }).slice(0, 4);
        if (!assets.length) {
          body.innerHTML = '<tr><td class="py-3 px-3 text-on-surface-variant italic" colspan="4">' +
            escapeHtml(tMetrics("metrics.noTeams", "Sin equipos / activos todavía")) + "</td></tr>";
        } else {
          var colors = ["bg-primary-container", "bg-[#B93815]", "bg-[#B26B00]", "bg-secondary"];
          body.innerHTML = assets.map(function (row, idx) {
            var initials = row.name.replace(/^https?:\/\//, "").slice(0, 2).toUpperCase();
            var avg = row.stats.mttrN ? (row.stats.mttrSum / row.stats.mttrN) : null;
            var mttrLabel = avg == null ? "—" : (avg < 1 ? (avg * 24).toFixed(1) + "h" : avg.toFixed(1) + "d");
            var sla = row.stats.slaTot ? Math.round((row.stats.slaHit / row.stats.slaTot) * 100) : null;
            var slaClass = sla == null ? "text-on-surface-variant" : sla >= 95 ? "text-tertiary font-medium" : sla >= 85 ? "text-on-surface" : "text-error font-medium";
            return '<tr class="hover:bg-surface-container-low transition-colors">' +
              '<td class="py-3 px-3 flex items-center gap-sm font-medium text-on-surface">' +
              '<div class="w-6 h-6 rounded ' + colors[idx % colors.length] +
              ' text-white flex items-center justify-center font-bold text-[10px] shrink-0">' +
              escapeHtml(initials) + "</div>" +
              '<span class="truncate max-w-[14rem]">' + escapeHtml(row.name) + "</span></td>" +
              '<td class="py-3 px-3 text-right">' + row.stats.closed + "</td>" +
              '<td class="py-3 px-3 text-right">' + mttrLabel + "</td>" +
              '<td class="py-3 px-3 text-right ' + slaClass + '">' + (sla != null ? sla + "%" : "—") + "</td></tr>";
          }).join("");
        }
      }

      // Aging distribution
      var agingBars = document.getElementById("metrics-aging-bars");
      if (agingBars) {
        var buckets = [
          { label: "0-30 Days", min: 0, max: 30, color: "bg-primary", n: 0 },
          { label: "31-60 Days", min: 31, max: 60, color: "bg-[#B26B00]", n: 0 },
          { label: "61-90 Days", min: 61, max: 90, color: "bg-[#B93815]", n: 0 },
          { label: "90+ Days", min: 91, max: 1e9, color: "bg-error", n: 0 },
        ];
        open.forEach(function (f) {
          var age = findingAgeDays(f);
          buckets.forEach(function (b) {
            if (age >= b.min && age <= b.max) b.n += 1;
          });
        });
        var maxB = 1;
        buckets.forEach(function (b) { maxB = Math.max(maxB, b.n); });
        agingBars.innerHTML = buckets.map(function (b) {
          var h = b.n ? Math.max(8, Math.round((b.n / maxB) * 100)) : 4;
          var labClass = b.label.indexOf("90+") === 0 ? "font-bold text-error" : "text-on-surface-variant";
          return '<div class="flex-1 flex flex-col items-center justify-end h-full group relative">' +
            '<div class="w-full max-w-[48px] ' + b.color + ' rounded-t-md transition-all duration-300 hover:opacity-80 cursor-pointer" style="height:' + h + '%">' +
            '<div class="opacity-0 group-hover:opacity-100 absolute -top-8 left-1/2 -translate-x-1/2 bg-inverse-surface text-inverse-on-surface font-body-sm text-[10px] px-2 py-1 rounded whitespace-nowrap">' +
            b.n + " Findings</div></div>" +
            '<span class="absolute -bottom-6 font-label-md text-[11px] ' + labClass + ' whitespace-nowrap">' +
            escapeHtml(b.label) + "</span></div>";
        }).join("");
      }

      if (window.lucide) lucide.createIcons();
    }

    if (rangeEl) {
      rangeEl.addEventListener("change", function () { render(cachedFindings); });
    }

    if (document.getElementById("metrics-list-view")) {
      bootScanHub({
        pageFile: "remediation-metrics.html",
        listViewId: "metrics-list-view",
        detailViewId: "metrics-detail-view",
        cardsId: "metrics-scans-cards",
        emptyId: "metrics-empty",
        searchId: "metrics-list-search",
        titleId: "metrics-detail-title",
        subtitleId: "metrics-detail-subtitle",
        ctaLabel: tKey("metrics.open", "Ver métricas"),
        ctaIcon: "gauge",
        onDetail: function (findings) { render(findings); },
      });
      return;
    }

    function refresh() {
      loadFindings().then(render).catch(function () { render([]); });
    }
    refresh();
    setInterval(refresh, 10000);
  }

  var ROOT_CAUSE_BUCKETS = [
    { re: /dvwa|deliberadamente vulnerable|vulnerable web application/i,
      es: "Aplicación deliberadamente vulnerable accesible fuera de un entorno aislado" },
    { re: /backup|\.bak\b|\.dist\b|\.old\b|config\.inc/i,
      es: "Archivos de configuración y copias de seguridad expuestos en el document root" },
    { re: /cookie|httponly|session/i,
      es: "Gestión insegura de sesiones (cookies sin HttpOnly/Secure)" },
    { re: /csrf|token/i,
      es: "Controles CSRF ausentes o incompletos" },
    { re: /directory listing|index of|listado de directorio|phpmyadmin|panel/i,
      es: "Exceso de exposición de superficie: paneles y listados accesibles sin autenticación" },
    { re: /sqli|sql injection|\bxss\b|\brfi\b|\blfi\b|inyecci[oó]n|inclusion/i,
      es: "Vulnerabilidades de inyección / inclusión de código sin sanitizar entradas" },
    { re: /version|server header|banner|phpinfo/i,
      es: "Divulgación de información de versión y stack tecnológico" },
    { re: /allow_url_include|php\.ini/i,
      es: "Configuración de PHP insegura por defecto (allow_url_include, exposición de php.ini)" },
  ];

  function findingBlob(f) {
    return [f.title, f.description, f.remediation, f.tags].filter(Boolean).join(" ");
  }

  function reportSevRank(f) {
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var n = order[String((f && f.severity) || "").toLowerCase()];
    return n == null ? 9 : n;
  }

  function reportSortedFindings(findings) {
    return (findings || []).slice().sort(function (a, b) { return reportSevRank(a) - reportSevRank(b); });
  }

  function conclusionsText(findings, meta) {
    var c = sevCounts(findings || []);
    return tKey("comp.sec09Body", "Este análisis contra {target} identificó {n} hallazgos: {c} críticos, {h} altos, {m} medios, {l} bajos y {i} informativos. Se recomienda priorizar la remediación de los hallazgos críticos y altos según el plan de la sección 06, y repetir el análisis tras aplicar las correcciones para verificar el cierre de cada hallazgo.")
      .replace("{target}", (meta && meta.target) || "—")
      .replace("{n}", String((findings || []).length))
      .replace("{c}", String(c.critical))
      .replace("{h}", String(c.high))
      .replace("{m}", String(c.medium))
      .replace("{l}", String(c.low))
      .replace("{i}", String(c.info));
  }

  function htmlDocControlRows(findings, meta) {
    var rows = [
      [tKey("comp.dtTarget", "Target"), (meta && meta.target) || "—"],
      [tKey("comp.dtScope", "Scope"), (meta && meta.scope) || "—"],
      [tKey("comp.dtStarted", "Inicio del engagement"), formatEngagementStarted(meta && meta.started_at)],
      [tKey("comp.dtGenerated", "Documento generado"), new Date().toLocaleString()],
      [tKey("comp.dtPhase", "Fase alcanzada"), meta && meta.phase != null ? String(meta.phase) : "—"],
      [tKey("comp.dtTotal", "Hallazgos totales"), String((findings || []).length)],
    ];
    return rows.map(function (r) {
      return '<div class="flex justify-between gap-md border-b border-outline-variant/20 pb-xs"><dt class="text-on-surface-variant">' +
        escapeHtml(r[0]) + '</dt><dd class="font-semibold text-on-surface text-right">' + escapeHtml(r[1]) + "</dd></div>";
    }).join("");
  }

  function htmlRootCauseItems(findings) {
    var langEn = window.DarkSpear && DarkSpear.lang && DarkSpear.lang() === "en";
    var hits = ROOT_CAUSE_BUCKETS.map(function (b) {
      var n = (findings || []).filter(function (f) { return b.re.test(findingBlob(f)); }).length;
      return { label: langEn && b.en ? b.en : b.es, n: n };
    }).filter(function (h) { return h.n > 0; }).sort(function (a, b) { return b.n - a.n; }).slice(0, 6);
    if (!hits.length) {
      return "<li>" + escapeHtml(tKey("comp.sec03Empty", "Sin hallazgos suficientes todavía para agrupar causas raíz.")) + "</li>";
    }
    return hits.map(function (h) {
      return "<li>" + escapeHtml(h.label) + ' <span class="text-on-surface-variant">(' + h.n + ")</span></li>";
    }).join("");
  }

  function htmlControlItems(findings) {
    var measures = (findings || []).filter(isObservedTechnicalMeasure);
    if (!measures.length) {
      return "<li>" + escapeHtml(tKey("comp.sec05Empty", "No se observaron controles compensatorios (WAF, filtrado de perímetro, HSTS) en este análisis.")) + "</li>";
    }
    return measures.map(function (f) {
      return "<li><span class=\"font-semibold\">" + escapeHtml(f.title || "—") + "</span> — " +
        escapeHtml((f.remediation || f.description || "").slice(0, 140)) + "</li>";
    }).join("");
  }

  function htmlExecChapter(findings, meta) {
    var c = sevCounts(findings || []);
    var m = maturityFromFindings(findings);
    var grade = m.score >= 85 ? "A" : m.score >= 70 ? "B" : m.score >= 55 ? "C" : m.score >= 40 ? "D" : "F";
    var top = reportSortedFindings(findings).filter(function (f) {
      var s = String(f.severity || "").toLowerCase();
      return s === "critical" || s === "high";
    }).slice(0, 4);
    var narrative = tKey("exec.narrativeP1", "Este análisis sobre {target} registró {n} hallazgos: {c} críticos, {h} altos, {m} medios.")
      .replace("{target}", (meta && meta.target) || "—")
      .replace("{n}", String((findings || []).length))
      .replace("{c}", String(c.critical))
      .replace("{h}", String(c.high))
      .replace("{m}", String(c.medium));
    var topLine = top.length
      ? escapeHtml(tKey("exec.narrativeP2", "Priorizar el cierre de: ")) + "<strong>" +
        escapeHtml(top.map(function (f) { return f.title; }).join("; ")) + "</strong>."
      : escapeHtml(tKey("exec.noCritical", "Sin hallazgos críticos o altos"));
    return '<div class="grid grid-cols-2 md:grid-cols-4 gap-sm mb-md">' +
      [["critical", tKey("exec.sevCritical", "Crítico"), c.critical],
       ["high", tKey("exec.sevHigh", "Alto"), c.high],
       ["medium", tKey("exec.sevMedium", "Medio"), c.medium],
       ["low", tKey("exec.sevLow", "Bajo"), c.low + c.info]].map(function (row) {
        var tone = row[0] === "critical" ? "bg-error-container/30 text-error"
          : row[0] === "high" ? "bg-[#FFEFE5]/50 text-[#C25400]"
          : row[0] === "medium" ? "bg-[#FFF4CE]/50 text-[#795F00]"
          : "bg-surface-container text-secondary";
        return '<div class="border border-outline-variant/30 p-md rounded-lg ' + tone + '"><p class="font-label-md mb-xs">' +
          escapeHtml(row[1]) + '</p><p class="font-headline-xl text-on-surface">' + row[2] + "</p></div>";
      }).join("") +
      "</div>" +
      '<p class="font-body-md text-on-surface-variant leading-relaxed mb-sm">' + escapeHtml(narrative) +
      " · " + escapeHtml(tKey("exec.posture", "Puntuación global")) + ": <strong>" + grade + " · " + m.score + "/100</strong> (" +
      escapeHtml(m.level) + ").</p>" +
      '<p class="font-body-md text-on-surface-variant leading-relaxed">' + topLine + "</p>";
  }

  function htmlSevSummaryTable(findings) {
    var c = sevCounts(findings || []);
    var rows = [
      ["critical", tKey("exec.sevCritical", "Crítico"), tKey("comp.sevCritHint", "Riesgo inmediato de compromiso o pérdida de datos."), c.critical, "bg-error"],
      ["high", tKey("exec.sevHigh", "Alto"), tKey("comp.sevHighHint", "Riesgo significativo para las operaciones."), c.high, "bg-[#f97316]"],
      ["medium", tKey("exec.sevMedium", "Medio"), tKey("comp.sevMedHint", "Explotable bajo condiciones específicas."), c.medium, "bg-[#eab308]"],
      ["low", tKey("exec.sevLow", "Bajo"), tKey("comp.sevLowHint", "Desviaciones de higiene o buenas prácticas."), c.low + c.info, "bg-tertiary-container"],
    ];
    return '<div class="border border-outline-variant rounded-lg overflow-hidden"><table class="w-full text-left border-collapse">' +
      '<thead class="bg-surface-container-low font-label-md text-secondary"><tr>' +
      "<th class=\"py-sm px-md border-b border-outline-variant\">" + escapeHtml(tKey("comp.colSev", "Severidad")) + "</th>" +
      "<th class=\"py-sm px-md border-b border-outline-variant\">" + escapeHtml(tKey("comp.colDesc", "Descripción")) + "</th>" +
      "<th class=\"py-sm px-md border-b border-outline-variant text-right\">" + escapeHtml(tKey("comp.colCount", "N.º")) + "</th>" +
      "</tr></thead><tbody class=\"font-body-md\">" +
      rows.map(function (r) {
        return "<tr><td class=\"py-sm px-md border-b border-outline-variant\"><span class=\"inline-flex items-center gap-sm\">" +
          '<span class="w-3 h-3 rounded-full ' + r[4] + '"></span>' + escapeHtml(r[1]) +
          "</span></td><td class=\"py-sm px-md border-b border-outline-variant text-on-surface-variant\">" +
          escapeHtml(r[2]) + "</td><td class=\"py-sm px-md border-b border-outline-variant text-right font-semibold\">" +
          r[3] + "</td></tr>";
      }).join("") +
      "</tbody></table></div>";
  }

  function htmlFindingArticles(findings, scanId, limit) {
    var list = reportSortedFindings(findings);
    if (limit) list = list.slice(0, limit);
    if (!list.length) {
      return '<p class="font-body-sm text-on-surface-variant italic">' +
        escapeHtml(tKey("comp.sec04Empty", "Este análisis aún no tiene hallazgos confirmados.")) + "</p>";
    }
    var extra = (findings || []).length - list.length;
    return list.map(function (f, i) {
      var sp = sevPill(f.severity);
      var techs = mitreForFinding(f);
      var ev = String(f.description || "").trim();
      var href = findingHref(f, scanId);
      return '<article class="border border-outline-variant/40 rounded-lg p-md">' +
        '<div class="flex items-start gap-sm mb-sm flex-wrap">' +
        '<span class="' + sp.badge + ' px-2 py-1 rounded font-label-md shrink-0">' + escapeHtml(sp.label) + "</span>" +
        '<h4 class="font-body-lg font-semibold text-on-surface">' + (i + 1) + ". " + escapeHtml(f.title || "—") + "</h4></div>" +
        '<p class="font-mono-md text-secondary mb-sm">' + escapeHtml(f.asset || "—") + "</p>" +
        (ev ? '<p class="font-body-md text-on-surface-variant mb-sm leading-relaxed">' +
          escapeHtml(ev.length > 420 ? ev.slice(0, 420) + "…" : ev) + "</p>" : "") +
        (techs.length ? '<p class="font-mono-md text-[11px] text-on-surface-variant mb-sm">' +
          techs.map(function (t) { return escapeHtml(t.id) + " " + escapeHtml(t.name); }).join(" · ") + "</p>" : "") +
        '<a class="font-label-md text-primary hover:underline" href="' + escapeHtml(href) + '">' +
        escapeHtml(tKey("remplan.openFinding", "Ficha y plan completo")) + "</a></article>";
    }).join("") + (extra > 0
      ? '<p class="font-body-sm text-on-surface-variant">' + extra + " " +
        escapeHtml(tKey("comp.moreFindings", "hallazgos más en el documento completo.")) + "</p>"
      : "");
  }

  function findingCardDomId(f) {
    return "finding-card-" + String((f && f.id) || "finding").replace(/[^a-zA-Z0-9_-]/g, "-");
  }

  function renderReportFindingDossiers(containerId, findings, scanId) {
    var root = typeof containerId === "string" ? document.getElementById(containerId) : containerId;
    if (!root) return;
    var list = reportSortedFindings(findings);
    var toc = document.getElementById("comp-toc-findings");
    if (!list.length) {
      root.innerHTML = '<p class="font-body-sm text-on-surface-variant italic">' +
        escapeHtml(tKey("comp.sec04Empty", "Este análisis aún no tiene hallazgos confirmados.")) + "</p>";
      if (toc) toc.innerHTML = "";
      return;
    }
    var indexHtml = '<nav class="border border-outline-variant/40 rounded-lg p-md bg-surface-container-lowest">' +
      '<p class="font-label-md text-on-surface-variant uppercase mb-sm">' +
      escapeHtml(tKey("comp.findingsIndex", "Índice de fichas")) + " · " + list.length + "</p>" +
      '<ol class="columns-1 md:columns-2 gap-md font-body-sm space-y-xs list-decimal pl-lg">' +
      list.map(function (f) {
        return '<li class="break-inside-avoid"><a class="text-primary hover:underline" href="#' +
          escapeHtml(findingCardDomId(f)) + '">' +
          escapeHtml(f.id || "") + " · " + escapeHtml(f.title || "—") +
          "</a></li>";
      }).join("") + "</ol></nav>";
    root.innerHTML = indexHtml + list.map(function (f) {
      return '<article id="' + escapeHtml(findingCardDomId(f)) + '" class="report-finding-card scroll-mt-4"></article>';
    }).join("");
    if (window.DarkSpearDossier && DarkSpearDossier.render) {
      list.forEach(function (f) {
        var card = document.getElementById(findingCardDomId(f));
        if (!card) return;
        var prefix = "rpt-" + String(f.id || "x").replace(/[^a-zA-Z0-9_-]/g, "-") + "-";
        DarkSpearDossier.render(card, f, {
          embedded: true,
          idPrefix: prefix,
          scanId: scanId,
          escapeHtml: escapeHtml,
          relativeTime: relativeTime,
          sevBadgeClass: sevBadgeClass,
        });
      });
    } else {
      list.forEach(function (f) {
        var card = document.getElementById(findingCardDomId(f));
        if (card) card.innerHTML = htmlFindingArticles([f], scanId);
      });
    }
    if (toc) {
      toc.innerHTML = list.map(function (f) {
        var title = String(f.title || "—");
        if (title.length > 42) title = title.slice(0, 40) + "…";
        return '<li><button class="toc-sub" data-go="' + escapeHtml(findingCardDomId(f)) + '" type="button">' +
          escapeHtml(f.id || "") + " · " + escapeHtml(title) + "</button></li>";
      }).join("");
      toc.querySelectorAll("[data-go]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var id = btn.getAttribute("data-go");
          if (typeof goToSection === "function") {
            goToSection(id);
            return;
          }
          var view = document.getElementById(id);
          if (!view) return;
          document.querySelectorAll(".toc-btn, .toc-sub").forEach(function (b) { b.classList.remove("active"); });
          btn.classList.add("active");
          view.scrollIntoView({ behavior: "smooth", block: "start" });
        });
      });
    }
  }

  function htmlRemediationPlan(findings, scanId) {
    var open = (findings || []).filter(isFindingOpen);
    var ranked = reportSortedFindings(open);
    if (!ranked.length) {
      return '<p class="font-body-md text-on-surface-variant">' +
        escapeHtml(tKey("remplan.noneOpen", "No hay hallazgos abiertos en este análisis.")) + "</p>";
    }
    var qScan = scanId ? ("?scan=" + encodeURIComponent(scanId) + "&") : "?";
    return ranked.slice(0, 12).map(function (f) {
      var d = window.DarkSpearDossier && DarkSpearDossier.enrich ? DarkSpearDossier.enrich(f) : null;
      var steps = d && d.steps ? d.steps.slice(0, 3) : [];
      var sp = sevPill(f.severity);
      var href = "finding-detail.html" + qScan + "id=" + encodeURIComponent(f.id || "");
      return '<article class="border border-outline-variant/40 rounded-lg p-md border-l-4 border-l-tertiary">' +
        '<div class="flex justify-between items-start gap-sm flex-wrap mb-xs">' +
        '<h4 class="font-headline-md text-on-surface">' + escapeHtml(f.title || "—") + "</h4>" +
        '<span class="' + sp.badge + ' px-sm py-xs rounded font-label-md">' + escapeHtml(sp.label) + "</span></div>" +
        '<p class="font-mono-md text-secondary mb-xs">' + escapeHtml(f.asset || "—") + "</p>" +
        (steps.length ? "<ol class=\"list-decimal pl-lg font-body-sm text-on-surface-variant space-y-xs\">" +
          steps.map(function (s) { return "<li>" + escapeHtml(s) + "</li>"; }).join("") + "</ol>" : "") +
        '<a class="font-label-md text-primary hover:underline mt-sm inline-block" href="' + escapeHtml(href) + '">' +
        escapeHtml(tKey("remplan.openFinding", "Ficha y plan completo")) + "</a></article>";
    }).join("");
  }

  function htmlRiskMatrix3x3(findings) {
    var grid = [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
    (findings || []).forEach(function (f) {
      if (!f || f.status === "rejected") return;
      var s = String(f.severity || "").toLowerCase();
      var impact = s === "critical" || s === "high" ? 2 : s === "medium" ? 1 : 0;
      var open = isFindingOpen(f);
      var like = !open ? 0 : s === "critical" ? 2 : (s === "high" || s === "medium") ? 1 : 0;
      grid[2 - like][impact] += 1;
    });
    var cells = "";
    for (var r = 0; r < 3; r++) {
      for (var col = 0; col < 3; col++) {
        var n = grid[r][col];
        var heat = r + col;
        var cls = n && heat >= 4 ? "bg-error-container/80 text-on-error-container font-black"
          : n && heat >= 3 ? "bg-error-container/30 text-error font-bold"
          : "bg-surface-container text-on-surface-variant";
        cells += '<div class="' + cls + ' flex items-center justify-center relative">' +
          (n && heat >= 3 ? '<div class="absolute top-1 right-1 w-2 h-2 rounded-full bg-error"></div>' : "") +
          '<span class="font-headline-md relative z-10">' + n + "</span></div>";
      }
    }
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="grid-3x3" class="text-primary"></i>' +
      escapeHtml(tKey("comp.matrixTitle", "Matriz de riesgo empresarial")) + "</h3>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' +
      escapeHtml(tKey("comp.matrixLead", "Distribución de hallazgos por probabilidad frente a impacto de negocio.")) + "</p>" +
      '<div class="relative w-full aspect-square max-w-[300px] mx-auto border-l-2 border-b-2 border-outline-variant pb-lg pl-lg">' +
      '<div class="absolute -left-2 top-1/2 -translate-y-1/2 -rotate-90 font-label-md text-label-md text-outline">' +
      escapeHtml(tKey("comp.likelihood", "Probabilidad")) + "</div>" +
      '<div class="absolute -bottom-6 left-1/2 -translate-x-1/2 font-label-md text-label-md text-outline">' +
      escapeHtml(tKey("comp.impactAxis", "Impacto")) + "</div>" +
      '<div class="grid grid-cols-3 grid-rows-3 w-full h-full gap-[2px] bg-outline-variant/20 p-[2px]">' + cells + "</div></div>";
  }

  function htmlRgpdChapter(findings) {
    var scores = gdprArticleScores(findings);
    var art32View = gdprArt32View(scores.art32Hits);
    var art33Hits = scores.art33Hits;
    var overall = art32View.tone === "error"
      ? tKey("comp.rgpdGap", "No demostrable")
      : tKey("comp.rgpdOk", "En revisión");
    var overallTone = art32View.tone === "error" ? "text-error" : "text-tertiary";
    var top32 = scores.art32Hits.filter(isFindingOpen)[0];
    var art32Block = top32
      ? '<div class="p-sm rounded bg-error-container/20 border border-error-container/50 flex items-start gap-sm">' +
        '<i data-lucide="triangle-alert" class="icon-sm text-error mt-xs"></i><div>' +
        "<h4 class=\"font-label-md text-on-surface\">" + escapeHtml(tKey("gdpr.art32", "Seguridad del tratamiento (Art. 32)")) + "</h4>" +
        '<p class="font-body-sm text-on-surface-variant mt-xs">' + escapeHtml(top32.title || "") + "</p></div></div>"
      : '<div class="p-sm rounded bg-surface-container border border-outline-variant/30 flex items-start gap-sm">' +
        '<i data-lucide="circle-check" class="icon-sm text-tertiary-container mt-xs"></i><div>' +
        "<h4 class=\"font-label-md text-on-surface\">" + escapeHtml(tKey("gdpr.art32", "Seguridad del tratamiento (Art. 32)")) + "</h4>" +
        '<p class="font-body-sm text-on-surface-variant mt-xs">' + escapeHtml(art32View.display) + "</p></div></div>";
    var art33Block = '<div class="p-sm rounded ' +
      (art33Hits.length ? "bg-error-container/20 border border-error-container/50" : "bg-surface-container border border-outline-variant/30") +
      ' flex items-start gap-sm">' +
      '<i data-lucide="' + (art33Hits.length ? "triangle-alert" : "circle-check") + '" class="icon-sm ' +
      (art33Hits.length ? "text-error" : "text-tertiary-container") + ' mt-xs"></i><div>' +
      "<h4 class=\"font-label-md text-on-surface\">" + escapeHtml(tKey("gdpr.art33", "Notificación de brechas (Art. 33)")) + "</h4>" +
      '<p class="font-body-sm text-on-surface-variant mt-xs">' +
      escapeHtml(art33Hits.length
        ? tKey("gdpr.art33LeadHits", "Hallazgos de secretos o compromiso de cuenta: evaluar si hay datos personales y el reloj de 72 h.")
        : tKey("gdpr.art33LeadNone", "Sin fuga de secretos ni compromiso de cuenta en este análisis.")) +
      "</p></div></div>";
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="scale" class="text-primary"></i>' +
      escapeHtml(tKey("comp.rgpdTitle", "Alineación RGPD")) + "</h3>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' +
      escapeHtml(tKey("comp.rgpdLead", "Controles de protección de datos derivados de los hallazgos de este escaneo.")) + "</p>" +
      '<div class="flex items-center justify-between mb-sm"><span class="font-label-md text-on-surface-variant">' +
      escapeHtml(tKey("gdpr.complianceOverview", "Estado general de cumplimiento")) +
      '</span><span class="font-label-md font-bold ' + overallTone + '">' + escapeHtml(overall) + "</span></div>" +
      '<div class="space-y-sm">' + art32Block + art33Block + "</div>";
  }

  function maturityDomainWhy(key) {
    var map = {
      iam: tKey("maturity.whyIam", "Identidad: login, sesiones, cookies, MFA e IdP (Entra/Workspace/SAML). Un SQLi en login o cookies sin flags tumba este dominio."),
      net: tKey("maturity.whyNet", "Red y perímetro: TLS, cabeceras, SPF/DMARC, puertos. Un dominio sin DMARC o sin CSP baja este eje aunque el resto esté sano."),
      data: tKey("maturity.whyData", "Datos: secretos en código, SQL, backups, buckets listables. Un crítico aquí es el que más duele en RGPD."),
      ir: tKey("maturity.whyIr", "Respuesta a incidentes: RCE, inclusión de ficheros, uploads. Si el atacante ejecuta código, el IR no tiene margen."),
      aware: tKey("maturity.whyAware", "Concienciación y higiene de despliegue: DVWA, debug, display_errors. Señala entornos que no deberían ser públicos."),
      assets: tKey("maturity.whyAssets", "Inventario: directory listing, robots, document root. Superficie que el equipo no tenía mapeada."),
    };
    return map[key] || "";
  }

  function htmlMaturityStory(findings, meta) {
    var m = maturityFromFindings(findings);
    var domains = maturityDomainsFromFindings(findings);
    var c = sevCounts(findings || []);
    var weakest = domains.slice().sort(function (a, b) { return a.actual - b.actual; }).slice(0, 2);
    var why = tKey("maturity.whyScore", "El índice {score}/100 ({level}) no es una nota de consultora: resta por hallazgos abiertos. En este análisis hay {c} críticos, {h} altos, {m} medios, {l} bajos y {i} infos. Cada crítico tira fuerte; un info apenas mueve. Por eso un único SQLi en login puede dejar IAM en 1.0 aunque el resto del radar se vea «verde».")
      .replace("{score}", String(m.score))
      .replace("{level}", m.level)
      .replace("{c}", String(c.critical))
      .replace("{h}", String(c.high))
      .replace("{m}", String(c.medium))
      .replace("{l}", String(c.low))
      .replace("{i}", String(c.info));
    var how = weakest.length
      ? tKey("maturity.howUp", "Para subir de nivel cierra primero los dominios más bajos ({domains}). El objetivo 4.0 en un eje significa: no quedan críticos ni altos abiertos en ese control. Relanza el análisis después; si el radar no se mueve, el hallazgo sigue abierto o no está clasificado en ese dominio.")
          .replace("{domains}", weakest.map(function (d) { return d.label + " " + d.actual.toFixed(1); }).join(", "))
      : "";
    var vsFair = tKey("maturity.vsFair", "No confundas este índice con el grado FAIR-lite de la ficha «Índice de exposición». FAIR resume riesgo de negocio (exposición × amenaza × impacto) para dirección. La madurez resume capacidad de control por dominio (1–5) para el CISO. Puedes tener FAIR C y madurez Inicial a la vez: mucha superficie y pocos controles demostrables.");
    var cards = domains.map(function (d) {
      var gap = d.actual < d.target;
      return '<article class="rounded-lg border border-outline-variant/40 p-md bg-surface-container-lowest">' +
        '<div class="flex justify-between items-start gap-sm mb-xs">' +
        '<h4 class="font-headline-md text-on-surface">' + escapeHtml(d.label) + "</h4>" +
        '<span class="font-mono-md ' + (gap ? "text-error" : "text-tertiary") + '">' + d.actual.toFixed(1) +
        " / " + d.target.toFixed(1) + "</span></div>" +
        '<p class="font-body-sm text-on-surface-variant mb-sm leading-relaxed">' + escapeHtml(maturityDomainWhy(d.key)) + "</p>" +
        (d.hits
          ? '<p class="font-label-md text-on-surface-variant uppercase mb-xs">' +
            escapeHtml(tKey("maturity.domainHits", "Hallazgos que tiran de este eje")) + " · " + d.hits + "</p>" +
            '<ul class="font-body-sm text-on-surface space-y-xs list-disc pl-md">' +
            (d.examples || []).map(function (t) {
              return "<li>" + escapeHtml(t) + "</li>";
            }).join("") +
            (d.hits > (d.examples || []).length ? "<li>…</li>" : "") +
            "</ul>"
          : '<p class="font-body-sm text-on-surface-variant italic">' +
            escapeHtml(tKey("maturity.domainClear", "Ningún hallazgo de este análisis encaja en este dominio. Eso no certifica el control: solo dice que el playbook no vio un fallo aquí.")) +
            "</p>") +
        "</article>";
    }).join("");
    return '<div class="flex flex-col gap-md">' +
      '<div class="rounded-lg border border-outline-variant/40 p-md bg-surface-container-lowest">' +
      '<h4 class="font-headline-md text-on-surface mb-sm">' + escapeHtml(tKey("maturity.whyTitle", "Por qué esta puntuación")) + "</h4>" +
      '<p class="font-body-md text-on-surface leading-relaxed mb-sm">' + escapeHtml(why) + "</p>" +
      (how ? '<p class="font-body-md text-on-surface leading-relaxed mb-sm">' + escapeHtml(how) + "</p>" : "") +
      '<p class="font-body-sm text-on-surface-variant leading-relaxed">' + escapeHtml(vsFair) + "</p>" +
      (meta && (meta.target || scanDisplayName(meta))
        ? '<p class="font-mono-md text-secondary mt-sm">' + escapeHtml(meta.target || scanDisplayName(meta)) + "</p>"
        : "") +
      "</div>" +
      '<h4 class="font-headline-md text-on-surface">' + escapeHtml(tKey("maturity.domainsExplain", "Qué mide cada dominio y por qué está así")) + "</h4>" +
      '<div class="grid grid-cols-1 md:grid-cols-2 gap-sm">' + cards + "</div></div>";
  }

  function htmlMaturityChapter(findings, meta, canvasId, scanId) {
    var m = maturityFromFindings(findings);
    var domains = maturityDomainsFromFindings(findings);
    var avg = domains.reduce(function (a, d) { return a + d.actual; }, 0) / (domains.length || 1);
    var toward = Math.round((avg / 4) * 100);
    var exp = computeExposureRisk(findings);
    var cid = canvasId || "comp-maturity-radar";
    var q = scanId ? ("?scan=" + encodeURIComponent(scanId)) : "";
    var bands = [
      { lo: 0, hi: 39, key: "maturity.levelInit", fb: "Inicial" },
      { lo: 40, hi: 59, key: "maturity.levelMan", fb: "Gestionado" },
      { lo: 60, hi: 79, key: "maturity.levelDef", fb: "Definido" },
      { lo: 80, hi: 100, key: "maturity.levelOpt", fb: "Optimización" },
    ];
    var scale = bands.map(function (b) {
      var on = m.score >= b.lo && m.score <= b.hi;
      return '<div class="rounded-lg p-sm border ' +
        (on ? "border-primary bg-primary-container/15" : "border-outline-variant/40 bg-surface-container-low") +
        '"><p class="font-label-md ' + (on ? "text-primary" : "text-on-surface") + '">' +
        escapeHtml(tKey(b.key, b.fb)) + '</p><p class="font-mono-md text-on-surface-variant">' +
        b.lo + "–" + b.hi + "</p></div>";
    }).join("");
    var table = '<table class="w-full text-left"><thead><tr class="border-b border-outline-variant/40 font-label-md text-on-surface-variant uppercase">' +
      "<th class=\"py-sm\">" + escapeHtml(tKey("maturity.domain", "Dominio")) + "</th>" +
      "<th class=\"py-sm text-right\">" + escapeHtml(tKey("maturity.actual", "Actual")) + "</th>" +
      "<th class=\"py-sm text-right\">" + escapeHtml(tKey("maturity.target", "Objetivo")) + "</th>" +
      "<th class=\"py-sm text-right\">" + escapeHtml(tKey("scan.findings", "Hallazgos")) + "</th></tr></thead><tbody>" +
      domains.map(function (d) {
        var pct = Math.round((d.actual / 5) * 100);
        return "<tr class=\"border-b border-outline-variant/20 font-body-sm\"><td class=\"py-sm text-on-surface\">" +
          escapeHtml(d.label) +
          '<div class="mt-xs h-1.5 rounded-full bg-surface-container-high overflow-hidden"><div class="h-full bg-primary-container rounded-full" style="width:' +
          pct + '%"></div></div></td><td class="py-sm text-right font-mono-md">' + d.actual.toFixed(1) +
          "</td><td class=\"py-sm text-right font-mono-md\">" + d.target.toFixed(1) +
          "</td><td class=\"py-sm text-right\">" + d.hits + "</td></tr>";
      }).join("") + "</tbody></table>";
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="gauge" class="text-primary"></i>' +
      escapeHtml(tKey("maturity.detailTitle", "Índice de Madurez de Seguridad")) + "</h3>" +
      '<p class="font-body-sm text-on-surface-variant mb-md leading-relaxed">' +
      escapeHtml(tKey("comp.maturityExplain", "No es un CMMI de consultora: es una lectura 1–5 por dominio frente al objetivo 4.0, más un índice 0–100 derivado de los hallazgos abiertos.")) +
      "</p>" +
      '<p class="font-body-sm text-on-surface-variant mb-md leading-relaxed">' +
      escapeHtml(tKey("comp.maturityMethod", "Los hallazgos abiertos restan por severidad. Niveles: 0–39 Inicial, 40–59 Gestionado, 60–79 Definido, 80–100 Optimización.")) +
      "</p>" +
      '<p class="font-label-md text-on-surface-variant uppercase mb-sm">' +
      escapeHtml(tKey("comp.maturityScale", "Escala de madurez")) + "</p>" +
      '<div class="grid grid-cols-2 md:grid-cols-4 gap-sm mb-md">' + scale + "</div>" +
      '<div class="grid grid-cols-1 lg:grid-cols-12 gap-md mb-md">' +
      '<div class="lg:col-span-8 border border-outline-variant/40 rounded-lg p-md bg-surface-container-lowest">' +
      '<div class="flex justify-between items-start mb-sm gap-sm flex-wrap">' +
      "<div><h4 class=\"font-headline-md text-on-surface\">" + escapeHtml(tKey("maturity.radarTitle", "Distribución por dominio")) +
      '</h4><p class="font-body-sm text-on-surface-variant">' +
      escapeHtml(tKey("maturity.radarLead", "Brecha entre nivel actual y objetivo (escala 1–5)")) +
      "</p></div>" +
      '<div class="flex items-center gap-md font-body-sm shrink-0">' +
      '<span class="flex items-center gap-xs"><span class="w-3 h-3 rounded-full bg-primary-container"></span>' +
      escapeHtml(tKey("maturity.actual", "Actual")) + "</span>" +
      '<span class="flex items-center gap-xs"><span class="w-3 h-3 rounded-full border-2 border-tertiary border-dashed"></span>' +
      escapeHtml(tKey("maturity.target", "Objetivo")) + "</span></div></div>" +
      '<div class="relative w-full min-h-[280px] h-[280px]"><canvas id="' + escapeHtml(cid) + '"></canvas></div></div>' +
      '<div class="lg:col-span-4 flex flex-col gap-sm">' +
      '<div class="border border-outline-variant/40 rounded-lg p-md bg-surface-container-lowest">' +
      "<h4 class=\"font-headline-md text-on-surface mb-xs\">" + escapeHtml(tKey("maturity.global", "Índice global")) + "</h4>" +
      '<p class="font-headline-xl text-primary">' + avg.toFixed(1) +
      ' <span class="font-body-md text-on-surface-variant">/ 5.0</span></p>' +
      '<p class="font-body-sm text-on-surface-variant mt-xs">' + escapeHtml(m.level) +
      " · " + m.score + "/100 " + escapeHtml(tKey("maturity.fromFindings", "desde hallazgos abiertos")) + "</p>" +
      '<p class="font-label-md text-on-surface mt-sm">' + escapeHtml(tKey("osint.exposureTitle", "Índice de exposición")) +
      ": " + exp.grade + " · " + exp.risk + "/100</p>" +
      '<div class="flex justify-between font-label-md mt-sm"><span class="text-on-surface-variant">' +
      escapeHtml(tKey("maturity.toward", "Progreso hacia objetivo 4.0")) +
      '</span><span class="text-primary">' + toward + "%</span></div>" +
      '<div class="w-full h-2 bg-surface-container-high rounded-full overflow-hidden mt-xs"><div class="h-full bg-primary-container rounded-full" style="width:' +
      Math.min(100, toward) + '%"></div></div>' +
      '<p class="font-mono-md text-secondary mt-sm">' +
      escapeHtml((meta && (meta.target || scanDisplayName(meta))) || "—") + "</p></div></div></div>" +
      '<div class="overflow-x-auto mb-sm">' + table + "</div>" +
      htmlMaturityStory(findings, meta) +
      '<a class="inline-flex items-center gap-xs font-label-md text-primary hover:underline mt-md" href="maturity-index.html' +
      q + '"><i data-lucide="external-link" class="icon-sm"></i>' +
      escapeHtml(tKey("comp.openMaturityPage", "Abrir la matriz de riesgos completa")) + "</a>";
  }

  function htmlMaturitySnap(findings, meta) {
    return htmlMaturityChapter(findings, meta, "comp-maturity-radar");
  }

  function htmlMitreKillChain(findings) {
    var obs = collectMitreObserved(findings);
    var byTactic = {};
    Object.keys(obs).forEach(function (id) {
      var t = obs[id];
      if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
      byTactic[t.tactic].push({ id: id, name: t.name, count: t.count, findings: t.findings });
    });
    var order = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
      "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"];
    var tactics = order.filter(function (t) { return byTactic[t]; });
    Object.keys(byTactic).forEach(function (t) {
      if (tactics.indexOf(t) < 0) tactics.push(t);
    });
    var body;
    if (!tactics.length) {
      body = '<p class="font-body-sm text-on-surface-variant italic">' +
        escapeHtml(tKey("killchain.noMitre", "Sin técnicas MITRE derivadas de este análisis.")) + "</p>";
    } else {
      var shown = tactics.slice(0, 5);
      body = '<div class="overflow-x-auto pb-sm"><div class="flex min-w-[640px] gap-sm items-stretch">' +
        shown.map(function (tac, idx) {
          var cells = byTactic[tac].slice(0, 3).map(function (tech) {
            var hot = tech.findings.some(function (f) {
              var s = String(f.severity || "").toLowerCase();
              return s === "critical" || s === "high";
            });
            return '<div class="' + (hot ? "bg-error-container/20 border-error/20" : "bg-surface-container") +
              ' border p-xs rounded-sm mb-xs font-mono-md text-[11px] text-on-surface">' +
              escapeHtml(tech.id) + ": " + escapeHtml(tech.name) + "</div>";
          }).join("");
          return '<div class="flex-1 min-w-[140px] bg-surface-container-low rounded p-sm border border-outline-variant/30">' +
            '<h4 class="font-label-md text-on-surface-variant mb-sm uppercase border-b border-outline-variant/30 pb-xs">' +
            escapeHtml(tac) + "</h4>" + cells + "</div>" +
            (idx < shown.length - 1 ? '<i data-lucide="arrow-right" class="icon-sm text-outline self-center shrink-0"></i>' : "");
        }).join("") + "</div></div>";
    }
    var buckets = killChainBuckets(findings);
    var chain = '<ul class="font-body-sm text-on-surface-variant mt-md space-y-xs">' +
      buckets.filter(function (b) { return b.items.length; }).map(function (b) {
        return "<li><span class=\"font-semibold text-on-surface\">" + escapeHtml(b.label) + "</span> · " +
          b.items.length + " " + tKey("scan.findings", "hallazgos") + "</li>";
      }).join("") + "</ul>";
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="share-2" class="text-primary"></i>' +
      escapeHtml(tKey("comp.sec08fTitle", "08f. Kill Chain y MITRE")) + "</h3>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' +
      escapeHtml(tKey("comp.sec08fLead", "Técnicas observadas durante el análisis, encadenadas por táctica.")) + "</p>" +
      body + chain;
  }

  function htmlBusinessImpact(findings, meta) {
    var c = sevCounts(findings || []);
    var scores = gdprArticleScores(findings);
    var art32View = gdprArt32View(scores.art32Hits);
    var obs = collectMitreObserved(findings);
    var hasT1190 = Object.keys(obs).some(function (id) { return id === "T1190" || /Exploit Public-Facing/i.test(obs[id].name || ""); });
    var strategic = [];
    if (art32View.tone === "error" || scores.art33Hits.length) {
      strategic.push(tKey("comp.impactGdpr", "Techo sancionador RGPD Art. 83 (hasta el 4 % de facturación global) si el tratamiento incluye datos personales — no es una multa calculada."));
    }
    if (hasT1190 || c.critical) {
      strategic.push(tKey("comp.impactPublic", "Riesgo reputacional por exposición de aplicación pública o hallazgos críticos abiertos en {target}.")
        .replace("{target}", (meta && meta.target) || "—"));
    }
    if (!strategic.length) {
      strategic.push(tKey("comp.impactNone", "Sin umbral de impacto regulatorio evidente a partir de este análisis."));
    }
    var actions = reportSortedFindings((findings || []).filter(isFindingOpen)).slice(0, 3).map(function (f) {
      var d = window.DarkSpearDossier && DarkSpearDossier.enrich ? DarkSpearDossier.enrich(f) : null;
      var step = d && d.steps && d.steps[0] ? d.steps[0] : (f.remediation || f.title);
      return "<li><span class=\"font-semibold text-on-surface\">" + escapeHtml(f.title || "—") + ":</span> " +
        escapeHtml(String(step).slice(0, 180)) + "</li>";
    });
    if (!actions.length) {
      actions = ["<li>" + escapeHtml(tKey("remplan.noneOpen", "No hay hallazgos abiertos en este análisis.")) + "</li>"];
    }
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="rocket" class="text-tertiary-container"></i>' +
      escapeHtml(tKey("comp.impactTitle", "Impacto de negocio y quick wins")) + "</h3>" +
      '<div class="grid grid-cols-1 md:grid-cols-2 gap-md mt-md">' +
      '<div class="pl-md border-l-2 border-primary/50"><h4 class="font-label-md text-on-surface mb-xs">' +
      escapeHtml(tKey("comp.impactStrategic", "Impacto estratégico")) + "</h4>" +
      '<ul class="list-disc list-outside ml-sm font-body-sm text-on-surface-variant space-y-xs">' +
      strategic.map(function (s) { return "<li>" + escapeHtml(s) + "</li>"; }).join("") + "</ul></div>" +
      '<div class="pl-md border-l-2 border-tertiary-container/50"><h4 class="font-label-md text-on-surface mb-xs">' +
      escapeHtml(tKey("comp.impactActions", "Acciones inmediatas")) + "</h4>" +
      '<ul class="list-disc list-outside ml-sm font-body-sm text-on-surface-variant space-y-xs">' +
      actions.join("") + "</ul></div></div>";
  }

  function htmlConnectedSurfaces(findings, meta, scanId) {
    var osint = osintClassifyFindings(findings);
    var osintN = osint.creds.length + osint.appSecrets.length + osint.infra.length + osint.repos.length + osint.mentions.length;
    var assets = {};
    (findings || []).forEach(function (f) {
      assets[String(f.asset || (meta && meta.target) || "—")] = true;
    });
    var mitreN = Object.keys(collectMitreObserved(findings)).length;
    var q = scanId ? ("?scan=" + encodeURIComponent(scanId)) : "";
    var cards = [
      ["osint.html" + q, "binoculars", tKey("nav.osint", "OSINT"), osintN + " " + tKey("comp.osintHits", "hallazgos OSINT")],
      ["ad-assessment.html" + q, "network", tKey("nav.ad", "Active Directory"), (function () {
        var a = adClassifyFindings(findings);
        return a.domain.length + a.users.length + a.shares.length + a.posture.length + a.auth.length + a.other.length;
      })() + " " + tKey("comp.adHits", "señales AD")],
      ["attack-graph.html" + q, "share-2", tKey("nav.graph", "Grafo de ataque"), Object.keys(assets).length + " " + tKey("comp.graphAssets", "activos en el grafo")],
      ["mitre.html" + q, "swords", tKey("nav.mitre", "MITRE ATT&CK"), mitreN + " " + tKey("comp.mitreTechs", "técnicas MITRE")],
      ["kill-chain.html" + q, "git-branch", tKey("nav.killchain", "Kill Chain"), tKey("comp.openChapter", "Abrir capítulo")],
    ];
    return '<h3 class="font-headline-md text-on-surface mb-sm flex items-center gap-sm">' +
      '<i data-lucide="link" class="text-primary"></i>' +
      escapeHtml(tKey("comp.connectedTitle", "Superficies conectadas")) + "</h3>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' +
      escapeHtml(tKey("comp.connectedLead", "OSINT, Active Directory, grafo de ataque y ATT&CK del mismo análisis.")) + "</p>" +
      '<div class="grid grid-cols-1 sm:grid-cols-2 gap-sm">' +
      cards.map(function (c) {
        return '<a class="flex items-center gap-sm p-sm rounded-lg border border-outline-variant/40 hover:bg-surface-container-low transition-colors" href="' +
          escapeHtml(c[0]) + '"><i data-lucide="' + c[1] + '" class="icon-sm text-primary"></i><span>' +
          '<span class="font-label-md text-on-surface block">' + escapeHtml(c[2]) + "</span>" +
          '<span class="font-body-sm text-on-surface-variant">' + escapeHtml(c[3]) + "</span></span></a>";
      }).join("") + "</div>";
  }

  function bindScanExport(btnId, findings, meta, scanId, kind) {
    var btn = document.getElementById(btnId);
    if (!btn) return;
    btn.onclick = function () {
      if (window.DarkSpearExport && DarkSpearExport.run) {
        DarkSpearExport.run(kind || "pdf", {
          findings: findings || [],
          target: meta && meta.target,
          scope: meta && meta.scope,
          engagementId: scanId,
        });
      }
    };
  }

  function renderComprehensiveDocument(findings, meta, scanId) {
    var all = findings || [];
    var tbl = document.getElementById("sec-00-table");
    if (tbl) tbl.innerHTML = htmlDocControlRows(all, meta || {});
    var exec = document.getElementById("sec-01-body");
    if (exec) exec.innerHTML = htmlExecChapter(all, meta || {});
    var sum = document.getElementById("sec-02-body");
    if (sum) sum.innerHTML = htmlSevSummaryTable(all);
    var rc = document.getElementById("sec-03-list");
    if (rc) rc.innerHTML = htmlRootCauseItems(all);
    var list = document.getElementById("comp-findings");
    if (list) renderReportFindingDossiers("comp-findings", all, scanId);
    var ctl = document.getElementById("sec-05-list");
    if (ctl) ctl.innerHTML = htmlControlItems(all);
    var rem = document.getElementById("sec-06-body");
    if (rem) rem.innerHTML = htmlRemediationPlan(all, scanId);
    var appx = document.getElementById("sec-07-meta");
    if (appx) {
      appx.textContent = tKey("comp.sec07Meta", "{n} hallazgos confirmados en este análisis. Cada uno enlaza a su ficha con evidencia de sonda.")
        .replace("{n}", String(all.length));
    }
    var mx = document.getElementById("sec-08-matrix");
    if (mx) mx.innerHTML = htmlRiskMatrix3x3(all);
    var rgpd = document.getElementById("sec-08-rgpd");
    if (rgpd) rgpd.innerHTML = htmlRgpdChapter(all);
    var mat = document.getElementById("sec-08e");
    if (mat) {
      mat.innerHTML = htmlMaturityChapter(all, meta || {}, "comp-maturity-radar", scanId);
      renderMaturityRadar(maturityDomainsFromFindings(all), "comp-maturity-radar");
    }
    var conn = document.getElementById("sec-08-connected");
    if (conn) conn.innerHTML = htmlConnectedSurfaces(all, meta || {}, scanId);
    var kc = document.getElementById("sec-08f-killchain");
    if (kc) kc.innerHTML = htmlMitreKillChain(all);
    var imp = document.getElementById("sec-08-impact");
    if (imp) imp.innerHTML = htmlBusinessImpact(all, meta || {});
    var concl = document.getElementById("sec-09-body");
    if (concl) concl.textContent = conclusionsText(all, meta || {});
    var footDate = document.getElementById("comp-doc-footer-date");
    if (footDate) footDate.textContent = new Date().toLocaleString();
    if (window.lucide) lucide.createIcons();
  }

  function renderPreviewPaper(findings, meta, scanId) {
    var root = document.getElementById("preview-paper");
    if (!root) return;
    var m = meta || {};
    var all = findings || [];
    var name = scanDisplayName(m) || m.target || "—";
    root.innerHTML =
      '<div id="watermark" class="pdf-watermark">Dark Spear</div>' +
      '<div class="flex justify-between items-start mb-xl border-b border-surface-dim pb-md">' +
      '<div class="flex items-center gap-sm"><img src="vendor/logo.png" alt="Dark Spear" class="w-8 h-8"/>' +
      '<span class="font-headline-lg font-bold text-on-surface">Dark Spear</span></div>' +
      '<div id="client-logo" class="w-32 h-12 border border-dashed border-outline-variant rounded flex items-center justify-center text-secondary font-body-sm bg-surface-container-lowest">' +
      escapeHtml(tKey("preview.clientLogo", "[Logo cliente]")) + "</div></div>" +
      '<div class="mb-xl text-center"><h1 class="font-headline-xl font-bold text-on-surface mb-xs">' +
      escapeHtml(tKey("preview.paperTitle", "Informe de evaluación de seguridad")) + "</h1>" +
      '<p class="font-body-lg text-secondary">' + escapeHtml(tKey("preview.engagement", "Engagement")) + ": " +
      escapeHtml(name) + '</p><p class="font-body-sm text-secondary mt-sm">' +
      escapeHtml(tKey("comp.dtGenerated", "Documento generado")) + ": " + escapeHtml(new Date().toLocaleString()) +
      "</p></div>" +
      '<section data-section="sec-00" class="mb-xl"><h2><span>00</span> ' + escapeHtml(tKey("comp.sec00Title", "Control documental")) +
      "</h2><dl>" + htmlDocControlRows(all, m) + "</dl></section>" +
      '<section data-section="sec-01" class="mb-xl"><h2><span>01</span> ' + escapeHtml(tKey("comp.sec01Title", "Resumen ejecutivo")) +
      "</h2>" + htmlExecChapter(all, m) + "</section>" +
      '<section data-section="sec-02" class="mb-xl"><h2><span>02</span> ' + escapeHtml(tKey("comp.sec02Title", "Resumen de hallazgos")) +
      "</h2>" + htmlSevSummaryTable(all) + "</section>" +
      '<section data-section="sec-03" class="mb-xl"><h2><span>03</span> ' + escapeHtml(tKey("comp.sec03Title", "Causa raíz")) +
      "</h2><ul class=\"list-disc pl-lg\">" + htmlRootCauseItems(all) + "</ul></section>" +
      '<section data-section="sec-04" class="mb-xl"><h2><span>04</span> ' + escapeHtml(tKey("comp.sec04Title", "Hallazgos detallados")) +
      "</h2><p class=\"font-body-sm text-on-surface-variant mb-md\">" +
      escapeHtml(tKey("comp.sec04Lead", "Ficha completa de cada hallazgo del escaneo.")) +
      '</p><div id="preview-dossiers" class="flex flex-col gap-md"></div></section>' +
      '<section data-section="sec-05" class="mb-xl"><h2><span>05</span> ' + escapeHtml(tKey("comp.sec05Title", "Controles vigentes")) +
      "</h2><ul class=\"list-disc pl-lg\">" + htmlControlItems(all) + "</ul></section>" +
      '<section data-section="sec-06" class="mb-xl"><h2><span>06</span> ' + escapeHtml(tKey("comp.sec06Title", "Remediación priorizada")) +
      "</h2><div class=\"flex flex-col gap-md\">" + htmlRemediationPlan(all, scanId) + "</div></section>" +
      '<section data-section="sec-07" class="mb-xl"><h2><span>07</span> ' + escapeHtml(tKey("comp.sec07Title", "Apéndice técnico")) +
      "</h2><p>" + escapeHtml(tKey("comp.sec07Body", "Metodología PTES.")) + "</p></section>" +
      '<section data-section="sec-08" class="mb-xl"><h2><span>08</span> ' + escapeHtml(tKey("comp.sec08Title", "Gobernanza")) + "</h2>" +
      '<div data-section="sec-08c" class="mb-lg">' + htmlRiskMatrix3x3(all) + "</div>" +
      '<div data-section="sec-08a" class="mb-lg">' + htmlRgpdChapter(all) + "</div>" +
      '<div data-section="sec-08e" class="mb-lg">' + htmlMaturityChapter(all, m, "preview-maturity-radar", scanId) + "</div>" +
      '<div data-section="sec-08d" class="mb-lg">' + htmlBusinessImpact(all, m) + "</div></section>" +
      '<section data-section="sec-08f" class="mb-xl"><h2><span>08f</span> ' + escapeHtml(tKey("comp.sec08fTitle", "Kill Chain y MITRE")) +
      "</h2>" + htmlMitreKillChain(all) + "</section>" +
      '<section data-section="sec-09" class="mb-xl"><h2><span>09</span> ' + escapeHtml(tKey("comp.sec09Title", "Conclusiones")) +
      "</h2><p>" + escapeHtml(conclusionsText(all, m)) + "</p></section>" +
      '<section data-section="sec-gallery" class="mb-xl hidden-section"><h2>' +
      escapeHtml(tKey("preview.gallery", "Galería de evidencia")) + "</h2>" +
      '<p class="font-body-sm text-on-surface-variant">' +
      escapeHtml(tKey("preview.galleryLead", "Las evidencias de sonda viven en la ficha de cada hallazgo.")) + "</p></section>";
    if (window.lucide) lucide.createIcons();
    renderReportFindingDossiers("preview-dossiers", all, scanId);
    renderMaturityRadar(maturityDomainsFromFindings(all), "preview-maturity-radar");
    document.querySelectorAll("input[data-toggle]").forEach(function (cb) {
      document.querySelectorAll('[data-section="' + cb.getAttribute("data-toggle") + '"]').forEach(function (el) {
        el.classList.toggle("hidden-section", !cb.checked);
      });
    });
  }

  function bootComprehensiveReport() {
    bootReportChapter({
      prefix: "comp",
      pageFile: "comprehensive-report.html",
      ctaKey: "comp.open",
      ctaFallback: "Abrir informe",
      ctaIcon: "file-text",
      hideOnListIds: ["comp-toc"],
      onDetail: function (findings, meta, scanId, status) {
        renderSevStatsGrid("comp-stats", findings);
        renderComprehensiveDocument(findings, meta, scanId);
        var titleEl = document.getElementById("comp-doc-title");
        if (titleEl) titleEl.textContent = scanDisplayName(meta) || tKey("comp.docTitle", "Informe integral");
        var crumb = document.getElementById("comp-crumb-scan");
        if (crumb) crumb.textContent = scanDisplayName(meta) || (meta && meta.target) || "—";
        var preview = document.getElementById("comp-link-preview");
        if (preview) preview.href = "report-preview.html" + (scanId ? "?scan=" + encodeURIComponent(scanId) : "");
        bindScanExport("btn-export", findings, meta, scanId, "pdf");
        var isActive = !!(meta && meta.active) || !!(status && status.active);
        var reachedMax = meta && meta.phase != null && meta.max_phase != null && Number(meta.phase) >= Number(meta.max_phase);
        var finished = !isActive || reachedMax;
        var dotEl = document.getElementById("comp-doc-dot");
        if (dotEl) dotEl.className = "w-2 h-2 rounded-full " + (finished ? "bg-tertiary-container" : "bg-primary");
        var statusEl = document.getElementById("comp-doc-status");
        if (statusEl) {
          var label = finished ? tKey("comp.docFinal", "Versión final") : tKey("comp.docDraft", "Borrador · escaneo en curso");
          statusEl.textContent = label + " · " + formatEngagementStarted(meta && meta.started_at);
        }
      },
    });
  }

  function bootGdprAlignment() {
    bootReportChapter({
      prefix: "gdpr",
      pageFile: "gdpr-alignment.html",
      ctaKey: "gdpr.open",
      ctaFallback: "Ver RGPD",
      ctaIcon: "scale",
      onDetail: function (findings, meta, scanId) {
        var gdpr = gdprRelevantFindings(findings);
        renderGdprComplianceDashboard(findings, meta, scanId);
        var subEl = document.getElementById("gdpr-detail-subtitle");
        if (subEl) {
          subEl.textContent = tKey("gdpr.detailLead", "Visión general del estado de cumplimiento y riesgos de sanción.") +
            (meta && meta.target ? " · Target: " + meta.target : "");
        }
        var list = document.getElementById("gdpr-findings");
        if (list && window.DarkSpearFindings) DarkSpearFindings.renderList(list, gdpr, "all");
      },
    });
  }

  function bootMaturityIndex() {
    bootReportChapter({
      prefix: "maturity",
      pageFile: "maturity-index.html",
      ctaKey: "maturity.open",
      ctaFallback: "Ver madurez",
      ctaIcon: "target",
      titleKey: "maturity.detailTitle",
      titleFallback: "Índice de Madurez de Seguridad",
      onDetail: function (findings, meta) {
        var m = maturityFromFindings(findings);
        var domains = maturityDomainsFromFindings(findings);
        var avg = domains.reduce(function (a, d) { return a + d.actual; }, 0) / (domains.length || 1);
        var toward = Math.round((avg / 4) * 100);
        var expScore = computeExposureRisk(findings);
        var sumEl = document.getElementById("maturity-summary");
        if (sumEl) {
          sumEl.innerHTML =
            '<div class="glass-panel rounded-xl p-lg flex flex-col gap-md">' +
            '<h3 class="font-headline-md text-on-surface">' + escapeHtml(tKey("maturity.global", "Índice global")) + "</h3>" +
            '<p class="font-headline-xl text-primary">' + avg.toFixed(1) +
            ' <span class="font-body-md text-on-surface-variant">/ 5.0</span></p>' +
            '<p class="font-body-sm text-on-surface-variant">' + escapeHtml(m.level) +
            " · " + m.score + "/100 " + escapeHtml(tKey("maturity.fromFindings", "desde hallazgos abiertos")) + "</p>" +
            '<p class="font-label-md text-on-surface">' + escapeHtml(tKey("osint.exposureTitle", "Índice de exposición")) +
            ": " + expScore.grade + " · " + expScore.risk + "/100</p>" +
            '<div class="flex justify-between font-label-md"><span class="text-on-surface-variant">' +
            escapeHtml(tKey("maturity.toward", "Progreso hacia objetivo 4.0")) +
            '</span><span class="text-primary">' + toward + "%</span></div>" +
            '<div class="w-full h-2 bg-surface-container-high rounded-full overflow-hidden"><div class="h-full bg-primary-container rounded-full" style="width:' + Math.min(100, toward) + '%"></div></div>' +
            '<p class="font-body-sm text-on-surface-variant">' +
            escapeHtml((meta && (meta.target || scanDisplayName(meta))) || "—") + "</p></div>";
        }
        renderMaturityRadar(domains);
        var table = document.getElementById("maturity-domains");
        if (table) {
          table.innerHTML =
            '<div class="glass-panel rounded-xl p-lg overflow-x-auto"><h3 class="font-headline-md text-on-surface mb-md">' +
            escapeHtml(tKey("maturity.domains", "Dominios")) + "</h3>" +
            '<table class="w-full text-left"><thead><tr class="border-b border-outline-variant/40 font-label-md text-on-surface-variant uppercase">' +
            "<th class=\"py-sm\">" + escapeHtml(tKey("maturity.domain", "Dominio")) + "</th>" +
            "<th class=\"py-sm text-right\">" + escapeHtml(tKey("maturity.actual", "Actual")) + "</th>" +
            "<th class=\"py-sm text-right\">" + escapeHtml(tKey("maturity.target", "Objetivo")) + "</th>" +
            "<th class=\"py-sm text-right\">" + escapeHtml(tKey("scan.findings", "Hallazgos")) + "</th></tr></thead><tbody>" +
            domains.map(function (d) {
              return "<tr class=\"border-b border-outline-variant/20 font-body-sm\"><td class=\"py-sm text-on-surface\">" +
                escapeHtml(d.label) + "</td><td class=\"py-sm text-right font-mono-md\">" + d.actual.toFixed(1) +
                "</td><td class=\"py-sm text-right font-mono-md\">" + d.target.toFixed(1) +
                "</td><td class=\"py-sm text-right\">" + d.hits + "</td></tr>";
            }).join("") +
            "</tbody></table></div>";
        }
        var story = document.getElementById("maturity-story");
        if (story) story.innerHTML = htmlMaturityStory(findings, meta);
        var list = document.getElementById("maturity-findings");
        if (list && window.DarkSpearFindings) DarkSpearFindings.renderList(list, findings, "all");
      },
    });
  }

  function bootKillChain() {
    bootReportChapter({
      prefix: "killchain",
      pageFile: "kill-chain.html",
      ctaKey: "killchain.open",
      ctaFallback: "Ver Kill Chain",
      ctaIcon: "git-branch",
      titleKey: "killchain.detailTitle",
      titleFallback: "Análisis Kill Chain",
      onDetail: function (findings, meta, scanId) {
        var buckets = killChainBuckets(findings);
        var narrative = document.getElementById("killchain-narrative");
        if (narrative) {
          narrative.innerHTML = buckets.map(function (b, idx) {
            var has = b.items.length > 0;
            var top = b.items.slice(0, 4);
            return '<div class="relative">' +
              '<div class="absolute -left-[25px] w-3 h-3 rounded-full mt-1.5 ' +
              (has ? "bg-primary-container border-2 border-primary-container" : "bg-white border-2 border-outline-variant") + '"></div>' +
              '<div class="flex justify-between items-start gap-md mb-xs">' +
              '<h4 class="font-headline-md text-on-surface">' + (idx + 1) + ". " + escapeHtml(b.label) + "</h4>" +
              '<span class="font-label-md text-[10px] uppercase tracking-wider px-sm py-xs rounded-full ' +
              (has ? "bg-error-container/40 text-error" : "bg-surface-container-high text-on-surface-variant") + '">' +
              b.items.length + " " + tKey("scan.findings", "hallazgos") + "</span></div>" +
              (has
                ? '<ul class="font-body-sm text-on-surface-variant space-y-xs">' +
                  top.map(function (f) {
                    var sev = String(f.severity || "").toUpperCase();
                    return "<li><a class=\"hover:text-primary\" href=\"" + escapeHtml(findingHref(f)) + "\">" +
                      '<span class="font-mono-md text-[10px] text-secondary">' + escapeHtml(sev) + "</span> " +
                      escapeHtml(f.title || "—") + "</a></li>";
                  }).join("") +
                  (b.items.length > 4 ? "<li>…</li>" : "") + "</ul>"
                : '<p class="font-body-sm text-on-surface-variant italic">' + escapeHtml(tKey("killchain.noStage", "Sin hallazgos en esta fase")) + "</p>") +
              "</div>";
          }).join("");
        }
        var obs = collectMitreObserved(findings);
        var byTactic = {};
        Object.keys(obs).forEach(function (id) {
          var t = obs[id];
          if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
          byTactic[t.tactic].push({ id: id, name: t.name, count: t.count, findings: t.findings });
        });
        var tactics = Object.keys(byTactic);
        var mitreEl = document.getElementById("killchain-mitre");
        var mitreCount = document.getElementById("killchain-mitre-count");
        if (mitreCount) {
          mitreCount.textContent = tKey("killchain.tacticsObserved", "Tácticas observadas") + ": " + tactics.length;
        }
        if (mitreEl) {
          if (!tactics.length) {
            mitreEl.innerHTML = '<p class="font-body-sm text-on-surface-variant italic">' +
              escapeHtml(tKey("killchain.noMitre", "Sin técnicas MITRE derivadas de este análisis.")) + "</p>";
          } else {
            mitreEl.innerHTML = '<div class="grid grid-cols-2 md:grid-cols-4 gap-sm">' +
              tactics.slice(0, 8).map(function (tac) {
                var cells = byTactic[tac].slice(0, 4).map(function (tech) {
                  var hot = tech.findings.some(function (f) {
                    var s = String(f.severity || "").toLowerCase();
                    return s === "critical" || s === "high";
                  });
                  return '<div class="p-sm rounded-md border text-left ' +
                    (hot ? "bg-error-container/50 border-error/30" : "bg-surface-container-low border-outline-variant/30") + '">' +
                    '<p class="font-mono-md text-[11px] ' + (hot ? "text-error" : "text-secondary") + '">' + escapeHtml(tech.id) +
                    "</p><p class=\"font-body-sm text-on-surface\">" + escapeHtml(tech.name) + "</p></div>";
                }).join("");
                return '<div><p class="font-label-md text-secondary uppercase mb-xs">' + escapeHtml(tac) + "</p>" + cells + "</div>";
              }).join("") + "</div>";
          }
        }
        var critN = countBySeverity(findings, ["critical"]);
        var highN = countBySeverity(findings, ["high"]);
        var q = scanId ? ("?scan=" + encodeURIComponent(scanId)) : "";
        var impact = document.getElementById("killchain-impact");
        if (impact) {
          impact.innerHTML =
            '<h3 class="font-headline-md text-on-surface flex items-center gap-sm mb-md">' +
            '<i data-lucide="triangle-alert" class="text-error"></i>' +
            escapeHtml(tKey("killchain.impact", "Impacto del análisis")) + "</h3>" +
            '<p class="font-headline-xl text-error mb-xs">' + critN + " " + escapeHtml(tKey("dash.kpi.critical", "críticos")) + "</p>" +
            '<p class="font-body-sm text-on-surface-variant mb-md">' + highN + " high · " +
            (findings || []).length + " " + tKey("scan.findings", "hallazgos") + "</p>" +
            '<a class="block text-center py-sm rounded-lg bg-primary-container text-on-primary-container font-label-md mb-sm" href="critical-findings.html' + q + '">' +
            escapeHtml(tKey("killchain.mitigate", "Mitigar amenazas")) + " (" + critN + ")</a>" +
            '<a class="block text-center py-sm rounded-lg border border-outline-variant font-label-md" href="attack-graph.html' + q + '">' +
            escapeHtml(tKey("killchain.viewGraph", "Ver grafo de ataque")) + "</a>";
        }
        var ctx = document.getElementById("killchain-context");
        if (ctx) {
          ctx.innerHTML =
            '<h3 class="font-headline-md text-on-surface mb-sm">' + escapeHtml(tKey("killchain.context", "Contexto del entorno")) + "</h3>" +
            '<p class="font-body-sm text-on-surface-variant leading-relaxed">' +
            escapeHtml(tKey("killchain.contextBody", "Cadena reconstruida solo con hallazgos de este análisis. No es un incidente nominado ni un volumen de exfiltración estimado.")) +
            "</p><p class=\"font-mono-md text-secondary mt-sm\">" + escapeHtml((meta && meta.target) || "—") + "</p>";
        }
        if (window.lucide) lucide.createIcons();
      },
    });
  }

  function bootFindingsSummary() {
    bootReportChapter({
      prefix: "summary",
      pageFile: "findings-summary.html",
      ctaKey: "summary.open",
      ctaFallback: "Ver resumen",
      ctaIcon: "layout-list",
      onDetail: function (findings) {
        renderFindingsChapterDetail(findings, "summary-findings", "summary-stats", "summary-kpi");
      },
    });
  }

  function bootExecutiveSummary() {
    bootReportChapter({
      prefix: "exec",
      pageFile: "executive-summary.html",
      ctaKey: "exec.open",
      ctaFallback: "Ver resumen",
      ctaIcon: "briefcase",
      titleKey: "exec.detailTitle",
      titleFallback: "Resumen Ejecutivo",
      onDetail: function (findings, meta, scanId) {
        var c = sevCounts(findings || []);
        var m = maturityFromFindings(findings);
        var grade = m.score >= 85 ? "A" : m.score >= 70 ? "B" : m.score >= 55 ? "C" : m.score >= 40 ? "D" : "F";
        var kpi = document.getElementById("exec-kpi");
        if (kpi) {
          var circ = Math.round(282.7 * (1 - m.score / 100));
          kpi.innerHTML =
            '<div class="grid grid-cols-1 md:grid-cols-12 gap-lg">' +
            '<section class="glass-panel rounded-xl p-lg md:col-span-4 flex flex-col items-center text-center">' +
            '<h3 class="font-label-md text-secondary uppercase tracking-widest mb-md w-full text-left">' +
            escapeHtml(tKey("exec.posture", "Puntuación global")) + "</h3>" +
            '<div class="relative w-36 h-36 flex items-center justify-center mb-md">' +
            '<svg class="w-full h-full transform -rotate-90" viewBox="0 0 100 100">' +
            '<circle cx="50" cy="50" fill="none" r="45" stroke="#e0e3e7" stroke-width="8"></circle>' +
            '<circle cx="50" cy="50" fill="none" r="45" stroke="#0078d4" stroke-dasharray="282.7" stroke-dashoffset="' + circ + '" stroke-width="8"></circle></svg>' +
            '<div class="absolute flex flex-col items-center"><span class="font-headline-xl text-primary">' + grade +
            '</span><span class="font-body-sm text-secondary">' + m.score + " / 100</span></div></div>" +
            '<p class="font-body-sm text-on-surface-variant">' + escapeHtml(m.level) + " · " +
            escapeHtml((meta && (meta.target || scanDisplayName(meta))) || "—") + "</p></section>" +
            '<section class="glass-panel rounded-xl p-lg md:col-span-8">' +
            '<h3 class="font-label-md text-secondary uppercase tracking-widest mb-md">' +
            escapeHtml(tKey("exec.bySev", "Hallazgos por severidad")) + "</h3>" +
            '<div class="grid grid-cols-2 md:grid-cols-4 gap-md">' +
            [["critical", tKey("exec.sevCritical", "Crítico"), c.critical, tKey("exec.sevCriticalHint", "Atención inmediata")],
             ["high", tKey("exec.sevHigh", "Alto"), c.high, tKey("exec.sevHighHint", "Corto plazo")],
             ["medium", tKey("exec.sevMedium", "Medio"), c.medium, tKey("exec.sevMediumHint", "Ciclo normal")],
             ["low", tKey("exec.sevLow", "Bajo"), c.low + c.info, tKey("exec.sevLowHint", "Higiene")]].map(function (row) {
              var tone = row[0] === "critical" ? "bg-error-container/30 border-error-container text-error"
                : row[0] === "high" ? "bg-[#FFEFE5]/50 border-[#FFD0B5] text-[#C25400]"
                : row[0] === "medium" ? "bg-[#FFF4CE]/50 border-[#FDE073] text-[#795F00]"
                : "bg-surface-container border-outline-variant/30 text-secondary";
              return '<div class="border p-md rounded-lg ' + tone + '"><p class="font-label-md uppercase mb-xs">' + escapeHtml(row[1]) +
                '</p><p class="font-headline-xl text-on-surface">' + row[2] + '</p><p class="font-body-sm mt-xs">' + escapeHtml(row[3]) + "</p></div>";
            }).join("") +
            "</div></section></div>";
        }
        var nar = document.getElementById("exec-narrative");
        if (nar) {
          var topTitles = (findings || []).filter(function (f) {
            return String(f.severity || "").toLowerCase() === "critical";
          }).slice(0, 4).map(function (f) { return f.title; });
          nar.innerHTML =
            '<h3 class="font-label-md text-secondary uppercase tracking-widest mb-md">' +
            escapeHtml(tKey("exec.narrative", "Resumen ejecutivo")) + "</h3>" +
            '<p class="font-body-lg text-on-surface-variant leading-relaxed mb-md">' +
            escapeHtml(tKey("exec.narrativeP1", "Este análisis sobre {target} registró {n} hallazgos: {c} críticos, {h} altos, {m} medios.")
              .replace("{target}", (meta && meta.target) || "—")
              .replace("{n}", String((findings || []).length))
              .replace("{c}", String(c.critical))
              .replace("{h}", String(c.high))
              .replace("{m}", String(c.medium))) + "</p>" +
            '<p class="font-body-lg text-on-surface-variant leading-relaxed">' +
            (topTitles.length
              ? escapeHtml(tKey("exec.narrativeP2", "Priorizar el cierre de: ")) + "<strong>" + escapeHtml(topTitles.join("; ")) + "</strong>."
              : escapeHtml(tKey("exec.noCritical", "Sin hallazgos críticos o altos"))) +
            "</p>";
        }
        renderChapterNav("exec-chapters", scanId, "executive-summary.html");
        var topEl = document.getElementById("exec-top");
        if (topEl) {
          var rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          var top = (findings || []).filter(function (f) {
            var s = String(f.severity || "").toLowerCase();
            return s === "critical" || s === "high";
          }).slice().sort(function (a, b) {
            var ra = rank[String(a.severity || "").toLowerCase()];
            var rb = rank[String(b.severity || "").toLowerCase()];
            return (ra == null ? 9 : ra) - (rb == null ? 9 : rb);
          }).slice(0, 6);
          topEl.innerHTML = top.length
            ? top.map(function (f) {
              var sp = sevPill(f.severity);
              return '<a class="glass-panel rounded-lg p-sm font-body-sm flex justify-between gap-sm hover:border-primary" href="' +
                escapeHtml(findingHref(f)) + '"><span>' + escapeHtml(f.title || "—") +
                '</span><span class="' + sp.badge + ' px-sm py-xs rounded font-label-md shrink-0">' + escapeHtml(sp.label) + "</span></a>";
            }).join("")
            : '<p class="font-body-sm text-on-surface-variant italic">' + escapeHtml(tKey("exec.noCritical", "Sin hallazgos críticos o altos")) + "</p>";
        }
      },
    });
  }

  function bootRemediationPlan() {
    bootReportChapter({
      prefix: "remplan",
      pageFile: "remediation-plan.html",
      ctaKey: "remplan.open",
      ctaFallback: "Ver plan",
      ctaIcon: "list-checks",
      onDetail: function (findings, meta, scanId) {
        var open = (findings || []).filter(isFindingOpen);
        renderSevStatsGrid("remplan-stats", findings);
        var kpiEl = document.getElementById("remplan-kpi");
        if (kpiEl) {
          var c = sevCounts(open);
          kpiEl.innerHTML =
            '<span data-i18n="remplan.openLabel">' + escapeHtml(tKey("remplan.openLabel", "Pendientes de remediación")) +
            "</span>: <strong id=\"remplan-open-count\">" + open.length + "</strong>" +
            " · Critical: <strong>" + c.critical + "</strong> · High: <strong>" + c.high + "</strong>";
        }
        var planEl = document.getElementById("remplan-open-count");
        if (planEl) planEl.textContent = String(open.length);
        var list = document.getElementById("remplan-findings");
        if (!list) return;
        var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        var ranked = open.slice().sort(function (a, b) {
          var ra = order[String(a.severity || "").toLowerCase()];
          var rb = order[String(b.severity || "").toLowerCase()];
          return (ra == null ? 9 : ra) - (rb == null ? 9 : rb);
        });
        if (!ranked.length) {
          list.innerHTML = '<p class="font-body-md text-on-surface-variant">' +
            escapeHtml(tKey("remplan.noneOpen", "No hay hallazgos abiertos en este análisis.")) + "</p>";
          return;
        }
        var qScan = scanId ? ("?scan=" + encodeURIComponent(scanId) + "&") : "?";
        list.innerHTML = ranked.map(function (f) {
          var d = window.DarkSpearDossier && DarkSpearDossier.enrich ? DarkSpearDossier.enrich(f) : null;
          var steps = d && d.steps ? d.steps : [];
          var stepsHtml = steps.slice(0, 5).map(function (s, i) {
            return '<li class="flex gap-sm items-start"><span class="w-6 h-6 rounded-full bg-primary-container text-on-primary-container flex items-center justify-center font-label-md shrink-0">' +
              (i + 1) + '</span><span class="font-body-md text-on-surface">' + escapeHtml(s) + "</span></li>";
          }).join("");
          var sp = sevPill(f.severity);
          var href = "finding-detail.html" + qScan + "id=" + encodeURIComponent(f.id || "");
          return '<article class="glass-panel rounded-xl p-md flex flex-col gap-sm border-l-4 border-l-tertiary">' +
            '<div class="flex justify-between items-start gap-sm flex-wrap">' +
            '<h3 class="font-headline-md text-on-surface">' + escapeHtml(f.title || "—") + "</h3>" +
            '<span class="' + sp.badge + ' px-sm py-xs rounded font-label-md text-label-md">' + escapeHtml(sp.label) + "</span></div>" +
            '<p class="font-mono-md text-secondary">' + escapeHtml(f.asset || "—") + "</p>" +
            (d && d.engineRemediation
              ? '<p class="font-body-sm text-on-surface-variant">' + escapeHtml(tKey("remplan.engineHint", "Indicación del motor")) +
                ": " + escapeHtml(d.engineRemediation) + "</p>"
              : "") +
            (stepsHtml ? "<ol class=\"space-y-sm mt-xs\">" + stepsHtml + "</ol>" : "") +
            '<a class="font-label-md text-primary hover:underline mt-xs" href="' + escapeHtml(href) + '">' +
            escapeHtml(tKey("remplan.openFinding", "Ficha y plan completo")) + "</a></article>";
        }).join("");
        if (window.lucide) lucide.createIcons();
      },
    });
  }

  function bootReportPreview() {
    bootReportChapter({
      prefix: "preview",
      pageFile: "report-preview.html",
      ctaKey: "preview.open",
      ctaFallback: "Configurar preview",
      ctaIcon: "file-search",
      hideOnListIds: ["preview-config", "preview-actionbar"],
      onDetail: function (findings, meta, scanId) {
        var title = document.getElementById("preview-detail-title");
        if (title) title.textContent = scanDisplayName(meta) || tKey("preview.title", "Vista previa PDF");
        var sub = document.getElementById("preview-detail-subtitle");
        if (sub) {
          sub.textContent = ((meta && meta.target) || "—") +
            (meta && meta.scope ? " · " + meta.scope : "") +
            " · " + (findings || []).length + " " + tKey("scan.findings", "hallazgos");
        }
        renderPreviewPaper(findings, meta, scanId);
        var fmt = document.getElementById("fmt");
        var btn = document.getElementById("btn-generate-fmt");
        if (btn) {
          btn.onclick = function () {
            var v = fmt ? String(fmt.value || "").toLowerCase() : "pdf";
            var kind = v.indexOf("json") !== -1 ? "json" : v.indexOf("html") !== -1 ? "html" : "pdf";
            if (window.DarkSpearExport && DarkSpearExport.run) {
              DarkSpearExport.run(kind, {
                findings: findings,
                target: meta && meta.target,
                scope: meta && meta.scope,
                engagementId: scanId,
              });
            }
          };
        }
      },
    });
  }

  function bootGenericFindings(emptyId, liveId, listId) {
    if (!document.getElementById(listId)) return;
    function refresh() {
      loadFindings().then(function (findings) {
        toggleViews(emptyId, liveId, findings.length > 0);
        var list = document.getElementById(listId);
        if (list && findings.length && window.DarkSpearFindings) {
          DarkSpearFindings.renderList(list, findings, "all");
        }
      });
    }
    refresh();
    setInterval(refresh, 10000);
  }

  function sevBadgeClass(sev) {
    var s = String(sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "bg-error/10 text-error border-error/20";
    if (s === "medium") return "bg-secondary-container/30 text-secondary";
    return "bg-surface-variant text-on-surface-variant";
  }

  function bootFindingDetail() {
    var root = document.getElementById("finding-detail-root");
    if (!root && !document.getElementById("finding-list-view")) return;
    var empty = document.getElementById("finding-detail-empty");
    var params = new URLSearchParams(location.search);
    var id = params.get("id") || params.get("finding");
    var scanParam = params.get("scan");
    var fp = params.get("fp");

    function showEmpty() {
      if (empty) empty.hidden = false;
      if (root) {
        root.hidden = true;
        root.innerHTML = "";
      }
    }

    function renderFinding(f, scanId) {
      if (empty) empty.hidden = true;
      if (root) root.hidden = false;
      if (window.DarkSpearDossier && typeof DarkSpearDossier.render === "function") {
        DarkSpearDossier.render(root, f, {
          escapeHtml: escapeHtml,
          relativeTime: relativeTime,
          sevBadgeClass: sevBadgeClass,
          scanId: scanId || scanParam || "",
        });
        return;
      }
      var sev = String(f.severity || "info");
      var sevLabel = sev.toUpperCase();
      root.innerHTML =
        '<nav class="flex items-center font-body-sm text-on-surface-variant gap-xs mb-md flex-wrap">' +
        '<a class="hover:text-primary" href="index.html">Dashboard</a><i data-lucide="chevron-right" class="icon-sm"></i>' +
        '<a class="hover:text-primary" href="reporting.html">Reporting</a><i data-lucide="chevron-right" class="icon-sm"></i>' +
        '<span class="text-on-surface font-semibold font-mono-md">' + escapeHtml(f.id || "—") + "</span></nav>" +
        '<header class="glass-panel rounded-xl p-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-md mb-md">' +
        '<div><div class="flex items-center gap-sm mb-sm flex-wrap">' +
        '<span class="font-mono-md text-secondary">' + escapeHtml(f.id || "—") + "</span>" +
        '<span class="px-2 py-0.5 rounded-full font-label-md text-label-md border ' + sevBadgeClass(sev) + '">' + escapeHtml(sevLabel) + "</span></div>" +
        '<h1 class="font-headline-xl text-headline-xl text-on-surface">' + escapeHtml(f.title || "Hallazgo") + "</h1></div>" +
        '<div class="flex gap-sm w-full md:w-auto">' +
        '<a href="remediation-detail.html?finding=' + encodeURIComponent(f.id || "") + '" class="px-md py-sm rounded-lg bg-primary-container text-on-primary-container hover:bg-primary transition-colors font-label-md">Remediar</a>' +
        "</div></header>" +
        '<div class="grid grid-cols-1 lg:grid-cols-3 gap-md">' +
        '<div class="lg:col-span-2 space-y-md">' +
        '<section class="glass-panel rounded-xl p-lg"><h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md border-b border-outline-variant/30 pb-sm">' +
        '<i data-lucide="file-text" class="text-primary"></i> Descripción técnica</h2>' +
        '<p class="font-body-md text-on-surface-variant leading-relaxed whitespace-pre-wrap">' + escapeHtml(f.description || "—") + "</p></section>" +
        '<section class="glass-panel rounded-xl p-lg border-l-4 border-l-tertiary"><h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md border-b border-outline-variant/30 pb-sm">' +
        '<i data-lucide="wrench" class="text-tertiary"></i> Remediación</h2>' +
        '<p class="font-body-md text-on-surface-variant leading-relaxed whitespace-pre-wrap">' + escapeHtml(f.remediation || "—") + "</p></section>" +
        "</div>" +
        '<div class="space-y-md">' +
        '<section class="glass-panel rounded-xl p-lg"><h3 class="font-label-md text-secondary uppercase tracking-wider mb-md border-b border-outline-variant/30 pb-sm">Información</h3>' +
        '<dl class="space-y-sm font-body-sm">' +
        '<div><dt class="text-on-surface-variant">Asset</dt><dd class="font-mono-md text-on-surface mt-xs">' + escapeHtml(f.asset || "—") + "</dd></div>" +
        '<div><dt class="text-on-surface-variant">Estado</dt><dd class="mt-xs">' + escapeHtml(f.status || "proposed") + "</dd></div>" +
        '<div><dt class="text-on-surface-variant">Detectado</dt><dd class="mt-xs">' + escapeHtml(relativeTime(f.created_at)) + "</dd></div>" +
        "</dl></section>" +
        '<a href="critical-findings.html" class="block text-center py-sm text-primary font-label-md hover:bg-surface-container-low rounded-lg">← Volver a hallazgos</a>' +
        "</div></div>";
      if (window.lucide) lucide.createIcons();
    }

    function pickFinding(findings, id, fp) {
      var f = null;
      if (id) f = (findings || []).find(function (x) { return x.id === id; });
      if (!f && fp) {
        f = (findings || []).find(function (x) {
          return (x.fingerprint || "") === fp;
        });
      }
      return f || null;
    }

    function renderScopeBar(alts, scanId) {
      if (!alts || alts.length < 2 || !root) return;
      var bar = document.createElement("div");
      bar.className = "glass-panel rounded-lg p-sm font-body-sm text-on-surface-variant flex flex-wrap items-center gap-sm";
      bar.innerHTML =
        '<span>' + escapeHtml(tKey("finding.multiScope", "Este id aparece en varios análisis. Abre el scope correcto:")) + "</span> " +
        alts.map(function (h) {
          var label = (h.scan && (h.scan.name || h.scan.target || h.scan.id)) || "—";
          var href = "finding-detail.html?id=" + encodeURIComponent(id || "") +
            "&scan=" + encodeURIComponent(h.scan.id);
          var on = h.scan.id === scanId;
          return '<a class="px-sm py-xs rounded-md font-label-md ' +
            (on ? "bg-primary-container text-on-primary-container" : "border border-outline-variant hover:bg-surface-container-low") +
            '" href="' + escapeHtml(href) + '">' + escapeHtml(label) + "</a>";
        }).join("");
      root.parentNode.insertBefore(bar, root);
    }

    function finishRender(finding, scanId, alts) {
      if (!finding) {
        showEmpty();
        return;
      }
      try {
        renderFinding(finding, scanId);
      } catch (err) {
        if (root) {
          root.hidden = false;
          root.innerHTML =
            '<div class="glass-panel rounded-xl p-lg"><h1 class="font-headline-xl">' +
            escapeHtml(finding.title || finding.id || "Hallazgo") +
            "</h1><p class=\"font-body-md text-on-surface-variant mt-sm whitespace-pre-wrap\">" +
            escapeHtml(finding.description || "") +
            "</p></div>";
        }
      }
      renderScopeBar(alts, scanId);
    }

    if (id || fp) {
      var listView = document.getElementById("finding-list-view");
      var scanDetailView = document.getElementById("finding-detail-view");
      if (listView) {
        listView.hidden = true;
        listView.style.display = "none";
      }
      if (scanDetailView) {
        scanDetailView.hidden = true;
        scanDetailView.style.display = "none";
      }
      if (empty) empty.hidden = true;
      if (root) {
        root.hidden = false;
        root.innerHTML = '<p class="font-body-md text-on-surface-variant">Cargando ficha…</p>';
      }
      loadEngagementScans().then(function (scans) {
        var list = scans || [];
        var hitsP = list.length
          ? Promise.all(list.map(function (s) {
            return loadScanFindings(s.id).then(function (fs) {
              var found = pickFinding(fs, id, fp);
              return found ? { scan: s, finding: found } : null;
            });
          })).then(function (rows) { return rows.filter(Boolean); })
          : Promise.resolve([]);
        return hitsP.then(function (hits) {
          if (scanParam) {
            var chosen = hits.find(function (h) { return h.scan && h.scan.id === scanParam; });
            if (chosen) {
              finishRender(chosen.finding, scanParam, hits);
              return;
            }
            return loadScanFindings(scanParam).then(function (findings) {
              finishRender(pickFinding(findings, id, fp), scanParam, hits);
            });
          }
          if (!hits.length) {
            return loadFindings().then(function (findings) {
              finishRender(pickFinding(findings, id, fp), "", []);
            });
          }
          var storedScan = "";
          try { storedScan = sessionStorage.getItem("ds-engagement-id") || ""; } catch (e) { /* */ }
          var preferred = (storedScan && hits.find(function (h) { return h.scan && h.scan.id === storedScan; }))
            || hits.find(function (h) { return h.scan && h.scan.active; })
            || hits[0];
          finishRender(preferred.finding, preferred.scan.id, hits);
        });
      }).catch(function () {
        showEmpty();
      });
      return;
    }

    if (document.getElementById("finding-list-view")) {
      bootScanHub({
        pageFile: "finding-detail.html",
        listViewId: "finding-list-view",
        detailViewId: "finding-detail-view",
        cardsId: "finding-scans-cards",
        emptyId: "finding-empty",
        searchId: "finding-list-search",
        titleId: "finding-detail-title",
        subtitleId: "finding-detail-subtitle",
        ctaLabel: tKey("finding.open", "Ver hallazgos"),
        ctaIcon: "search",
        onDetail: function (findings) {
          if (empty) empty.hidden = true;
          if (root) root.hidden = true;
          var list = document.getElementById("finding-scan-list");
          if (list && window.DarkSpearFindings) DarkSpearFindings.renderList(list, findings, "all");
        },
      });
      return;
    }

    showEmpty();
  }

  function bootSettings() {
    var btn = document.getElementById("panic-btn");
    if (!btn || btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", function () {
      var msg = "Esto borra el pool cifrado de API keys. No afecta hallazgos ni evidencia. ¿Continuar?";
      if (window.DarkSpear && DarkSpear.lang && DarkSpear.lang() === "en") {
        msg = "This deletes the encrypted API key pool. Findings and evidence are not affected. Continue?";
      }
      if (!window.confirm(msg)) return;
      bridgePost("/keystore/panic", { confirm: "WIPE_KEYS" }).then(function (data) {
        var ok = data && data.ok;
        window.alert(ok ? "Pool de claves borrado." : "Error: " + ((data && data.error) || "desconocido"));
      });
    });
  }

  function boot() {
    var p = page();
    if (p === "index.html") bootDashboard();
    else if (p === "settings.html") bootSettings();
    else if (p === "finding-detail.html" || p === "remediation-detail.html") bootFindingDetail();
    else if (p === "vulnerabilities.html") bootVulnerabilities();
    else if (p === "critical-findings.html") bootCriticalFindings();
    else if (p === "assets.html") bootAssets();
    else if (p === "reporting.html") bootReporting();
    else if (p === "osint.html") bootOsint();
    else if (p === "ad-assessment.html") bootAdAssessment();
    else if (p === "attack-graph.html") bootAttackGraph();
    else if (p === "notifications.html") bootNotifications();
    else if (p === "mitre.html") bootMitre();
    else if (p === "remediation-metrics.html") bootRemediationMetrics();
    else if (p === "comprehensive-report.html") bootComprehensiveReport();
    else if (p === "gdpr-alignment.html") bootGdprAlignment();
    else if (p === "maturity-index.html") bootMaturityIndex();
    else if (p === "kill-chain.html") bootKillChain();
    else if (p === "findings-summary.html") bootFindingsSummary();
    else if (p === "executive-summary.html") bootExecutiveSummary();
    else if (p === "remediation-plan.html") bootRemediationPlan();
    else if (p === "report-preview.html") bootReportPreview();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
