(function () {
  function toast(msg) {
    var el = document.getElementById("ds-toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "ds-toast";
      el.className = "ds-toast";
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { el.classList.remove("show"); }, 2400);
  }

  function t(key, fallback) {
    if (window.DarkSpear && DarkSpear.t) {
      var v = DarkSpear.t(key);
      if (v && v !== key) return v;
    }
    return fallback;
  }

  function download(filename, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function escHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function csvCell(v) {
    var s = String(v == null ? "" : v);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function loadFindings() {
    try {
      return JSON.parse(sessionStorage.getItem("ds-findings-inbox") || "[]");
    } catch (e) {
      return [];
    }
  }

  function loadRun() {
    try {
      return JSON.parse(sessionStorage.getItem("ds-engine-run") || "null");
    } catch (e) {
      return null;
    }
  }

  function normalizeFindings(list) {
    return (list || []).filter(function (f) {
      return f && f.title && f.status !== "rejected";
    }).map(function (f) {
      return {
        id: f.id || "",
        title: String(f.title || "").trim(),
        severity: f.severity || "Info",
        asset: String(f.asset || "").trim(),
        description: String(f.description || "").trim(),
        remediation: String(f.remediation || "").trim(),
        status: f.status || "proposed",
        evidence_step_ids: Array.isArray(f.evidence_step_ids) ? f.evidence_step_ids : [],
        evidence_hashes: Array.isArray(f.evidence_hashes) ? f.evidence_hashes : [],
        created_at: f.created_at || null,
      };
    });
  }

  function buildPayload(extra) {
    var run = loadRun();
    var findings = normalizeFindings(extra && extra.findings ? extra.findings : loadFindings());
    var payload = {
      product: "Dark Spear",
      engagement: (run && run.target) || (extra && extra.target) || "—",
      scope: (run && run.scope) || (extra && extra.scope) || "—",
      model: (run && run.model) || (extra && extra.model) || "",
      endpoint: (run && run.endpoint) || "",
      generated: new Date().toISOString(),
      findings: findings,
      summary: summarize(findings),
    };
    if (extra && extra.steps) payload.steps = extra.steps;
    if (extra && extra.axis_ledger) payload.axis_ledger = extra.axis_ledger;
    if (extra && extra.engagementId != null) payload.engagementId = extra.engagementId;
    return payload;
  }

  function summarize(findings) {
    var counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach(function (f) {
      var k = f.severity;
      if (counts[k] != null) counts[k] += 1;
      else counts.Info += 1;
    });
    return { total: findings.length, by_severity: counts };
  }

  function stamp() {
    var run = loadRun();
    var base = (run && run.target) ? String(run.target).replace(/[^a-zA-Z0-9._-]+/g, "_") : "dark-spear";
    return base.slice(0, 64) || "dark-spear";
  }

  function hasFindings(extra) {
    return buildPayload(extra).findings.length > 0;
  }

  function requireFindings(extra) {
    if (!hasFindings(extra)) {
      toast(t("export.noData", "No hay hallazgos para exportar"));
      return false;
    }
    return true;
  }

  function sevClass(sev) {
    var s = String(sev || "").toLowerCase();
    if (s === "critical") return "crit";
    if (s === "high") return "high";
    if (s === "medium") return "med";
    if (s === "low") return "low";
    return "info";
  }

  function statusClass(status) {
    var s = String(status || "").toLowerCase();
    if (s === "reported") return "st-reported";
    if (s === "verifying") return "st-verifying";
    if (s === "accepted") return "st-accepted";
    if (s === "rejected") return "st-rejected";
    if (s === "edited") return "st-edited";
    return "st-proposed";
  }

  function findLivePaper() {
    return document.getElementById("preview-paper") || document.getElementById("comp-paper");
  }

  function injectPrintChrome() {
    if (document.getElementById("ds-print-chrome")) return;
    var style = document.createElement("style");
    style.id = "ds-print-chrome";
    style.textContent =
      "@page{size:A4;margin:12mm}" +
      "@media print{" +
      "*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}" +
      "html,body{background:#fff!important}" +
      "body.ds-printing nav[data-app-nav]," +
      "body.ds-printing header," +
      "body.ds-printing aside," +
      "body.ds-printing #preview-actionbar," +
      "body.ds-printing #preview-config," +
      "body.ds-printing #preview-list-view," +
      "body.ds-printing #comp-list-view," +
      "body.ds-printing #comp-toc," +
      "body.ds-printing .skip-link," +
      "body.ds-printing .sidebar-edge-toggle{display:none!important}" +
      "body.ds-printing,body.ds-printing #main-content,body.ds-printing .overflow-hidden," +
      "body.ds-printing .overflow-y-auto,body.ds-printing .h-screen{overflow:visible!important;height:auto!important;max-height:none!important}" +
      "body.ds-printing #preview-detail-view>div:first-child," +
      "body.ds-printing #comp-detail-view>nav," +
      "body.ds-printing #comp-detail-view>div:first-of-type," +
      "body.ds-printing #comp-stats{display:none!important}" +
      "body.ds-printing .ds-print-target{box-shadow:none!important;border:none!important;max-width:none!important;min-height:0!important;margin:0 auto!important;background:#fff!important}" +
      "body.ds-printing .glass-panel{background:#fff!important;border:1px solid #D8E3F0!important}" +
      "body.ds-printing .report-finding-card+ .report-finding-card{break-before:page;border-top:0}" +
      "body.ds-printing .hidden-section{display:none!important}" +
      "}";
    document.head.appendChild(style);
  }

  function snapshotCanvases(liveRoot, cloneRoot) {
    var live = liveRoot.querySelectorAll("canvas");
    var dest = cloneRoot.querySelectorAll("canvas");
    for (var i = 0; i < live.length && i < dest.length; i++) {
      try {
        var img = document.createElement("img");
        img.src = live[i].toDataURL("image/png");
        img.alt = "";
        img.style.maxWidth = "100%";
        dest[i].parentNode.replaceChild(img, dest[i]);
      } catch (err) { /* canvas tainted or empty */ }
    }
  }

  function collectHeadAssets() {
    var parts = [];
    document.querySelectorAll("link[rel='stylesheet']").forEach(function (l) {
      parts.push('<link rel="stylesheet" href="' + l.href + '">');
    });
    document.querySelectorAll("style").forEach(function (s) {
      parts.push(s.outerHTML);
    });
    return parts.join("\n");
  }

  function standalonePaperHTML(paper) {
    var clone = paper.cloneNode(true);
    snapshotCanvases(paper, clone);
    clone.classList.remove("paper-shadow");
    return "<!DOCTYPE html><html class=\"" + escHtml(document.documentElement.className || "light") +
      "\" lang=\"" + escHtml(document.documentElement.lang || "es") + "\"><head><meta charset=\"utf-8\"/>" +
      "<title>Dark Spear — Informe</title>" + collectHeadAssets() +
      "<style>@page{size:A4;margin:12mm}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}" +
      "body{margin:0;background:#fff}.paper-shadow{box-shadow:none!important}</style></head>" +
      "<body class=\"bg-white text-on-surface\">" + clone.outerHTML + "</body></html>";
  }

  function printLivePaper() {
    var paper = findLivePaper();
    if (!paper || !paper.innerHTML.trim()) return false;
    injectPrintChrome();
    document.body.classList.add("ds-printing");
    paper.classList.add("ds-print-target");
    var cleanup = function () {
      document.body.classList.remove("ds-printing");
      paper.classList.remove("ds-print-target");
      window.removeEventListener("afterprint", cleanup);
    };
    window.addEventListener("afterprint", cleanup);
    setTimeout(function () { window.print(); }, 50);
    return true;
  }

  function downloadLivePaper() {
    var paper = findLivePaper();
    if (!paper || !paper.innerHTML.trim()) return false;
    download(stamp() + ".html", "text/html;charset=utf-8", standalonePaperHTML(paper));
    return true;
  }

  function rawFindings(extra) {
    var list = extra && extra.findings ? extra.findings : loadFindings();
    var rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (list || []).filter(function (f) {
      return f && f.title && f.status !== "rejected";
    }).slice().sort(function (a, b) {
      var ra = rank[String(a.severity || "").toLowerCase()];
      var rb = rank[String(b.severity || "").toLowerCase()];
      return (ra != null ? ra : 5) - (rb != null ? rb : 5);
    });
  }

  function sevBadgeClass(sev) {
    var s = String(sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "bg-error/10 text-error border-error/20";
    if (s === "medium") return "bg-secondary-container/30 text-secondary";
    return "bg-surface-variant text-on-surface-variant";
  }

  function relativeTime(ts) {
    if (ts == null || ts === "") return "—";
    var d = typeof ts === "number" ? new Date(ts < 1e12 ? ts * 1000 : ts) : new Date(ts);
    return isNaN(d.getTime()) ? "—" : d.toLocaleString();
  }

  function ensureDossier() {
    return new Promise(function (resolve) {
      if (window.DarkSpearDossier && typeof DarkSpearDossier.render === "function") {
        resolve(true);
        return;
      }
      var src = new URL("vendor/finding-dossier.js", location.href).href;
      var existing = document.querySelector('script[src*="finding-dossier.js"]');
      function done() {
        resolve(!!(window.DarkSpearDossier && typeof DarkSpearDossier.render === "function"));
      }
      if (existing) {
        existing.addEventListener("load", done);
        existing.addEventListener("error", function () { resolve(false); });
        setTimeout(done, 0);
        return;
      }
      var s = document.createElement("script");
      s.src = src;
      s.onload = done;
      s.onerror = function () { resolve(false); };
      document.head.appendChild(s);
    });
  }

  var DOSSIER_DOC_CSS =
    "*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}" +
    "body{margin:0;padding:28px 24px;background:#f7fafe;color:#181c1f;font-family:'Public Sans',sans-serif}" +
    ".glass-panel{background-color:#ffffff;border:1px solid #D8E3F0}" +
    "[data-lucide],svg.lucide{width:20px;height:20px;stroke-width:1.75;flex-shrink:0}" +
    ".icon-sm{width:16px!important;height:16px!important}" +
    ".icon-md{width:18px!important;height:18px!important}" +
    ".report-finding-card{margin-top:36px}" +
    ".report-finding-card+.report-finding-card{break-before:page}" +
    "@page{size:A4;margin:12mm}" +
    ".ds-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 0}" +
    ".ds-kpi{border:1px solid #D8E3F0;border-radius:10px;padding:10px 14px;min-width:88px;background:#fff}" +
    ".ds-kpi strong{display:block;font-size:22px}" +
    ".ds-kpi.crit{background:#ffdad6;color:#93000a}" +
    ".ds-kpi.high{background:#fff0e8;color:#ba1a1a}" +
    ".ds-kpi.med{background:#d3e3ff;color:#004883}" +
    ".ds-kpi.low{background:#ebeef2;color:#404752}" +
    ".ds-kpi.info{background:#e8f5f2;color:#005046}";

  var FALLBACK_TW_CONFIG =
    "tailwind.config={darkMode:'class',theme:{extend:{" +
    "colors:{" +
    "'background':'#f7fafe','on-surface':'#181c1f','on-surface-variant':'#404752'," +
    "'primary':'#005faa','primary-container':'#0078d4','on-primary':'#ffffff'," +
    "'on-primary-container':'#ffffff','secondary':'#505f79'," +
    "'secondary-container':'#d1e0ff','on-secondary-container':'#54637d'," +
    "'error':'#ba1a1a','error-container':'#ffdad6','surface-variant':'#e0e3e7'," +
    "'surface-container-low':'#f1f4f8','surface-container-high':'#e5e8ec'," +
    "'surface-container-lowest':'#ffffff','outline-variant':'#c0c7d4'," +
    "'tertiary':'#006a5c','tertiary-container':'#0a8575'" +
    "}," +
    "borderRadius:{DEFAULT:'0.25rem',lg:'0.5rem',xl:'0.75rem',full:'9999px'}," +
    "spacing:{xs:'4px',sm:'8px',md:'16px',lg:'24px',xl:'32px'}," +
    "fontFamily:{'headline-xl':['Public Sans'],'headline-lg':['Public Sans']," +
    "'headline-md':['Public Sans'],'body-lg':['Public Sans'],'body-md':['Public Sans']," +
    "'body-sm':['Public Sans'],'label-md':['Public Sans'],'mono-md':['JetBrains Mono']}," +
    "fontSize:{" +
    "'headline-xl':['32px',{lineHeight:'40px',letterSpacing:'-0.02em',fontWeight:'700'}]," +
    "'headline-lg':['24px',{lineHeight:'32px',fontWeight:'600'}]," +
    "'headline-md':['20px',{lineHeight:'28px',fontWeight:'600'}]," +
    "'body-lg':['16px',{lineHeight:'24px',fontWeight:'400'}]," +
    "'body-md':['14px',{lineHeight:'20px',fontWeight:'400'}]," +
    "'body-sm':['12px',{lineHeight:'16px',fontWeight:'400'}]," +
    "'label-md':['12px',{lineHeight:'16px',letterSpacing:'0.05em',fontWeight:'600'}]," +
    "'mono-md':['13px',{lineHeight:'20px',fontWeight:'400'}]" +
    "}}}}";

  function dossierAssetsHead() {
    var tw = document.getElementById("tailwind-config");
    var tokens = new URL("vendor/tokens.css", location.href).href;
    var lucide = new URL("vendor/lucide.min.js", location.href).href;
    return (
      '<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>' +
      (tw ? tw.outerHTML : "<script>" + FALLBACK_TW_CONFIG + "<\/script>") +
      '<link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet"/>' +
      '<link href="' + tokens + '" rel="stylesheet"/>' +
      '<script src="' + lucide + '"><\/script>' +
      "<style>" + DOSSIER_DOC_CSS + "</style>"
    );
  }

  function coverHTML(payload) {
    var sev = payload.summary.by_severity;
    function kpi(label, n, cls) {
      return '<div class="ds-kpi ' + cls + '"><div>' + escHtml(label) + "</div><strong>" + n + "</strong></div>";
    }
    return '<header class="glass-panel rounded-xl p-lg mb-md">' +
      '<p class="font-label-md text-secondary">Dark Spear</p>' +
      '<h1 class="font-headline-xl text-headline-xl text-on-surface">' +
      escHtml(t("export.reportTitle", "Informe de hallazgos")) + "</h1>" +
      '<p class="font-body-md text-on-surface-variant mt-sm">' +
      escHtml(payload.engagement) + " · " + escHtml(payload.scope) + "</p>" +
      '<p class="font-body-sm text-on-surface-variant">' + escHtml(payload.generated) + "</p>" +
      '<div class="ds-kpis">' +
      kpi("Total", payload.summary.total, "") +
      kpi("Critical", sev.Critical, "crit") +
      kpi("High", sev.High, "high") +
      kpi("Medium", sev.Medium, "med") +
      kpi("Low", sev.Low, "low") +
      kpi("Info", sev.Info, "info") +
      "</div></header>";
  }

  function buildDossierBodyHTML(extra) {
    var payload = buildPayload(extra);
    var findings = rawFindings(extra);
    var host = document.createElement("div");
    host.innerHTML = coverHTML(payload);
    findings.forEach(function (f, i) {
      var card = document.createElement("article");
      card.className = "report-finding-card";
      host.appendChild(card);
      DarkSpearDossier.render(card, f, {
        embedded: true,
        idPrefix: "exp-" + String(f.id || i).replace(/[^a-zA-Z0-9_-]/g, "-") + "-",
        scanId: extra && extra.engagementId,
        escapeHtml: escHtml,
        relativeTime: relativeTime,
        sevBadgeClass: sevBadgeClass,
      });
    });
    return host.innerHTML;
  }

  function buildDossierDocumentHTML(extra) {
    return "<!DOCTYPE html><html class=\"" +
      escHtml(document.documentElement.className || "light") +
      "\" lang=\"" + escHtml(document.documentElement.lang || "es") +
      "\"><head><meta charset=\"utf-8\"/><title>Dark Spear — Informe</title>" +
      dossierAssetsHead() +
      "</head><body class=\"bg-background text-on-surface font-body-md\">" +
      buildDossierBodyHTML(extra) +
      "<script>if(window.lucide)lucide.createIcons();<\/script></body></html>";
  }

  function openDossierWindow(extra, opts) {
    var html = buildDossierDocumentHTML(extra);
    var w = window.open("", "_blank");
    if (!w) return false;
    w.document.open();
    w.document.write(html);
    w.document.close();
    if (opts && opts.print) {
      var printed = false;
      var go = function () {
        if (printed) return;
        printed = true;
        try { if (w.lucide) w.lucide.createIcons(); } catch (err) {}
        w.focus();
        w.print();
      };
      if (w.addEventListener) w.addEventListener("load", function () { setTimeout(go, 350); });
      setTimeout(go, 1200);
    }
    return true;
  }

  function buildReportHTML(payload, { printable } = { printable: false }) {
    var rows = payload.findings.map(function (f) {
      return "<article class=\"finding\">" +
        "<header><span class=\"id\">" + escHtml(f.id) + "</span>" +
        "<span class=\"sev " + sevClass(f.severity) + "\">" + escHtml(f.severity) + "</span>" +
        "<span class=\"st " + statusClass(f.status) + "\">" + escHtml(f.status) + "</span></header>" +
        "<h2>" + escHtml(f.title) + "</h2>" +
        "<p class=\"asset\">" + escHtml(f.asset) + "</p>" +
        "<p>" + escHtml(f.description || "—") + "</p>" +
        "<p class=\"rem\"><strong>Remediación:</strong> " + escHtml(f.remediation || "—") + "</p>" +
        "</article>";
    }).join("");

    var sev = payload.summary.by_severity;
    var kpi = function (label, n, cls) {
      return "<div class=\"kpi " + cls + "\"><div>" + label + "</div><strong>" + n + "</strong></div>";
    };
    var printCss = printable
      ? "@page{size:A4;margin:14mm}@media print{body{margin:0}.finding{break-inside:avoid}}"
      : "";
    return "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"/>" +
      "<title>Dark Spear — " + escHtml(payload.engagement) + "</title>" +
      "<style>" +
      "*{-webkit-print-color-adjust:exact;print-color-adjust:exact}" +
      "body{font-family:'Public Sans',Segoe UI,sans-serif;margin:32px;color:#181c1f;line-height:1.5;background:#fff}" +
      "h1{font-size:26px;margin:0 0 8px;color:#005faa}" +
      ".meta{color:#404752;margin-bottom:20px}" +
      ".kpis{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 24px}" +
      ".kpi{border-radius:8px;padding:10px 14px;min-width:88px;border:1px solid #e0e3e7;background:#f7fafe}" +
      ".kpi.crit{background:#ffdad6;color:#93000a;border-color:#ffdad6}" +
      ".kpi.high{background:#fff0e8;color:#ba1a1a;border-color:#ffdad6}" +
      ".kpi.med{background:#d3e3ff;color:#004883;border-color:#d3e3ff}" +
      ".kpi.low{background:#ebeef2;color:#404752}" +
      ".kpi.info{background:#e8f5f2;color:#005046}" +
      ".kpi strong{display:block;font-size:22px}" +
      ".finding{border:1px solid #e0e3e7;border-radius:10px;padding:16px;margin:0 0 16px;break-inside:avoid}" +
      ".finding header{display:flex;gap:8px;align-items:center;margin-bottom:8px}" +
      ".finding h2{font-size:16px;margin:0 0 6px;color:#181c1f}" +
      ".finding .asset{font-family:'JetBrains Mono',monospace;font-size:12px;color:#005faa}" +
      ".id{font-family:'JetBrains Mono',monospace;font-size:12px;color:#505f79}" +
      ".st{font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 7px;border-radius:4px;color:#717783;background:#eceef1}" +
      ".st.st-reported{background:#d4f2dd;color:#0f6b34}" +
      ".st.st-verifying{background:#fff2cc;color:#8a6300}" +
      ".st.st-accepted{background:#d3e3ff;color:#004883}" +
      ".st.st-rejected{background:#f0f0f0;color:#5c5c5c;text-decoration:line-through}" +
      ".sev{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:4px}" +
      ".sev.crit{background:#ffdad6;color:#93000a}" +
      ".sev.high{background:#ffdad6;color:#ba1a1a}" +
      ".sev.med{background:#d3e3ff;color:#004883}" +
      ".sev.low{background:#ebeef2;color:#404752}" +
      ".sev.info{background:#e8f5f2;color:#005046}" +
      ".rem{color:#404752}" +
      printCss +
      "</style></head><body>" +
      "<h1>Dark Spear — Informe de hallazgos</h1>" +
      "<div class=\"meta\">" +
      "<div><strong>Engagement:</strong> " + escHtml(payload.engagement) + "</div>" +
      "<div><strong>Scope:</strong> " + escHtml(payload.scope) + "</div>" +
      "<div><strong>Generado:</strong> " + escHtml(payload.generated) + "</div>" +
      "</div>" +
      "<div class=\"kpis\">" +
      kpi("Total", payload.summary.total, "") +
      kpi("Critical", sev.Critical, "crit") +
      kpi("High", sev.High, "high") +
      kpi("Medium", sev.Medium, "med") +
      kpi("Low", sev.Low, "low") +
      kpi("Info", sev.Info, "info") +
      "</div>" +
      rows + "</body></html>";
  }

  function exportJSON(extra) {
    var payload = buildPayload(extra);
    if (!payload.findings.length && !(payload.steps && payload.steps.length)) {
      toast(t("export.noData", "No hay hallazgos para exportar"));
      return;
    }
    download(stamp() + ".json", "application/json", JSON.stringify(payload, null, 2));
    toast(t("export.jsonOk", "JSON descargado"));
  }

  function exportCSV(extra) {
    if (!requireFindings(extra)) return;
    var payload = buildPayload(extra);
    var rows = [["id", "title", "severity", "asset", "status", "description", "remediation"]];
    payload.findings.forEach(function (f) {
      rows.push([
        csvCell(f.id),
        csvCell(f.title),
        csvCell(f.severity),
        csvCell(f.asset),
        csvCell(f.status),
        csvCell(f.description),
        csvCell(f.remediation),
      ]);
    });
    download(stamp() + "-findings.csv", "text/csv;charset=utf-8", "\uFEFF" + rows.map(function (r) { return r.join(","); }).join("\n"));
    toast(t("export.csvOk", "CSV descargado"));
  }

  function fallbackPrint(extra) {
    var payload = buildPayload(extra);
    var html = buildReportHTML(payload, { printable: true });
    var w = window.open("", "_blank");
    if (!w) {
      toast(t("export.popupBlocked", "Permite ventanas emergentes para exportar PDF"));
      return;
    }
    w.document.open();
    w.document.write(html);
    w.document.close();
    w.onload = function () {
      w.focus();
      w.print();
    };
    toast(t("export.pdfOk", "Abriendo diálogo de impresión (PDF)"));
  }

  function exportHTML(extra) {
    if (downloadLivePaper()) {
      toast(t("export.htmlOk", "HTML descargado"));
      return;
    }
    if (!requireFindings(extra)) return;
    ensureDossier().then(function (ok) {
      if (ok) {
        download(stamp() + ".html", "text/html;charset=utf-8", buildDossierDocumentHTML(extra));
      } else {
        download(stamp() + ".html", "text/html;charset=utf-8", buildReportHTML(buildPayload(extra), { printable: false }));
      }
      toast(t("export.htmlOk", "HTML descargado"));
    });
  }

  function exportPDF(extra) {
    if (printLivePaper()) {
      toast(t("export.pdfOk", "Abriendo diálogo de impresión (PDF)"));
      return;
    }
    if (!requireFindings(extra)) return;
    ensureDossier().then(function (ok) {
      if (ok && openDossierWindow(extra, { print: true })) {
        toast(t("export.pdfOk", "Abriendo diálogo de impresión (PDF)"));
        return;
      }
      fallbackPrint(extra);
    });
  }

  function exportSVG() {
    toast(t("export.svgSoon", "Exporta el grafo cuando haya rutas documentadas en el engagement"));
  }

  function exportEvidence(extra) {
    if (!requireFindings(extra)) return;
    var payload = buildPayload(extra);
    download(stamp() + "-evidence.json", "application/json", JSON.stringify({
      engagement: payload.engagement,
      scope: payload.scope,
      generated: payload.generated,
      findings: payload.findings.map(function (f) {
        return {
          id: f.id,
          title: f.title,
          severity: f.severity,
          asset: f.asset,
          evidence_step_ids: f.evidence_step_ids,
          evidence_hashes: f.evidence_hashes,
        };
      }),
    }, null, 2));
    toast(t("export.evidenceOk", "Evidencia JSON descargada"));
  }

  function downloadEngagementBundle(bundle) {
    var payload = buildPayload({
      findings: bundle.findings,
      steps: bundle.steps,
      axis_ledger: bundle.axis_ledger,
      engagementId: bundle.engagementId,
      target: bundle.target,
      scope: bundle.scope,
      model: bundle.model,
    });
    if (!payload.findings.length && !(payload.steps && payload.steps.length)) {
      toast(t("export.noEngagement", "No hay pasos ni hallazgos para exportar"));
      return;
    }
    download(stamp() + "-engagement.json", "application/json", JSON.stringify(payload, null, 2));
    toast(t("export.jsonOk", "JSON descargado"));
  }

  function run(kind, extra) {
    if (kind === "json") exportJSON(extra);
    else if (kind === "csv") exportCSV(extra);
    else if (kind === "html") exportHTML(extra);
    else if (kind === "svg") exportSVG();
    else if (kind === "pdf") exportPDF(extra);
    else if (kind === "evidence") exportEvidence(extra);
  }

  function bindChrome() {
    document.querySelectorAll("a").forEach(function (a) {
      if (!a.querySelector('[data-i18n="nav.signOut"]')) return;
      a.setAttribute("href", "index.html");
      a.addEventListener("click", function (e) {
        e.preventDefault();
        try {
          localStorage.removeItem("ds-splash");
          sessionStorage.removeItem("ds-splash");
        } catch (err) {}
        toast(t("export.signedOut", "Sesión cerrada"));
        setTimeout(function () { location.href = "index.html"; }, 400);
      });
    });

    document.querySelectorAll('[data-i18n-aria="aria.notifications"]').forEach(function (btn) {
      if (btn.tagName === "A") return;
      btn.addEventListener("click", function () { location.href = "notifications.html"; });
    });

    document.querySelectorAll("header [role='link'], header .cursor-pointer").forEach(function (wrap) {
      if (wrap.closest("a")) return;
      if (!wrap.querySelector(".font-label-md, img")) return;
      wrap.style.cursor = "pointer";
      wrap.setAttribute("role", "link");
      wrap.setAttribute("tabindex", "0");
      wrap.addEventListener("click", function () { location.href = "profile.html"; });
      wrap.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); location.href = "profile.html"; }
      });
    });
  }

  document.addEventListener("click", function (e) {
    var el = e.target.closest("[data-export]");
    if (!el) return;
    e.preventDefault();
    run(el.getAttribute("data-export"));
  });

  document.addEventListener("DOMContentLoaded", function () {
    bindChrome();
    var fmtBtn = document.getElementById("btn-generate-fmt");
    var fmt = document.getElementById("fmt");
    if (fmtBtn && fmt && !document.getElementById("preview-paper")) {
      fmtBtn.addEventListener("click", function (e) {
        e.preventDefault();
        var v = (fmt.value || "").toLowerCase();
        if (v.indexOf("json") !== -1) run("json");
        else if (v.indexOf("html") !== -1) run("html");
        else run("pdf");
      });
    }
    var btnExport = document.getElementById("btn-export");
    if (btnExport && !btnExport.getAttribute("data-export")) {
      btnExport.setAttribute("data-export", "pdf");
    }
  });

  window.DarkSpearExport = {
    run: run,
    json: exportJSON,
    csv: exportCSV,
    html: exportHTML,
    pdf: exportPDF,
    evidence: exportEvidence,
    buildPayload: buildPayload,
    buildDossierDocumentHTML: buildDossierDocumentHTML,
    hasFindings: hasFindings,
    downloadEngagementBundle: downloadEngagementBundle,
  };

  if (!document.querySelector('script[src*="findings-inbox.js"]')) {
    var inbox = document.createElement("script");
    inbox.src = "vendor/findings-inbox.js";
    document.head.appendChild(inbox);
  }
})();
