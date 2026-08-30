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

  function buildReportHTML(payload, { printable } = { printable: false }) {
    var rows = payload.findings.map(function (f) {
      return "<tr>" +
        "<td>" + escHtml(f.id) + "</td>" +
        "<td><strong>" + escHtml(f.title) + "</strong></td>" +
        "<td>" + escHtml(f.severity) + "</td>" +
        "<td>" + escHtml(f.asset) + "</td>" +
        "<td>" + escHtml(f.status) + "</td>" +
        "</tr>" +
        "<tr class=\"detail\"><td colspan=\"5\">" +
        "<p><strong>Descripción:</strong> " + escHtml(f.description || "—") + "</p>" +
        "<p><strong>Remediación:</strong> " + escHtml(f.remediation || "—") + "</p>" +
        (f.evidence_step_ids.length ? "<p><strong>Evidencia (steps):</strong> " + escHtml(f.evidence_step_ids.join(", ")) + "</p>" : "") +
        "</td></tr>";
    }).join("");

    var sev = payload.summary.by_severity;
    var printCss = printable ? "@page{margin:18mm}@media print{body{margin:0}.no-print{display:none}}" : "";
    return "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"/>" +
      "<title>Dark Spear — " + escHtml(payload.engagement) + "</title>" +
      "<style>" +
      "body{font-family:'Public Sans',Segoe UI,sans-serif;margin:32px;color:#181c1f;line-height:1.5}" +
      "h1{font-size:28px;margin:0 0 8px}meta-block{color:#404752;margin-bottom:24px}" +
      ".kpis{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}" +
      ".kpi{border:1px solid #c0c7d4;border-radius:8px;padding:12px 16px;min-width:100px}" +
      "table{border-collapse:collapse;width:100%;margin-top:16px;font-size:14px}" +
      "th,td{border:1px solid #c0c7d4;padding:10px;text-align:left;vertical-align:top}" +
      "th{background:#ebeef2;font-weight:600}tr.detail td{background:#f7fafe;font-size:13px}" +
      printCss +
      "</style></head><body>" +
      "<h1>Dark Spear — Informe de hallazgos</h1>" +
      "<div class=\"meta-block\">" +
      "<div><strong>Engagement:</strong> " + escHtml(payload.engagement) + "</div>" +
      "<div><strong>Scope:</strong> " + escHtml(payload.scope) + "</div>" +
      "<div><strong>Generado:</strong> " + escHtml(payload.generated) + "</div>" +
      "</div>" +
      "<div class=\"kpis\">" +
      "<div class=\"kpi\"><div>Total</div><strong>" + payload.summary.total + "</strong></div>" +
      "<div class=\"kpi\"><div>Critical</div><strong>" + sev.Critical + "</strong></div>" +
      "<div class=\"kpi\"><div>High</div><strong>" + sev.High + "</strong></div>" +
      "<div class=\"kpi\"><div>Medium</div><strong>" + sev.Medium + "</strong></div>" +
      "</div>" +
      "<table><thead><tr><th>ID</th><th>Hallazgo</th><th>Severidad</th><th>Activo</th><th>Estado</th></tr></thead><tbody>" +
      rows + "</tbody></table></body></html>";
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

  function exportHTML(extra) {
    if (!requireFindings(extra)) return;
    var payload = buildPayload(extra);
    download(stamp() + ".html", "text/html;charset=utf-8", buildReportHTML(payload, { printable: false }));
    toast(t("export.htmlOk", "HTML descargado"));
  }

  function exportPDF(extra) {
    if (!requireFindings(extra)) return;
    var payload = buildPayload(extra);
    var html = buildReportHTML(payload, { printable: true });
    var w = window.open("", "_blank");
    if (!w) {
      toast(t("export.popupBlocked", "Permití ventanas emergentes para exportar PDF"));
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

  function exportSVG() {
    toast(t("export.svgSoon", "Exportá el grafo cuando haya rutas documentadas en el engagement"));
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
        sessionStorage.removeItem("ds-splash");
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
    if (fmtBtn && fmt) {
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
    hasFindings: hasFindings,
    downloadEngagementBundle: downloadEngagementBundle,
  };

  if (!document.querySelector('script[src*="findings-inbox.js"]')) {
    var inbox = document.createElement("script");
    inbox.src = "vendor/findings-inbox.js";
    document.head.appendChild(inbox);
  }
})();
