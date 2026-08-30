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
    toast._t = setTimeout(function () { el.classList.remove("show"); }, 2200);
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

  function buildPayload() {
    var run = loadRun();
    var findings = loadFindings().filter(function (f) {
      return f && f.title && f.status !== "rejected";
    });
    return {
      product: "Dark Spear",
      engagement: (run && run.target) || "—",
      scope: (run && run.scope) || "—",
      generated: new Date().toISOString(),
      findings: findings.map(function (f) {
        return {
          id: f.id || "",
          title: f.title || "",
          severity: f.severity || "Info",
          asset: f.asset || "",
          description: f.description || "",
          remediation: f.remediation || "",
          status: f.status || "proposed"
        };
      }),
      perimeter: [],
      mitre: []
    };
  }

  function stamp() {
    var run = loadRun();
    var base = (run && run.target) ? String(run.target).replace(/[^a-zA-Z0-9._-]+/g, "_") : "dark-spear";
    return base.slice(0, 64) || "dark-spear";
  }

  function exportJSON() {
    var payload = buildPayload();
    if (!payload.findings.length) {
      toast("No hay hallazgos para exportar");
      return;
    }
    download(stamp() + ".json", "application/json", JSON.stringify(payload, null, 2));
    toast("JSON descargado");
  }

  function exportCSV() {
    var payload = buildPayload();
    if (!payload.findings.length) {
      toast("No hay hallazgos para exportar");
      return;
    }
    var rows = [["id", "title", "severity", "asset", "status"]];
    payload.findings.forEach(function (f) {
      rows.push([
        f.id,
        '"' + String(f.title).replace(/"/g, '""') + '"',
        f.severity,
        f.asset,
        f.status
      ]);
    });
    download(stamp() + "-findings.csv", "text/csv;charset=utf-8", rows.map(function (r) { return r.join(","); }).join("\n"));
    toast("CSV descargado");
  }

  function exportHTML() {
    var payload = buildPayload();
    if (!payload.findings.length) {
      toast("No hay hallazgos para exportar");
      return;
    }
    var rows = payload.findings.map(function (f) {
      return "<tr><td>" + f.id + "</td><td>" + f.title + "</td><td>" + f.severity + "</td><td>" + f.asset + "</td><td>" + f.status + "</td></tr>";
    }).join("");
    var html = "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"/><title>Dark Spear — " + stamp() + "</title>" +
      "<style>body{font-family:Segoe UI,sans-serif;margin:32px;color:#181c1f}table{border-collapse:collapse;width:100%}th,td{border:1px solid #c0c7d4;padding:8px;text-align:left}th{background:#ebeef2}</style></head><body>" +
      "<h1>Dark Spear — " + payload.engagement + "</h1><p>Generado: " + payload.generated + "</p>" +
      "<table><thead><tr><th>ID</th><th>Hallazgo</th><th>Severidad</th><th>Activo</th><th>Estado</th></tr></thead><tbody>" + rows + "</tbody></table></body></html>";
    download(stamp() + ".html", "text/html;charset=utf-8", html);
    toast("HTML descargado");
  }

  function exportSVG() {
    toast("Generá el grafo cuando haya un engagement con rutas documentadas");
  }

  function exportPDF() {
    var payload = buildPayload();
    var path = (location.pathname.split("/").pop() || "").toLowerCase();
    var printable = /comprehensive-report|report-preview|executive-summary|finding-detail|findings-summary|remediation-plan|gdpr-alignment|maturity-index|kill-chain/.test(path);
    if (!payload.findings.length && !printable) {
      toast("No hay informe para exportar");
      return;
    }
    if (printable) {
      toast("Abriendo diálogo de impresión (PDF)");
      setTimeout(function () { window.print(); }, 80);
      return;
    }
    sessionStorage.setItem("ds-print", "1");
    location.href = "comprehensive-report.html";
  }

  function exportEvidence() {
    var payload = buildPayload();
    if (!payload.findings.length) {
      toast("No hay evidencia para exportar");
      return;
    }
    download(stamp() + "-evidence.json", "application/json", JSON.stringify({
      engagement: payload.engagement,
      findings: payload.findings,
      generated: payload.generated
    }, null, 2));
    toast("Evidencia JSON descargada");
  }

  function run(kind) {
    if (kind === "json") exportJSON();
    else if (kind === "csv") exportCSV();
    else if (kind === "html") exportHTML();
    else if (kind === "svg") exportSVG();
    else if (kind === "pdf") exportPDF();
    else if (kind === "evidence") exportEvidence();
  }

  function bindChrome() {
    document.querySelectorAll("a").forEach(function (a) {
      if (!a.querySelector('[data-i18n="nav.signOut"]')) return;
      a.setAttribute("href", "index.html");
      a.addEventListener("click", function (e) {
        e.preventDefault();
        sessionStorage.removeItem("ds-splash");
        toast("Sesión cerrada");
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
    if (sessionStorage.getItem("ds-print") === "1") {
      sessionStorage.removeItem("ds-print");
      setTimeout(function () { window.print(); }, 400);
    }
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

  window.DarkSpearExport = { run: run, json: exportJSON, pdf: exportPDF, html: exportHTML };

  if (!document.querySelector('script[src*="findings-inbox.js"]')) {
    var inbox = document.createElement("script");
    inbox.src = "vendor/findings-inbox.js";
    document.head.appendChild(inbox);
  }
})();
