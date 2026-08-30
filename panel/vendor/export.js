(function () {
  var PAYLOAD = {
    product: "Dark Spear",
    engagement: "Target_Alpha_Main",
    generated: new Date().toISOString(),
    findings: [
      { id: "F-001", title: "Domain Admin credentials extracted", severity: "critical", cvss: 9.8, asset: "DC01" },
      { id: "F-003", title: "Lateral path via unconstrained delegation", severity: "high", cvss: 8.4, asset: "WS01" },
      { id: "F-005", title: "Blind SQLi in authentication module", severity: "high", cvss: 8.1, asset: "SRV-WEB-01" },
      { id: "#04-A", title: "Unencrypted PII in development databases", severity: "critical", cvss: 9.1, asset: "db-dev" }
    ],
    perimeter: ["Internet Externo", "VPN-User-74", "SRV-WEB-01", "DB-PROD-Main"],
    mitre: ["T1190", "T1003", "T1550", "T1078"]
  };

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

  function stamp() {
    return "Target_Alpha_Main";
  }

  function exportJSON() {
    download(stamp() + ".json", "application/json", JSON.stringify(PAYLOAD, null, 2));
    toast("JSON descargado");
  }

  function exportCSV() {
    var rows = [["id", "title", "severity", "cvss", "asset"]];
    PAYLOAD.findings.forEach(function (f) {
      rows.push([f.id, '"' + f.title.replace(/"/g, '""') + '"', f.severity, f.cvss, f.asset]);
    });
    download(stamp() + "-assets.csv", "text/csv;charset=utf-8", rows.map(function (r) { return r.join(","); }).join("\n"));
    toast("CSV descargado");
  }

  function exportHTML() {
    var rows = PAYLOAD.findings.map(function (f) {
      return "<tr><td>" + f.id + "</td><td>" + f.title + "</td><td>" + f.severity + "</td><td>" + f.cvss + "</td><td>" + f.asset + "</td></tr>";
    }).join("");
    var html = "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"/><title>Dark Spear — " + stamp() + "</title>" +
      "<style>body{font-family:Segoe UI,sans-serif;margin:32px;color:#181c1f}table{border-collapse:collapse;width:100%}th,td{border:1px solid #c0c7d4;padding:8px;text-align:left}th{background:#ebeef2}</style></head><body>" +
      "<h1>Dark Spear — " + stamp() + "</h1><p>Generado: " + PAYLOAD.generated + "</p>" +
      "<p>Perímetro: " + PAYLOAD.perimeter.join(" → ") + "</p>" +
      "<table><thead><tr><th>ID</th><th>Hallazgo</th><th>Severidad</th><th>CVSS</th><th>Activo</th></tr></thead><tbody>" + rows + "</tbody></table></body></html>";
    download(stamp() + ".html", "text/html;charset=utf-8", html);
    toast("HTML descargado");
  }

  function exportSVG() {
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="920" height="420" viewBox="0 0 920 420">' +
      '<rect width="920" height="420" fill="#f7fafe"/>' +
      '<line x1="140" y1="90" x2="430" y2="210" stroke="#c0c7d4" stroke-dasharray="6 6" stroke-width="2"/>' +
      '<line x1="140" y1="310" x2="430" y2="210" stroke="#c0c7d4" stroke-width="2"/>' +
      '<line x1="500" y1="200" x2="740" y2="140" stroke="#ba1a1a" stroke-width="4"/>' +
      '<circle cx="140" cy="90" r="28" fill="#e0e3e7" stroke="#c0c7d4" stroke-width="2"/>' +
      '<rect x="112" y="282" width="56" height="56" rx="8" fill="#fff" stroke="#c0c7d4"/>' +
      '<rect x="402" y="176" width="64" height="64" rx="8" fill="#fff" stroke="#0078d4" stroke-width="3"/>' +
      '<rect x="708" y="108" width="56" height="56" rx="8" fill="#fff" stroke="#ba1a1a" stroke-width="3"/>' +
      '<text x="140" y="140" text-anchor="middle" font-family="Public Sans,sans-serif" font-size="12" fill="#181c1f">Internet Externo</text>' +
      '<text x="140" y="360" text-anchor="middle" font-family="Public Sans,sans-serif" font-size="12" fill="#181c1f">VPN-User-74</text>' +
      '<text x="434" y="262" text-anchor="middle" font-family="Public Sans,sans-serif" font-size="12" font-weight="700" fill="#181c1f">SRV-WEB-01</text>' +
      '<text x="736" y="188" text-anchor="middle" font-family="Public Sans,sans-serif" font-size="12" fill="#181c1f">DB-PROD-Main</text>' +
      '</svg>';
    download(stamp() + "-attack-graph.svg", "image/svg+xml;charset=utf-8", svg);
    toast("SVG descargado");
  }

  function exportPDF() {
    var path = (location.pathname.split("/").pop() || "").toLowerCase();
    var printable = /comprehensive-report|report-preview|executive-summary|finding-detail|findings-summary|remediation-plan|gdpr-alignment|maturity-index|kill-chain/.test(path);
    if (printable) {
      toast("Abriendo diálogo de impresión (PDF)");
      setTimeout(function () { window.print(); }, 80);
      return;
    }
    sessionStorage.setItem("ds-print", "1");
    location.href = "comprehensive-report.html";
  }

  function exportEvidence() {
    download(stamp() + "-evidence.json", "application/json", JSON.stringify({
      path: "77A-92",
      nodes: ["10.0.4.12", "app-server-01", "db-cluster"],
      perimeter: PAYLOAD.perimeter,
      generated: PAYLOAD.generated
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

    document.querySelectorAll("header img[alt*='avatar'], header img[alt*='User profile']").forEach(function (img) {
      var wrap = img.closest("div");
      if (!wrap) return;
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
