#!/usr/bin/env node
/** Informe integral estilo Genexys: KPIs, leyenda, patrones, ficha 1 columna, PASS. */
import { readFileSync } from "node:fs";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
let fail = 0;
function check(cond, msg) {
  if (!cond) {
    fail += 1;
    console.error("FAIL", msg);
  } else {
    console.log("ok ", msg);
  }
}

const findings = [
  {
    id: "F-001",
    title: "Endpoint de tenant expone Cognito User Pool ID y Client ID sin autenticación",
    severity: "critical",
    asset: "https://api.lab.test/tenant-config",
    description: "GET /api/tenants/public/tenant-config devuelve userPoolId y clientId. Rate limiting ausente en login.",
    remediation: "Proteger el endpoint y quitar userPoolId del bundle.",
    status: "accepted",
  },
  {
    id: "F-013",
    title: "Dominio lab.test sin registro SPF",
    severity: "medium",
    asset: "https://lab.test",
    description: "No hay TXT con v=spf1. DMARC ausente. Suplantación de email del dominio posible.",
    remediation: "Publicar SPF con -all y DMARC p=quarantine.",
    status: "accepted",
  },
  {
    id: "F-020",
    title: "WAF activo: Cloudflare delante del host",
    severity: "info",
    asset: "https://lab.test",
    description: "No es vulnerabilidad: documenta que hay un filtro delante del host.",
    remediation: "Mantener el WAF y revisar reglas tras cada despliegue.",
    status: "accepted",
  },
];

function runChromiumDump(url) {
  return new Promise((resolve) => {
    const proc = spawn("chromium", [
      "--headless", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=8000",
      "--dump-dom", url,
    ], { timeout: 25000 });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => { stdout += d; });
    proc.stderr.on("data", (d) => { stderr += d; });
    proc.on("close", (code) => resolve({ status: code, stdout, stderr }));
    proc.on("error", (err) => resolve({ status: 1, stdout, stderr: String(err) }));
  });
}

const live = readFileSync(`${root}/panel/vendor/panel-live.js`, "utf8");
check(live.includes("function htmlKpiTiles"), "htmlKpiTiles");
check(live.includes("function htmlGlossary"), "htmlGlossary");
check(live.includes("SYSTEMIC_PATTERNS"), "SYSTEMIC_PATTERNS");
check(live.includes("function htmlCvssCompactLine"), "htmlCvssCompactLine");
check(live.includes("rpt-impact"), "caja impacto");
check(live.includes("rpt-fix"), "caja remediación");
check(!live.includes("function htmlReportCvssPanel"), "sin widget CVSS de dos columnas");
check(live.includes("htmlFindingsInventory(all)"), "preview usa inventario KPI+tabla");
check(live.includes("function htmlMethodologyAppendix"), "htmlMethodologyAppendix");
check(live.includes("function htmlRgpdFindingCard"), "htmlRgpdFindingCard");
check(live.includes("function htmlComplianceRisk"), "htmlComplianceRisk");
check(live.includes("htmlMethodologyAppendix(all"), "render cablea §07");
check(live.includes("function htmlGdprDashboard"), "htmlGdprDashboard");
check(live.includes("htmlGdprDashboard(findings"), "08c usa el tablero RGPD");
check(live.includes("rpt-heat-cell"), "heatmap con celdas propias");
check(!/G-00[1-9]/.test(live), "sin IDs G- inventados");

const hasChromium = spawnSync("which", ["chromium"], { encoding: "utf8" }).status === 0;
if (!hasChromium) {
  console.log("skip chromium e2e (binario no encontrado)");
  if (fail) process.exit(1);
  process.exit(0);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const json = (obj) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === "/session") return json({ token: "t" });
  if (url.pathname === "/status") return json({ active: false, target: "https://lab.test" });
  if (url.pathname === "/engagements/list") {
    return json({
      engagements: [{
        id: "eng-demo",
        engagement_dir: "eng-demo",
        name: "Lab",
        target: "https://lab.test",
        scope: "web",
        status: "done",
        findings_count: findings.length,
        active: false,
      }],
    });
  }
  if (url.pathname === "/engagements/findings") return json({ findings });
  if (url.pathname === "/findings/list") return json({ findings });
  if (url.pathname === "/boot.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(
      "<!doctype html><meta charset=utf-8><script>" +
      "sessionStorage.setItem('ds-engine-url', location.origin);" +
      "sessionStorage.setItem('ds-engine-token','t');" +
      "location.replace('comprehensive-report.html?scan=eng-demo');" +
      "</script>"
    );
    return;
  }
  let file = url.pathname === "/" ? "/comprehensive-report.html" : url.pathname;
  if (file.includes("..")) {
    res.writeHead(400);
    res.end();
    return;
  }
  try {
    const path = `${root}/panel${file}`;
    const body = readFileSync(path);
    const type = file.endsWith(".js") ? "text/javascript"
      : file.endsWith(".css") ? "text/css"
      : file.endsWith(".png") ? "image/png"
      : "text/html";
    res.writeHead(200, { "content-type": type });
    res.end(body);
  } catch (e) {
    res.writeHead(404);
    res.end();
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
try {
  const dump = await runChromiumDump(`http://127.0.0.1:${port}/boot.html`);
  const dom = dump.stdout || "";
  check(dump.status === 0, "chromium dump exit 0");
  check(dom.includes("rpt-kpi-row") || /rpt-kpi/.test(dom), "KPIs en DOM");
  check(/F-001/.test(dom) && /F-013/.test(dom), "tabla de hallazgos con IDs");
  check(/Leyenda de categorías y términos|Cognito/.test(dom), "leyenda/glosario");
  check(/Patrón dominante|patrones sistémicos|SYSTEMIC/.test(dom) || /Ausencia transversal|Autenticación de correo|Secretos y configuración/.test(dom), "capítulo de patrones");
  check(/rpt-term/.test(dom) && /Qué es/.test(dom), "ficha con evidencia terminal y qué es");
  check(/rpt-impact/.test(dom) && /rpt-fix/.test(dom), "cajas impacto y remediación");
  check(/rpt-pass/.test(dom) && /WAF activo/.test(dom), "tarjeta PASS de control observado");
  check(!/rpt-finding-grid/.test(dom), "sin grid de dos columnas en la ficha");
  check(/rpt-meth/.test(dom) && /F-001/.test(dom) && /F-013/.test(dom), "§07 metodología con IDs reales");
  check(/rpt-gov-card/.test(dom) && /F-001/.test(dom), "08a ficha RGPD con F-xxx");
  check(!/G-00[1-9]/.test(dom), "DOM sin IDs G- inventados");
  check(/rpt-gov-table/.test(dom), "08b/08d tabla de cumplimiento o impacto");
  check(/rpt-gdpr-dash/.test(dom) && /rpt-heat-cell/.test(dom), "08c tablero RGPD + heatmap");
  check(/rpt-impact-cols/.test(dom), "08d columnas impacto / acciones");
  check(/rpt-kc-step/.test(dom) || /rpt-kc-kpis/.test(dom), "08f kill chain con etapas o KPI");
} finally {
  server.close();
}

if (fail) {
  console.error("\n" + fail + " fallos");
  process.exit(1);
}
console.log("\nOK layout Genexys del informe integral");
