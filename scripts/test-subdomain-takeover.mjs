#!/usr/bin/env node
/**
 * Fase 2: subdomain takeover automation. httpx ya corre sobre los
 * subdominios de subfinder (Fase 1 OSINT) — agregar -cname es casi gratis
 * y permite detectar CNAMEs colgantes hacia proveedores conocidos
 * (GitHub Pages, Heroku, S3, Azure, Shopify...) sin tooling nuevo.
 */
import { httpxArgsForHosts, subdomainTakeoverFindings } from "../backend/js/vuln-kb.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- httpxArgsForHosts ---------------------------- */

const args = httpxArgsForHosts(["a.example.com"]);
check("httpxArgsForHosts ahora pide -cname (necesario para takeover)", args.includes("-cname"));

/* ---------------------------- subdomainTakeoverFindings ---------------------------- */

// Fixture real: dig/httpx -cname contra un host sano (github.com resuelve
// bien, no es takeover aunque el cname apunte a un dominio de la lista).
const healthyGithub = JSON.stringify({
  url: "https://www.github.com", input: "www.github.com", host: "www.github.com",
  cname: ["github.com"], status_code: 200, failed: false, host_ip: "140.82.121.4",
});
check("CNAME sano (200, resuelve) -> no es takeover", subdomainTakeoverFindings(healthyGithub).length === 0);

// CNAME hacia GitHub Pages que ya no resuelve (failed) — candidato real.
const danglingGhPages = JSON.stringify({
  url: "https://blog.acme-corp.com", input: "blog.acme-corp.com", host: "blog.acme-corp.com",
  cname: ["acme-corp.github.io"], status_code: 0, failed: true,
});
const ghFindings = subdomainTakeoverFindings(danglingGhPages);
check("CNAME colgante a GitHub Pages -> 1 finding", ghFindings.length === 1);
check("severidad Medium (candidato, requiere confirmación manual)", ghFindings[0]?.severity === "Medium");
check("título menciona el host y el servicio", /blog\.acme-corp\.com/.test(ghFindings[0]?.title) && /GitHub Pages/i.test(ghFindings[0]?.title));
check("remediation pide reclamar o borrar el CNAME", /reclamar|eliminar/i.test(ghFindings[0]?.remediation));

// CNAME hacia S3 con 404 (bucket no existe) — otro patrón dangling.
const danglingS3 = JSON.stringify({
  url: "https://assets.acme-corp.com", input: "assets.acme-corp.com", host: "assets.acme-corp.com",
  cname: ["acme-assets.s3-website-us-east-1.amazonaws.com"], status_code: 404, failed: false, host_ip: "3.5.1.1",
});
const s3Findings = subdomainTakeoverFindings(danglingS3);
check("CNAME hacia S3 con 404 -> 1 finding", s3Findings.length === 1);
check("servicio identificado como AWS S3", /S3/i.test(s3Findings[0]?.title));

// CNAME hacia Heroku pero respondiendo 200 sano -> NO es takeover.
const healthyHeroku = JSON.stringify({
  url: "https://app.acme-corp.com", input: "app.acme-corp.com", host: "app.acme-corp.com",
  cname: ["acme-corp.herokuapp.com"], status_code: 200, failed: false, host_ip: "54.1.2.3",
});
check("CNAME a Heroku pero sano (200) -> no es takeover", subdomainTakeoverFindings(healthyHeroku).length === 0);

// Sin CNAME -> nada que evaluar.
const noCname = JSON.stringify({ url: "https://x.acme-corp.com", host: "x.acme-corp.com", status_code: 200, failed: false });
check("sin CNAME -> cero findings", subdomainTakeoverFindings(noCname).length === 0);

// CNAME hacia proveedor NO catalogado (dominio propio de otro cliente) -> no dispara.
const unknownProvider = JSON.stringify({
  url: "https://x.acme-corp.com", host: "x.acme-corp.com",
  cname: ["backend.some-other-company.com"], status_code: 0, failed: true,
});
check("CNAME colgante hacia proveedor no catalogado -> no dispara (evita ruido)", subdomainTakeoverFindings(unknownProvider).length === 0);

// Múltiples líneas: dedupe por host, cap razonable.
const multiLine = [danglingGhPages, danglingS3, danglingGhPages].join("\n");
const multiFindings = subdomainTakeoverFindings(multiLine);
check("dedupe: mismo host repetido -> no duplica", multiFindings.length === 2);

check("stdout vacío -> cero findings", subdomainTakeoverFindings("").length === 0);
check("JSON inválido por línea -> no crashea", subdomainTakeoverFindings("no es json\n{ tampoco").length === 0);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
