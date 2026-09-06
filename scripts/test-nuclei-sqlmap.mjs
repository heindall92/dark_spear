#!/usr/bin/env node
/**
 * Verifica nucleiFindings() y sqlmapFindings(): parseo de la salida real
 * de cada herramienta a findings del motor, con caso positivo y negativo.
 */
import { nucleiFindings, sqlmapFindings, nucleiTagsForContext } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

// --- nuclei ---
const nucleiJsonl = [
  JSON.stringify({
    "template-id": "CVE-2021-44228",
    info: { name: "Log4Shell RCE", severity: "critical", classification: { "cve-id": ["CVE-2021-44228"] } },
    host: "http://target.local", "matched-at": "http://target.local/api",
  }),
  JSON.stringify({
    "template-id": "exposed-panel",
    info: { name: "Admin panel exposed", severity: "low" },
    host: "http://target.local", "matched-at": "http://target.local/admin",
  }),
  "not-json-garbage-line",
  "",
].join("\n");

const nucleiHits = nucleiFindings(nucleiJsonl);
check("nuclei parsea 2 líneas JSON válidas, ignora la basura", nucleiHits.length === 2);
check("nuclei mapea severity critical", nucleiHits[0].severity === "Critical");
check("nuclei incluye el CVE en el título", nucleiHits[0].title.includes("CVE-2021-44228"));
check("nuclei mapea severity low", nucleiHits[1].severity === "Low");
check("nuclei sin líneas válidas -> []", nucleiFindings("garbage\nmore garbage").length === 0);

check("nucleiTagsForContext incluye exposure siempre", nucleiTagsForContext({}).includes("exposure"));
check("nucleiTagsForContext suma wordpress si aplica", nucleiTagsForContext({ isWordpress: true }).includes("wordpress"));

// --- sqlmap ---
const sqlmapVulnOutput = `
sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind
---
[INFO] the back-end DBMS is MySQL
`;
const sqlmapHits = sqlmapFindings(sqlmapVulnOutput);
check("sqlmap encuentra 2 parámetros distintos", sqlmapHits.length === 2);
check("sqlmap captura el nombre del primer parámetro", sqlmapHits[0].title.includes("«id»"));
check("sqlmap captura el nombre del segundo parámetro", sqlmapHits[1].title.includes("«username»"));

const sqlmapCleanOutput = "\n[INFO] testing connection to the target URL\n[INFO] target URL content is stable\nsqlmap is not vulnerable\nall tested parameters do not appear to be injectable\n";
check("sqlmap sin vulnerabilidad -> []", sqlmapFindings(sqlmapCleanOutput).length === 0);

process.exit(ok ? 0 : 1);
