#!/usr/bin/env node
/**
 * Fase 1 de mejoras post-wapiti/dalfox/arjun: arjun también alimenta a
 * sqlmap (SQLi sobre params GET ocultos), no solo a dalfox (XSS). Vive en
 * Fase 3 (Exploitation) — sqlmap es tool de explotación con gate humano de
 * fase, igual que p3-sqlmap-forms; el descubrimiento de params (Fase 2) se
 * arrastra vía ctx.arjunParams, que ya persiste entre fases.
 */
import { sqlmapArjunArgs, sqlmapFindings } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- sqlmapArjunArgs ---------------------------- */

const args = sqlmapArjunArgs("http://demo.testfire.net/search.jsp", ["query"]);
check("incluye -u con la URL + param como query string (?query=1)", args.includes("-u") && args.some((a) => /\/search\.jsp\?query=1$/.test(String(a))));
check("restringe con -p al param exacto (no explora otros)", args.includes("-p") && args.includes("query"));
check("--batch (no interactivo)", args.includes("--batch"));
check("nivel conservador (level=1 risk=1), mismo criterio que p3-sqlmap-forms", args.includes("--level=1") && args.includes("--risk=1"));

const argsMulti = sqlmapArjunArgs("http://x.com/api/items", ["id", "sort"]);
check("multi-param: query string con ambos", argsMulti.some((a) => /\?id=1&sort=1$/.test(String(a))));
check("multi-param: -p con ambos separados por coma", argsMulti.includes("id,sort"));

const argsExistingQuery = sqlmapArjunArgs("http://x.com/search?existing=1", ["q"]);
check("URL con query previa: concatena con &", argsExistingQuery.some((a) => /\?existing=1&q=1$/.test(String(a))));

/* sqlmapFindings ya es genérico (no depende de cómo se invocó sqlmap) —
 * solo confirmar que el output de esta invocación también se parsea. */
const sqlmapStdout = `
[10:00:00] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:00:01] [INFO] GET parameter 'query' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:
---
Parameter: query (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
---
`;
const findings = sqlmapFindings(sqlmapStdout);
check("sqlmapFindings ya parsea el output de la invocación encadenada", findings.length === 1 && findings[0].severity === "Critical");
check("el finding cita el param real descubierto por arjun", findings[0].title.includes("query"));

/* ------------------------- wiring Fase 3 ------------------------- */

const ctxSinParams = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsFase3SinParams = stepsForPhase(3, "https://x.com", ctxSinParams);
const sqlmapArjunStepSinParams = stepsFase3SinParams.find((s) => s.id === "p3-sqlmap-arjun-1");
check("p3-sqlmap-arjun-1 se salta si arjun no descubrió params", !sqlmapArjunStepSinParams || sqlmapArjunStepSinParams.skipIf?.(ctxSinParams));

const ctxConParams = buildPlaybookContext([], {
  host: "x.com", scope: "https://x.com", hasWebStack: true,
  arjunParams: [{ url: "https://x.com/search", params: ["q"] }],
});
const stepsFase3ConParams = stepsForPhase(3, "https://x.com", ctxConParams);
const sqlmapArjunStep = stepsFase3ConParams.find((s) => s.id === "p3-sqlmap-arjun-1");
check("p3-sqlmap-arjun-1 corre en Fase 3 cuando arjun descubrió params", !!sqlmapArjunStep && !sqlmapArjunStep.skipIf?.(ctxConParams));
check("p3-sqlmap-arjun-1 usa tool sqlmap (fase-gated, no bypassea el gate humano)", sqlmapArjunStep?.tool === "sqlmap");
const resolvedArgs = typeof sqlmapArjunStep?.args === "function" ? sqlmapArjunStep.args(ctxConParams) : sqlmapArjunStep?.args;
check("p3-sqlmap-arjun-1 usa la URL/param descubiertos por arjun", resolvedArgs?.some((a) => /\/search\?q=1$/.test(String(a))));

// NO debe aparecer en Fase 2 (ahí solo se descubre con arjun y se confirma
// XSS con dalfox; sqlmap es explotación, requiere avance de fase explícito).
const stepsFase2ConParams = stepsForPhase(2, "https://x.com", ctxConParams);
check("p3-sqlmap-arjun-1 NO aparece en Fase 2 (gate de fase respetado)", !stepsFase2ConParams.some((s) => s.id === "p3-sqlmap-arjun-1"));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
