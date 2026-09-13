#!/usr/bin/env node
import {
  wapitiArgs, wapitiFindings,
  arjunArgs, extractArjunParams, arjunFindings,
  dalfoxArgs, dalfoxFindings,
} from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- wapiti ---------------------------- */

const wapitiArgList = wapitiArgs("http://demo.testfire.net/");
check("wapiti: incluye -u con target", wapitiArgList.includes("http://demo.testfire.net/"));
check("wapiti: salida json a stdout", wapitiArgList.includes("-f") && wapitiArgList.includes("json") && wapitiArgList.includes("/dev/stdout"));
check("wapiti: -v 0 (stdout limpio de banner)", wapitiArgList.includes("-v") && wapitiArgList.includes("0"));
check("wapiti: acota con --max-scan-time", wapitiArgList.includes("--max-scan-time"));

// Fixture real: captura contra demo.testfire.net/search.jsp (reflected XSS
// confirmado, level=2). classifications trae la solución por categoría.
const wapitiStdout = JSON.stringify({
  classifications: {
    "Reflected Cross Site Scripting": {
      desc: "XSS reflejado",
      sol: "Escapar/validar toda entrada reflejada en la respuesta.",
      ref: {},
      wstg: ["WSTG-INPV-01"],
    },
    "SQL Injection": { desc: "SQLi", sol: "Usar consultas parametrizadas.", ref: {}, wstg: [] },
  },
  vulnerabilities: {
    "Reflected Cross Site Scripting": [
      {
        method: "GET",
        path: "/search.jsp",
        info: "Reflected Cross Site Scripting vulnerability found via injection in the parameter query",
        level: 2,
        parameter: "query",
        module: "xss",
        curl_command: "curl \"http://demo.testfire.net/search.jsp?query=%3CScRiPt%3E\"",
        wstg: ["WSTG-INPV-01"],
      },
    ],
    "SQL Injection": [],
  },
  anomalies: {},
  additionals: {},
  infos: { target: "http://demo.testfire.net/", crawled_pages_nbr: 1 },
});

const wFindings = wapitiFindings(wapitiStdout, "http://demo.testfire.net/");
check("wapiti: 1 finding consolidado por categoría con hallazgos", wFindings.length === 1);
check("wapiti: severity level=2 -> Medium", wFindings[0]?.severity === "Medium");
check("wapiti: título menciona la categoría", wFindings[0]?.title.includes("Reflected Cross Site Scripting"));
check("wapiti: descripción incluye el parámetro afectado", wFindings[0]?.description.includes("query"));
check("wapiti: remediation viene de classifications.sol", wFindings[0]?.remediation.includes("Escapar/validar"));

check("wapiti: sin vulnerabilidades -> cero findings", wapitiFindings(JSON.stringify({
  classifications: {}, vulnerabilities: { "SQL Injection": [] }, anomalies: {}, additionals: {}, infos: {},
}), "http://x.com").length === 0);

check("wapiti: JSON inválido -> cero findings (no crashea)", wapitiFindings("not json", "http://x.com").length === 0);
check("wapiti: stdout vacío -> cero findings", wapitiFindings("", "http://x.com").length === 0);

/* ---------------------------- arjun ---------------------------- */

const arjunArgList = arjunArgs("http://demo.testfire.net/search.jsp");
check("arjun: incluye -u con target", arjunArgList.includes("http://demo.testfire.net/search.jsp"));
check("arjun: modo GET", arjunArgList.includes("-m") && arjunArgList.includes("GET"));
check("arjun: json a stdout", arjunArgList.includes("-oJ") && arjunArgList.includes("/dev/stdout"));
check("arjun: modo silencioso", arjunArgList.includes("-q"));
check("arjun: usa wordlist small (rapidez, evita 25889 palabras de large.txt)", arjunArgList.some((a) => String(a).includes("small.txt")));

// Fixture real capturada: arjun -oJ /dev/stdout contra /search.jsp (sort_keys=True, indent=4)
const arjunStdout = `{
    "http://demo.testfire.net/search.jsp": {
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0"
        },
        "method": "GET",
        "params": [
            "query"
        ]
    }
}`;

const arjunParams = extractArjunParams(arjunStdout);
check("arjun: extrae 1 URL con params", arjunParams.length === 1);
check("arjun: extrae el param correcto", arjunParams[0]?.params.includes("query"));
check("arjun: extrae la URL correcta", arjunParams[0]?.url === "http://demo.testfire.net/search.jsp");

check("arjun: stdout vacío (sin params descubiertos) -> array vacío", extractArjunParams("").length === 0);

// rawBlob mezclado con salida de otros steps (nmap, curl HTML) no debe confundir el parser
const mixedBlob = [
  "PORT   STATE SERVICE\n80/tcp open  http",
  "<html><script>var x = {foo: 1};</script></html>",
  arjunStdout,
].join("\n");
const arjunParamsMixed = extractArjunParams(mixedBlob);
check("arjun: extrae bien aunque el blob tenga output de otros steps mezclado", arjunParamsMixed.length === 1 && arjunParamsMixed[0].params.includes("query"));

const arjunFindingsList = arjunFindings(arjunStdout, "http://demo.testfire.net/");
check("arjun: 1 finding Info consolidado", arjunFindingsList.length === 1 && arjunFindingsList[0].severity === "Info");
check("arjun: el finding menciona el param descubierto", arjunFindingsList[0].description.includes("query"));
check("arjun: sin params -> cero findings", arjunFindings("", "http://x.com").length === 0);

/* ---------------------------- dalfox ---------------------------- */

const dalfoxArgList = dalfoxArgs("http://demo.testfire.net/search.jsp", ["query"]);
check("dalfox: subcomando url", dalfoxArgList[0] === "url");
check("dalfox: incluye target", dalfoxArgList.includes("http://demo.testfire.net/search.jsp"));
check("dalfox: pasa el param descubierto por arjun", dalfoxArgList.includes("-p") && dalfoxArgList.includes("query"));
check("dalfox: salida jsonl silenciosa", dalfoxArgList.includes("--format") && dalfoxArgList.includes("jsonl") && dalfoxArgList.includes("-S"));

// Fixture real capturada contra demo.testfire.net/search.jsp?query= (XSS reflejado confirmado)
const dalfoxStdout = [
  JSON.stringify({
    type: "V", inject_type: "inHTML", method: "GET",
    data: "http://demo.testfire.net/search.jsp?query=%22%3E%3CIMG+SRC%3Dx%3E",
    param: "query",
    payload: "\"><IMG SRC=x oninvalid=\"alert(1)\">",
    cwe: "CWE-79", severity: "High",
    message_str: "Triggered XSS Payload (found DOM Object)",
  }),
  JSON.stringify({
    type: "R", inject_type: "inHTML", method: "GET",
    data: "http://demo.testfire.net/search.jsp?query=%3Eembed",
    param: "query", payload: "><embed src=# codebase=javascript:alert(1)>",
    cwe: "CWE-79", severity: "Medium",
    message_str: "Reflected Payload in HTML",
  }),
].join("\n");

const dalfoxFindingsList = dalfoxFindings(dalfoxStdout, "http://demo.testfire.net/search.jsp");
check("dalfox: 1 finding por hallazgo confirmado/reflejado", dalfoxFindingsList.length === 2);
check("dalfox: severity tomada del propio dalfox", dalfoxFindingsList.some((f) => f.severity === "High") && dalfoxFindingsList.some((f) => f.severity === "Medium"));
check("dalfox: descripción incluye el param vulnerable", dalfoxFindingsList[0].description.includes("query"));
check("dalfox: descripción incluye el payload/PoC", dalfoxFindingsList[0].description.includes("IMG SRC") || dalfoxFindingsList[0].description.includes("embed"));

check("dalfox: sin hallazgos -> cero findings", dalfoxFindings("", "http://x.com").length === 0);
check("dalfox: líneas no-JSON (logs de progreso) no crashean el parser", dalfoxFindings("[*] Scanning...\n[I] Content-Type", "http://x.com").length === 0);

/* ------------------------- wiring Fase 2 ------------------------- */

const ctxNormal = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsFase2 = stepsForPhase(2, "https://x.com", ctxNormal);

const wapitiStep = stepsFase2.find((s) => s.id === "p2-wapiti");
check("Fase 2 incluye el step p2-wapiti", !!wapitiStep);
check("p2-wapiti apunta al baseUrl correcto", wapitiStep?.args.includes("https://x.com"));

const arjunStep = stepsFase2.find((s) => s.id === "p2-arjun");
check("Fase 2 incluye el step p2-arjun", !!arjunStep);

// dalfox depende de que arjun haya descubierto params en ctx — sin eso, no corre
const ctxSinParams = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsSinParams = stepsForPhase(2, "https://x.com", ctxSinParams);
const dalfoxStepSinParams = stepsSinParams.find((s) => s.id === "p2-dalfox-1");
check("p2-dalfox-1 se salta si arjun no descubrió params", !dalfoxStepSinParams || dalfoxStepSinParams.skipIf?.(ctxSinParams));

const ctxConParams = buildPlaybookContext([], {
  host: "x.com", scope: "https://x.com",
  arjunParams: [{ url: "https://x.com/search", params: ["q"] }],
});
const stepsConParams = stepsForPhase(2, "https://x.com", ctxConParams);
const dalfoxStepConParams = stepsConParams.find((s) => s.id === "p2-dalfox-1");
check("p2-dalfox-1 corre cuando arjun sí descubrió params", !!dalfoxStepConParams && !dalfoxStepConParams.skipIf?.(ctxConParams));
const dalfoxResolvedArgs = typeof dalfoxStepConParams?.args === "function"
  ? dalfoxStepConParams.args(ctxConParams)
  : dalfoxStepConParams?.args;
check("p2-dalfox-1 usa la URL y param descubiertos por arjun", dalfoxResolvedArgs?.includes("https://x.com/search") && dalfoxResolvedArgs?.includes("q"));

const ctxDvwa = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", isDvwa: true });
const stepsFase2Dvwa = stepsForPhase(2, "https://x.com", ctxDvwa);
const wapitiStepDvwa = stepsFase2Dvwa.find((s) => s.id === "p2-wapiti");
check("p2-wapiti se salta en DVWA (skipHeavy)", !wapitiStepDvwa || wapitiStepDvwa.skipIf?.(ctxDvwa));
const arjunStepDvwa = stepsFase2Dvwa.find((s) => s.id === "p2-arjun");
check("p2-arjun se salta en DVWA (skipHeavy)", !arjunStepDvwa || arjunStepDvwa.skipIf?.(ctxDvwa));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
