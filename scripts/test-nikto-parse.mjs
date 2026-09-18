#!/usr/bin/env node
/** Parseo de salida real de Nikto → findings (no un Medium genérico). */
import { niktoFindings } from "../backend/js/vuln-kb.js";
import { readFileSync } from "node:fs";
import vm from "node:vm";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const sample = `
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        80
+ Start Time:         2026-09-06
---------------------------------------------------------------------------
+ Server: Apache/2.4.57
+ /: Retrieved x-powered-by header: PHP/8.1.2.
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3092: /admin/: This might be interesting...
+ /icons/: Directory indexing found.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ CVE-2017-7679: /cgi-bin/: Apache mod_mime buffer overflow.
+ [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
+ 12 item(s) reported on remote host
`;

const hits = niktoFindings(sample);
check("no inventa hallazgo por cabeceras ya cubiertas (XFO/XCTO)", !hits.some((f) => /X-Frame|X-Content-Type/i.test(f.title)));
check("no inventa hallazgo por x-powered-by / Server", !hits.some((f) => /x-powered-by|Apache\/2/i.test(f.title)));
check("ignora referrer-policy + URL MDN (no path //developer…)", !hits.some((f) => /referrer-policy|mozilla\.org|\/\/developer/i.test(f.title + f.description)));
check("captura config.php como High", hits.some((f) => /config\.php/.test(f.title) && f.severity === "High"));
check("captura phpinfo como High", hits.some((f) => /phpinfo\(\)/.test(f.title) && /phpinfo\.php/.test(f.title) && f.severity === "High"));
check("captura directory indexing como Medium", hits.some((f) => /icons/.test(f.title) && /listado de directorio/i.test(f.title) && f.severity === "Medium"));
check("captura CVE en título/desc y High", hits.some((f) => /CVE-2017-7679/.test(f.title + f.description) && f.severity === "High"));
check("captura OSVDB-3092 /admin/", hits.some((f) => /\/admin\//.test(f.title)));
check("títulos cortos (sin prosa EN de Nikto)", hits.every((f) => f.title.length <= 72 && !/This might be interesting|may contain database|Suggested security/i.test(f.title)));
check("título config en ES", hits.some((f) => f.title === "Nikto: configuración expuesta en /config.php"));
check("título CVE corto", hits.some((f) => f.title === "Nikto: CVE-2017-7679 en /cgi-bin/"));
check("descripción conserva la línea cruda", hits.some((f) => /PHP Config file may contain/.test(f.description)));
check("tope razonable (≤8)", hits.length <= 8 && hits.length >= 4);
check("sin salida -> []", niktoFindings("").length === 0);
check("solo ruido de cabecera -> []", niktoFindings("+ The X-Frame-Options header is not present.\n").length === 0);
check("solo referrer-policy Suggested -> []", niktoFindings("+ [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy\n").length === 0);

// Secreto real filtrado (caso visto en auditoría real de cliente): Nikto reporta
// esto como check de "superficie" genérico -> Low, escondiendo que hay una
// clave de API en texto plano. Debe reclasificar a severidad alta con
// título específico, reusando el catálogo JS_SECRET_SIGNATURES.
const leakedKeySample = `+ [750534] /webcgi/: Google API keys may now be used for Gemini API access. The key is: "AIzaSyDe0LldBAVmT9ZzViJBZa0XQvR_iYEyA-0" . See: https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules\n`;
const leakedKeyHits = niktoFindings(leakedKeySample);
check("clave de Google API filtrada -> severidad High (no Low genérico)", leakedKeyHits.some((f) => f.severity === "High"));
check("clave de Google API filtrada -> título menciona la clave, no 'superficie'", leakedKeyHits.some((f) => /Google API Key/i.test(f.title) && !/superficie/i.test(f.title)));
check("clave de Google API filtrada -> título incluye la ruta", leakedKeyHits.some((f) => /\/webcgi\//.test(f.title)));
check("clave de Google API filtrada -> remediation menciona rotar", leakedKeyHits.some((f) => /rotar/i.test(f.remediation)));

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const code = readFileSync(`${root}/panel/vendor/finding-dossier.js`, "utf8");
const sandbox = { window: {}, console, localStorage: { getItem: () => "es" } };
sandbox.window = sandbox;
sandbox.global = sandbox;
vm.runInNewContext(code.replace("(window);", "(this);"), sandbox);
const d = sandbox.DarkSpearDossier.enrich({
  title: hits[0].title,
  severity: hits[0].severity,
  description: hits[0].description,
  remediation: hits[0].remediation,
  asset: "http://127.0.0.1",
});
check("dossier Nikto no cae al genérico CWE-1035", !(d.cwe || []).includes("CWE-1035"));
check("dossier Nikto cita la ruta en el ejecutivo", /Nikto:|Ruta señalada/.test(d.exec));

process.exit(ok ? 0 : 1);
