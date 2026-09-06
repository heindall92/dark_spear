#!/usr/bin/env node
/**
 * Verifica codeDangerFinding(): confirma cada clase solo cuando la
 * respuesta real de la sonda trae la evidencia esperada, y no antes.
 */
import { codeDangerFinding } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const sqliHit = { kind: "sqli_concat", param: "code", cwe: "CWE-89", severity: "Critical" };
check(
  "sqli_concat confirma con error SQL en el cuerpo",
  codeDangerFinding("You have an error in your SQL syntax near...", sqliHit).length === 1,
);
check(
  "sqli_concat NO confirma sin error SQL (200 normal)",
  codeDangerFinding("<html>OK</html>", sqliHit).length === 0,
);

const lfiHit = { kind: "lfi_include", param: "url", cwe: "CWE-98", severity: "Critical" };
check(
  "lfi_include confirma con contenido real de /etc/passwd",
  codeDangerFinding("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1", lfiHit).length === 1,
);
check(
  "lfi_include NO confirma sin firma de /etc/passwd",
  codeDangerFinding("archivo no encontrado", lfiHit).length === 0,
);

const xssHit = { kind: "xss_unescaped_echo", param: "q", cwe: "CWE-79", severity: "High" };
check(
  "xss_unescaped_echo confirma con payload sin escapar en el cuerpo",
  codeDangerFinding("Resultados: <script>alert(1)</script>", xssHit).length === 1,
);
check(
  "xss_unescaped_echo NO confirma si el payload salió escapado",
  codeDangerFinding("Resultados: &lt;script&gt;alert(1)&lt;/script&gt;", xssHit).length === 0,
);

const authzHit = { kind: "authz_missing_middleware", route: "/admin/export", cwe: "CWE-862", severity: "High" };
check(
  "authz_missing_middleware confirma con HTTP 200 anónimo",
  codeDangerFinding("<html>panel</html>\nDS_HTTP:200\n", authzHit).length === 1,
);
check(
  "authz_missing_middleware NO confirma si redirige (302->login, DS_HTTP final distinto de 200)",
  codeDangerFinding("<html>login</html>\nDS_HTTP:401\n", authzHit).length === 0,
);

process.exit(ok ? 0 : 1);
