#!/usr/bin/env node
/**
 * Cuando Print Spooler está activo Y hay una plantilla ADCS vulnerable a
 * ESC8 (web enrollment HTTP, sin protección de relay), correlaciona ambas
 * señales en un finding Critical con la cadena completa de comandos
 * (coerce -> relay -> certipy auth). Solo se emite si ambas condiciones
 * se cumplen; cada señal por separado sigue generando su propio finding
 * individual (ya cubierto por spoolerFindings/certipyFindFindings).
 */
import { coercionRelayEsc8Findings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const spoolerOn = "[+] Spooler service enabled";
const spoolerOff = "[-] Spooler service disabled";
const esc8Present = "Certificate Template: DomainController\n[!] Vulnerable to ESC8";
const esc8Absent = "No vulnerable templates found";

const both = coercionRelayEsc8Findings(spoolerOn, esc8Present);
check("spooler+ESC8 -> genera finding", both.length === 1);
check("severity Critical", both[0].severity === "Critical");
check("título menciona coerción y ESC8", /[Cc]oerci/.test(both[0].title) && /ESC8/.test(both[0].title));
check("incluye petitpotam.py", /petitpotam\.py/.test(both[0].description));
check("incluye ntlmrelayx.py con --adcs", /ntlmrelayx\.py/.test(both[0].description) && /--adcs/.test(both[0].description));
check("incluye certipy auth -pfx (paso final)", /certipy auth -pfx/.test(both[0].description));

check("solo spooler sin ESC8 -> []", coercionRelayEsc8Findings(spoolerOn, esc8Absent).length === 0);
check("solo ESC8 sin spooler -> []", coercionRelayEsc8Findings(spoolerOff, esc8Present).length === 0);
check("ninguno -> []", coercionRelayEsc8Findings(spoolerOff, esc8Absent).length === 0);
check("vacíos -> []", coercionRelayEsc8Findings("", "").length === 0);

if (!ok) process.exit(1);
console.log("\nOK coercion-relay-esc8: correlación Print Spooler + ESC8 -> cadena de ataque completa");
