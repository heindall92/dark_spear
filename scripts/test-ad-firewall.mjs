#!/usr/bin/env node
/**
 * Cortafuegos AD: a diferencia de ufw/iptables/nft (host local, lectura
 * directa de reglas), Windows Firewall en un DC remoto no tiene consulta
 * de solo-lectura vía RPC/LDAP — la única vía es ejecutar
 * `netsh advfirewall show allprofiles` remoto (netexec -x, wmiexec/
 * smbexec: crea un proceso real en el DC). Por eso vive en Fase 3
 * (Exploitation, gate humano ya existente), no en la collection AD de
 * Fase 1/2 (que es puramente RPC/LDAP/SMB sin ejecutar nada).
 */
import { adFirewallCheckSteps, adFirewallFindings } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- steps ---------------------------- */

function mockStep(id, tool, args, when, meta = {}) {
  const s = { id, tool, args, ...meta };
  if (when) s.when = when;
  return s;
}
const stepsNoCreds = adFirewallCheckSteps(mockStep, "dc01.corp.local");
check("sin creds: la función igual arma el step (skipIf decide en runtime)", stepsNoCreds.length === 1);

const resolveArgs = (s, ctx) => (typeof s.args === "function" ? s.args(ctx) : s.args);
const ctxCreds = { adUser: "auditor", adPassword: "P@ssw0rd", adDomain: "CORP.LOCAL", isAdTarget: true };
const argsWithCreds = resolveArgs(stepsNoCreds[0], ctxCreds);
check("con creds: manda -x con netsh advfirewall", argsWithCreds.includes("-x") && argsWithCreds.some((a) => String(a).includes("netsh advfirewall show allprofiles")));
check("con creds: pasa usuario/password/dominio", argsWithCreds.includes("-u") && argsWithCreds.includes("auditor") && argsWithCreds.includes("-d") && argsWithCreds.includes("CORP.LOCAL"));

check("sin creds: skipIf true (no ejecuta)", stepsNoCreds[0].skipIf?.({ isAdTarget: true }) === true);
check("con creds pero sin isAdTarget: skipIf true", stepsNoCreds[0].skipIf?.({ ...ctxCreds, isAdTarget: false }) === true);
check("con creds y AD target: skipIf false (ejecuta)", stepsNoCreds[0].skipIf?.(ctxCreds) === false);

/* ---------------------------- adFirewallFindings ---------------------------- */

// Los 3 perfiles activos (buena postura) -> sin finding de exposición, la
// función igual confirma que se pudo leer el estado real (no oculta que
// corrió: eso ya es collection útil aunque no haya vulnerabilidad).
const allOn = `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
`;
const allOnFindings = adFirewallFindings(allOn, "dc01.corp.local");
check("los 3 perfiles ON -> cero findings de exposición", !allOnFindings.some((f) => /desactivad/i.test(f.title)));

// Perfil de dominio DESACTIVADO en un DC -> severidad alta (el perfil que
// más importa: es el que aplica a tráfico intra-dominio).
const domainOff = `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
`;
const domainOffFindings = adFirewallFindings(domainOff, "dc01.corp.local");
check("perfil Domain OFF -> 1 finding High", domainOffFindings.length === 1 && domainOffFindings[0].severity === "High");
check("título menciona el perfil Domain y el host", /domain/i.test(domainOffFindings[0].title) && /dc01\.corp\.local/.test(domainOffFindings[0].title));

// Perfil Public desactivado (menos crítico que Domain en un DC) -> Medium.
const publicOff = `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
`;
const publicOffFindings = adFirewallFindings(publicOff, "dc01.corp.local");
check("perfil Public OFF -> Medium (menos crítico que Domain)", publicOffFindings.length === 1 && publicOffFindings[0].severity === "Medium");

// Varios perfiles OFF a la vez -> un finding por perfil.
const bothOff = `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
`;
check("Domain + Public OFF -> 2 findings distintos", adFirewallFindings(bothOff, "dc01.corp.local").length === 2);

check("stdout vacío -> cero findings (no crashea)", adFirewallFindings("", "dc01.corp.local").length === 0);
check("salida sin formato netsh reconocible -> cero findings", adFirewallFindings("Access is denied", "dc01.corp.local").length === 0);

/* ------------------------- wiring Fase 3 ------------------------- */

const ctxSinCreds = buildPlaybookContext([], { host: "dc01.corp.local", scope: "dc01.corp.local", isAdTarget: true });
const stepsFase3SinCreds = stepsForPhase(3, "dc01.corp.local", ctxSinCreds);
const fwStep = stepsFase3SinCreds.find((s) => s.id === "p3-ad-firewall");
check("Fase 3 incluye p3-ad-firewall", !!fwStep);
check("sin creds AD: se salta", !!fwStep?.skipIf?.(ctxSinCreds));

const ctxConCreds = buildPlaybookContext([], {
  host: "dc01.corp.local", scope: "dc01.corp.local", isAdTarget: true,
  adUser: "auditor", adPassword: "P@ssw0rd", adDomain: "CORP.LOCAL",
});
const stepsFase3ConCreds = stepsForPhase(3, "dc01.corp.local", ctxConCreds);
const fwStepConCreds = stepsFase3ConCreds.find((s) => s.id === "p3-ad-firewall");
check("con creds AD: corre en Fase 3", !!fwStepConCreds && !fwStepConCreds.skipIf?.(ctxConCreds));
check("tool es netexec (mismo mecanismo que el resto de exec AD)", fwStepConCreds?.tool === "netexec");

const ctxNoAd = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsFase3NoAd = stepsForPhase(3, "https://x.com", ctxNoAd);
check("target no-AD: no aparece o se salta", !stepsFase3NoAd.some((s) => s.id === "p3-ad-firewall" && !s.skipIf?.(ctxNoAd)));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
