#!/usr/bin/env node
/**
 * XXE (XML External Entity) genérico: mismo patrón que SSTI — un payload
 * curado se manda contra rutas típicas que aceptan XML (SOAP, APIs REST
 * que también aceptan application/xml, endpoints de importación), y se
 * confirma solo si la respuesta refleja el contenido real de /etc/passwd
 * (firma clásica "root:x:0:0:" — no adivinable, prueba lectura de fichero
 * local real, no un eco ciego del payload).
 */
import { xxeCurlSteps, xxeConfirmed, XXE_PATHS, XXE_PAYLOAD } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check("XXE_PAYLOAD declara un DOCTYPE con ENTITY externa", /<!ENTITY\s+xxe\s+SYSTEM/.test(XXE_PAYLOAD));
check("XXE_PAYLOAD referencia file:///etc/passwd", XXE_PAYLOAD.includes("file:///etc/passwd"));
check("XXE_PATHS no está vacío", Array.isArray(XXE_PATHS) && XXE_PATHS.length > 0);

const steps = xxeCurlSteps((id, tool, args, verify, opts) => ({ id, tool, args, opts }), "p1-xxe", "http://target.local", "12");
check("xxeCurlSteps genera un step por ruta curada", steps.length === XXE_PATHS.length);
check("xxeCurlSteps manda Content-Type application/xml", steps.every((s) => s.args.some((a) => /Content-Type:\s*application\/xml/i.test(a))));
check("xxeCurlSteps manda el payload como cuerpo POST", steps.every((s) => s.args.includes(XXE_PAYLOAD)));
check("xxeCurlSteps apunta cada ruta curada", steps.every((s, i) => s.args.some((a) => a === "http://target.local" + XXE_PATHS[i])));

check("xxeConfirmed detecta /etc/passwd reflejado (root:x:0:0:)",
  xxeConfirmed("HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"));
check("xxeConfirmed no dispara con XML sin evaluar (payload literal)",
  !xxeConfirmed("<foo>&xxe;</foo> parse error: entity not defined"));
check("xxeConfirmed no dispara con respuesta vacía", !xxeConfirmed(""));
check("xxeConfirmed no dispara con texto que solo menciona 'root' sin la firma completa",
  !xxeConfirmed("Usuario actual: root"));

const ctx = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: true });
const stepsFase1 = stepsForPhase(1, "https://x.com", ctx);
check("Fase 1 incluye los steps p1-xxe-*", XXE_PATHS.every((_, i) => stepsFase1.some((s) => s.id === `p1-xxe-${i + 1}`)));

const ctxNoWeb = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: false });
const stepsFase1NoWeb = stepsForPhase(1, "https://x.com", ctxNoWeb);
const xxeStepNoWeb = stepsFase1NoWeb.find((s) => s.id === "p1-xxe-1");
check("se salta si no hay web stack (mismo criterio que ssti/redirect/idor)", !!xxeStepNoWeb?.skipIf?.(ctxNoWeb));

if (!ok) process.exit(1);
console.log("\nOK xxe: sonda genérica de XML External Entity");
