#!/usr/bin/env node
/**
 * Fase 3: SSTI (Server-Side Template Injection). Mismo patrón que la sonda
 * de XSS reflejado genérico (marcador único + curl -G por parámetro), pero
 * en vez de buscar el payload SIN escapar, busca que el motor de plantillas
 * lo haya EVALUADO: {{7*7}}, ${7*7}, <%= 7*7 %>, @(7*7), #{7*7} cubren
 * Jinja2/Twig/Nunjucks, Freemarker/Thymeleaf/JSP EL, ERB/JSP scriptlet,
 * Razor y Pug respectivamente — los 5 envueltos en el mismo marcador único
 * para que "MARCADOR + 49 + MARCADOR" sea imposible de confundir con
 * contenido real de la página (a diferencia de buscar "49" a secas).
 */
import { SSTI_MARKER, SSTI_PAYLOAD, SSTI_PARAMS, sstiReflectionCurlSteps, sstiEvaluated } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- payload / marcador ---------------------------- */

check("el marcador es único (no una palabra genérica)", SSTI_MARKER.length >= 8);
check("el payload incluye sintaxis Jinja2/Twig ({{7*7}})", SSTI_PAYLOAD.includes("{{7*7}}"));
check("el payload incluye sintaxis Freemarker/EL (${7*7})", SSTI_PAYLOAD.includes("${7*7}"));
check("el payload incluye sintaxis ERB (<%= 7*7 %>)", SSTI_PAYLOAD.includes("<%= 7*7 %>"));
check("el payload incluye sintaxis Razor (@(7*7))", SSTI_PAYLOAD.includes("@(7*7)"));
check("el payload incluye sintaxis Pug (#{7*7})", SSTI_PAYLOAD.includes("#{7*7}"));
check("cada expresión queda envuelta por el marcador (evita falso positivo con '49' suelto)", SSTI_PAYLOAD.split(SSTI_MARKER).length - 1 >= 6);

/* ---------------------------- sstiEvaluated ---------------------------- */

// Ninguna evaluación: el payload vuelve literal (app no vulnerable, o ni
// siquiera lo refleja).
check("payload sin evaluar (reflejado literal) -> no detecta SSTI", !sstiEvaluated(`eco: ${SSTI_PAYLOAD}`));
check("sin reflejo en absoluto -> no detecta SSTI", !sstiEvaluated("<html><body>ok</body></html>"));

// Jinja2 evaluó su segmento: MARCADOR + 49 + MARCADOR aparece donde estaba {{7*7}}.
const jinjaEvaluated = `resultado: ${SSTI_MARKER}49${SSTI_MARKER}\${7*7}${SSTI_MARKER}<%= 7*7 %>${SSTI_MARKER}@(7*7)${SSTI_MARKER}#{7*7}${SSTI_MARKER}`;
check("Jinja2/Twig evaluó {{7*7}} -> 49 -> detecta SSTI", sstiEvaluated(jinjaEvaluated) === true);

// Motor tipo Freemarker/EL evaluó SU segmento (no el primero).
const elEvaluated = `${SSTI_MARKER}{{7*7}}${SSTI_MARKER}49${SSTI_MARKER}<%= 7*7 %>${SSTI_MARKER}@(7*7)${SSTI_MARKER}#{7*7}${SSTI_MARKER}`;
check("Freemarker/EL evaluó ${7*7} en cualquier posición -> detecta SSTI", sstiEvaluated(elEvaluated) === true);

// "49" suelto en la página SIN los marcadores alrededor -> NO debe disparar
// (evita falso positivo con un precio, una fecha, un contador real de la app).
check("'49' suelto sin marcador -> NO es SSTI (evita falso positivo)", !sstiEvaluated("Tienes 49 mensajes nuevos"));

/* ---------------------------- steps / wiring ---------------------------- */

const steps = sstiReflectionCurlSteps((id, tool, args) => ({ id, tool, args }), "p1-ssti", "https://x.com", "12");
check("genera 1 step por parámetro típico", steps.length === SSTI_PARAMS.length);
check("cada step manda el payload completo (todas las sintaxis a la vez)", steps.every((s) => s.args.some((a) => String(a).includes(SSTI_PAYLOAD))));
check("apunta a la raíz del target", steps.every((s) => s.args.some((a) => String(a) === "https://x.com/")));

const ctx = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: true });
const stepsFase1 = stepsForPhase(1, "https://x.com", ctx);
check("Fase 1 incluye los steps p1-ssti-*", SSTI_PARAMS.every((p) => stepsFase1.some((s) => s.id === `p1-ssti-${p}`)));

const ctxNoWeb = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: false });
const stepsFase1NoWeb = stepsForPhase(1, "https://x.com", ctxNoWeb);
const sstiStepNoWeb = stepsFase1NoWeb.find((s) => s.id === "p1-ssti-q");
check("se salta si no hay web stack (mismo criterio que xss/redirect/idor)", !!sstiStepNoWeb?.skipIf?.(ctxNoWeb));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
