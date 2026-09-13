#!/usr/bin/env node
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

// Sin webLoginUrl: cero steps de login, comportamiento actual intacto.
const ctxSinLogin = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsSinLogin = stepsForPhase(1, "https://x.com", ctxSinLogin);
check(
  "sin webLoginUrl: no hay steps p1-webauth-*",
  !stepsSinLogin.some((s) => s.id.startsWith("p1-webauth-")),
);

// Con webLoginUrl: los 2 steps de login aparecen al inicio de Fase 1.
const ctxConLogin = buildPlaybookContext([], {
  host: "x.com",
  scope: "https://x.com",
  webLoginUrl: "https://x.com/login",
  webUser: "u@x.com",
  webPassword: "pass",
});
check("ctx propaga webLoginUrl", ctxConLogin.webLoginUrl === "https://x.com/login");
const stepsConLogin = stepsForPhase(1, "https://x.com", ctxConLogin);
check(
  "con webLoginUrl: aparecen p1-webauth-get y p1-webauth-post",
  stepsConLogin.some((s) => s.id === "p1-webauth-get") && stepsConLogin.some((s) => s.id === "p1-webauth-post"),
);
check(
  "los steps de login van ANTES que el resto de Fase 1",
  stepsConLogin.findIndex((s) => s.id === "p1-webauth-get") < stepsConLogin.findIndex((s) => s.id === "p1-nmap-sV"),
);

// discoveredForms: extraído del blob acumulado (mismo patrón que bruteDiscovered).
const htmlConForm = '<form action="/comment" method="POST"><textarea name="body"></textarea></form>';
const ctxConForm = buildPlaybookContext([htmlConForm], { host: "x.com", scope: "https://x.com" });
check("discoveredForms detecta el form del blob", ctxConForm.discoveredForms.length === 1);
check("discoveredForms conserva el action", ctxConForm.discoveredForms[0].action === "/comment");

// Fase 2 genera steps de XSS/SQLi por cada form descubierto.
const stepsFase2 = stepsForPhase(2, "https://x.com", ctxConForm);
check(
  "Fase 2 incluye sondas XSS contra el form descubierto",
  stepsFase2.some((s) => s.id.startsWith("p2-formxss-")),
);
check(
  "Fase 2 incluye sondas SQLi contra el form descubierto",
  stepsFase2.some((s) => s.id.startsWith("p2-formsqli-")),
);

// Sin forms descubiertos: cero steps de sondas de form en Fase 2.
const ctxSinForm = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsFase2SinForm = stepsForPhase(2, "https://x.com", ctxSinForm);
check(
  "sin forms descubiertos: no hay steps p2-formxss-/p2-formsqli-",
  !stepsFase2SinForm.some((s) => s.id.startsWith("p2-formxss-") || s.id.startsWith("p2-formsqli-")),
);

// Cap de formularios: muchos forms descubiertos (ej. app con 20 páginas
// distintas visitadas) no deben explotar el conteo de pasos de Fase 2 —
// mismo criterio que hydraAdUserSteps (tope 3 usuarios).
const manyForms = Array.from({ length: 20 }, (_, i) => ({
  action: `/form-${i}`,
  method: "POST",
  fields: [{ name: "x", type: "text" }],
}));
const ctxManyForms = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", discoveredForms: manyForms });
const stepsFase2Many = stepsForPhase(2, "https://x.com", ctxManyForms);
const formStepCount = stepsFase2Many.filter((s) => s.id.startsWith("p2-formxss-") || s.id.startsWith("p2-formsqli-")).length;
check(
  "cap de formularios: 20 forms descubiertos generan steps acotados (<=10, no 40)",
  formStepCount <= 10,
);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
