# dark_spear — Login Web + Descubrimiento de Formularios (Fase 1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** El operador completa URL de login + usuario + contraseña en el panel; el motor se loguea (Laravel con CSRF, o fallback genérico sin token), descubre formularios en el HTML ya recolectado por sondas de Fase 1/2, y prueba XSS reflejado + SQLi genérico contra cada campo de texto de cada form descubierto — todo con evidencia por-paso, nunca contra el blob acumulado.

**Architecture:** Dos módulos nuevos (`web-auth.js`, `form-discovery.js`) siguiendo el patrón ya establecido en el proyecto (funciones puras, sin estado, exportadas e importadas por `playbook.js`/`finding-heuristics.js`). El login se inserta como 2 steps al inicio de Fase 1 vía el mismo mecanismo de `ctx` dinámico que ya usa el playbook (`step(id, tool, args_fn, when, meta)` con `args` como función de `ctx`). Los formularios descubiertos se extraen dentro de `buildPlaybookContext` (mismo patrón que `bruteDiscovered`/`robotsDisallowed`) y se materializan como steps de Fase 2 vía un generador nuevo, análogo a como `DVWA_EXTRA_PROBES.map(...)` ya genera steps a partir de una lista.

**Tech Stack:** JavaScript ES modules (mismo runtime que el resto de `backend/js/`), tests con el patrón existente del proyecto (`scripts/test-*.mjs`, funciones `check(label, ok)`, sin framework de testing — node plano). Ejecución de red vía `curl` (binario ya whitelisted en `bridge.py`).

**Spec:** `/home/kali/dark_spear/docs/superpowers/specs/2026-09-12-web-login-and-form-discovery.md` (Fase 1 de 4)

## Global Constraints

- `web-login-url`/`web-user`/`web-password` son campos separados de `ad-domain`/`ad-user`/`ad-password` — nunca se mezclan ni se comparte lectura entre ambos pares.
- Si `web-login-url` está vacío, el comportamiento del motor es idéntico al actual (cero steps de login, cero descubrimiento de forms).
- Toda confirmación (login exitoso, form descubierto, XSS/SQLi confirmado) se evalúa contra la evidencia de SU PROPIO paso — nunca contra el blob acumulado de la sesión (regla reforzada en el fix de `finding-heuristics.js` del mismo día, commit `2a830b1`).
- CAPTCHA/2FA detectado → finding informativo, el motor no reintenta ni intenta bypasear nada.
- Después de cualquier cambio en `backend/js/`, correr `python3 scripts/sync-engine-js.py` antes de commitear.
- Nunca pasar pathspec a `git commit` en este repo (bug conocido, ver memoria `feedback_git_commit_pathspec_bug`) — stagear con `git add <archivos>` explícitos, commit bare.

---

## Task 1: `web-auth.js` — detección de CSRF/usuario + construcción de steps de login

**Files:**
- Create: `backend/js/web-auth.js`
- Test: `scripts/test-web-auth.mjs`

**Interfaces:**
- Produces: `detectCsrfToken(html: string): string | null`, `detectUserField(html: string): string`, `buildLoginSteps(step: Function, loginUrl: string, user: string, password: string, cookieFile: string): Array<StepSpec>` (donde `StepSpec` es el objeto que produce la función `step(id, tool, args, when, meta)` ya existente en `playbook.js`, pasada como parámetro para no duplicar su implementación).

- [ ] **Step 1: Escribir test que falla (`scripts/test-web-auth.mjs`)**

```js
#!/usr/bin/env node
import { detectCsrfToken, detectUserField, buildLoginSteps } from "../backend/js/web-auth.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

// detectCsrfToken
check(
  "detecta token en meta tag",
  detectCsrfToken('<meta name="csrf-token" content="abc123">') === "abc123",
);
check(
  "detecta token en input hidden",
  detectCsrfToken('<input type="hidden" name="_token" value="xyz789">') === "xyz789",
);
check(
  "sin token retorna null",
  detectCsrfToken("<html><body>sin token acá</body></html>") === null,
);

// detectUserField
check(
  "detecta campo email",
  detectUserField('<input type="email" name="email">') === "email",
);
check(
  "detecta campo username",
  detectUserField('<input type="text" name="username">') === "username",
);
check(
  "default a email sin campo reconocible",
  detectUserField("<html>sin inputs relevantes</html>") === "email",
);

// buildLoginSteps — fake step() que solo registra lo que se le pasó
function fakeStep(id, tool, args, when, meta) {
  return { id, tool, args: typeof args === "function" ? args({}) : args, when, meta };
}

const stepsWithToken = buildLoginSteps(fakeStep, "https://x/login", "u@x.com", "pass", "/tmp/c.txt");
check("con token: genera 2 steps (GET + POST)", stepsWithToken.length === 2);
check("con token: el GET apunta a la URL de login", stepsWithToken[0].args.includes("https://x/login"));
check("con token: el GET guarda cookies en cookieFile", stepsWithToken[0].args.includes("/tmp/c.txt"));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
```

- [ ] **Step 2: Correr y confirmar que falla**

Run: `cd /home/kali/dark_spear && node scripts/test-web-auth.mjs`
Expected: FAIL — `Error [ERR_MODULE_NOT_FOUND]: Cannot find module '.../backend/js/web-auth.js'`

- [ ] **Step 3: Implementar `backend/js/web-auth.js`**

```js
/**
 * Login web genérico: detecta el patrón Laravel (CSRF token + campo de
 * usuario) y arma los steps de GET+POST correspondientes. Sin token
 * detectado, cae a un fallback genérico (POST directo sin _token) para
 * stacks que no lo exigen en su form de login.
 */

const CSRF_META_RE = /<meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i;
const CSRF_INPUT_RE = /<input[^>]*name=["']_token["'][^>]*value=["']([^"']+)["']/i;

export function detectCsrfToken(html) {
  const meta = CSRF_META_RE.exec(html);
  if (meta) return meta[1];
  const input = CSRF_INPUT_RE.exec(html);
  if (input) return input[1];
  return null;
}

const USER_FIELD_RE = /<input[^>]*type=["'](?:email|text)["'][^>]*name=["'](email|username|user|login)["']/i;

export function detectUserField(html) {
  const match = USER_FIELD_RE.exec(html);
  return match ? match[1] : "email";
}

export function buildLoginSteps(step, loginUrl, user, password, cookieFile) {
  const getStep = step(
    "p1-webauth-get",
    "curl",
    ["-s", "-c", cookieFile, "--max-time", "15", loginUrl],
    null,
    { desc: "Login web: GET página de login para extraer token/campo" },
  );

  const postStep = step(
    "p1-webauth-post",
    "curl",
    (ctx) => {
      const html = String(ctx.webLoginPageHtml || "");
      const token = detectCsrfToken(html);
      const userField = detectUserField(html);
      const fields = [`${userField}=${encodeURIComponent(user)}`, `password=${encodeURIComponent(password)}`];
      if (token) fields.push(`_token=${encodeURIComponent(token)}`);
      return [
        "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
        "-X", "POST", "-d", fields.join("&"), loginUrl,
      ];
    },
    null,
    { desc: "Login web: POST credenciales (con _token si el stack lo exige)" },
  );

  return [getStep, postStep];
}
```

- [ ] **Step 4: Correr y confirmar que pasa**

Run: `cd /home/kali/dark_spear && node scripts/test-web-auth.mjs`
Expected: 9 checks, RESULTADO: OK

- [ ] **Step 5: Commit**

```bash
cd /home/kali/dark_spear
git add backend/js/web-auth.js scripts/test-web-auth.mjs
git commit -m "feat: web-auth.js - detección CSRF/usuario + steps de login genérico (Laravel + fallback)"
```

---

## Task 2: `form-discovery.js` — extracción de formularios desde HTML ya recolectado

**Files:**
- Create: `backend/js/form-discovery.js`
- Test: `scripts/test-form-discovery.mjs`

**Interfaces:**
- Produces: `extractForms(html: string): Array<{action: string, method: string, fields: Array<{name: string, type: string}>}>`

- [ ] **Step 1: Escribir test que falla (`scripts/test-form-discovery.mjs`)**

```js
#!/usr/bin/env node
import { extractForms } from "../backend/js/form-discovery.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

const singleFormHtml = `
<form action="/products/28/comments" method="POST">
  <input type="hidden" name="_token" value="abc">
  <textarea name="content"></textarea>
  <button type="submit">Enviar</button>
</form>
`;
const single = extractForms(singleFormHtml);
check("encuentra 1 form", single.length === 1);
check("action correcto", single[0]?.action === "/products/28/comments");
check("method correcto (mayúsculas normalizadas)", single[0]?.method === "POST");
check(
  "excluye hidden/submit, incluye textarea como campo probable",
  single[0]?.fields.some((f) => f.name === "content") &&
    !single[0]?.fields.some((f) => f.name === "_token"),
);

const noFormHtml = "<html><body>sin formularios acá</body></html>";
check("sin forms retorna lista vacía", extractForms(noFormHtml).length === 0);

const multiFormHtml = `
<form action="/search" method="GET"><input type="text" name="q"></form>
<form action="/comment" method="POST"><input type="text" name="body"><input type="password" name="pw"></form>
`;
const multi = extractForms(multiFormHtml);
check("encuentra 2 forms", multi.length === 2);
check(
  "excluye campos password de los campos probables",
  !multi[1]?.fields.some((f) => f.type === "password"),
);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
```

- [ ] **Step 2: Correr y confirmar que falla**

Run: `cd /home/kali/dark_spear && node scripts/test-form-discovery.mjs`
Expected: FAIL — módulo no encontrado

- [ ] **Step 3: Implementar `backend/js/form-discovery.js`**

```js
/**
 * Descubrimiento de formularios sobre HTML ya recolectado por sondas
 * existentes (root, robots.txt-linked, etc.) — sin requests nuevas en esta
 * fase. Los campos hidden/submit/password/csrf se excluyen de los "campos
 * probables" que después reciben payloads de XSS/SQLi: no tiene sentido
 * inyectar en un token oculto ni en un botón.
 */

const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const ACTION_RE = /action=["']([^"']+)["']/i;
const METHOD_RE = /method=["']([^"']+)["']/i;
const INPUT_RE = /<input\b([^>]*)>/gi;
const TEXTAREA_RE = /<textarea\b([^>]*?)name=["']([^"']+)["']/gi;
const NAME_RE = /name=["']([^"']+)["']/i;
const TYPE_RE = /type=["']([^"']+)["']/i;

const EXCLUDED_TYPES = new Set(["hidden", "submit", "password", "button", "image", "reset"]);
const EXCLUDED_NAME_RE = /token|csrf/i;

function fieldsFromFormBody(body) {
  const fields = [];

  let m;
  INPUT_RE.lastIndex = 0;
  while ((m = INPUT_RE.exec(body)) !== null) {
    const attrs = m[1];
    const nameMatch = NAME_RE.exec(attrs);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const typeMatch = TYPE_RE.exec(attrs);
    const type = typeMatch ? typeMatch[1].toLowerCase() : "text";
    if (EXCLUDED_TYPES.has(type) || EXCLUDED_NAME_RE.test(name)) continue;
    fields.push({ name, type });
  }

  TEXTAREA_RE.lastIndex = 0;
  while ((m = TEXTAREA_RE.exec(body)) !== null) {
    const name = m[2];
    if (EXCLUDED_NAME_RE.test(name)) continue;
    fields.push({ name, type: "textarea" });
  }

  return fields;
}

export function extractForms(html) {
  const forms = [];
  const text = String(html || "");
  let m;
  FORM_RE.lastIndex = 0;
  while ((m = FORM_RE.exec(text)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const actionMatch = ACTION_RE.exec(attrs);
    const methodMatch = METHOD_RE.exec(attrs);
    forms.push({
      action: actionMatch ? actionMatch[1] : "",
      method: methodMatch ? methodMatch[1].toUpperCase() : "GET",
      fields: fieldsFromFormBody(body),
    });
  }
  return forms;
}
```

- [ ] **Step 4: Correr y confirmar que pasa**

Run: `cd /home/kali/dark_spear && node scripts/test-form-discovery.mjs`
Expected: 6 checks, RESULTADO: OK

- [ ] **Step 5: Commit**

```bash
cd /home/kali/dark_spear
git add backend/js/form-discovery.js scripts/test-form-discovery.mjs
git commit -m "feat: form-discovery.js - extracción de <form> desde HTML ya recolectado"
```

---

## Task 3: `vuln-kb.js` — builders de sondas XSS/SQLi genéricas por formulario

**Files:**
- Modify: `backend/js/vuln-kb.js`
- Test: `scripts/test-form-probes.mjs`

**Interfaces:**
- Consumes: la forma `{action, method, fields}` producida por `extractForms` (Task 2).
- Produces: `xssFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12"): Array<StepSpec>`, `sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12"): Array<StepSpec>` — un step por cada campo de texto del form, con el resto de campos rellenados con un valor benigno fijo (`"x"`).

- [ ] **Step 1: Escribir test que falla (`scripts/test-form-probes.mjs`)**

```js
#!/usr/bin/env node
import { xssFormProbeSteps, sqliFormProbeSteps, XSS_REFLECTION_PAYLOAD } from "../backend/js/vuln-kb.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

function fakeStep(id, tool, args, when, meta) {
  return { id, tool, args, when, meta };
}

const form = {
  action: "/products/28/comments",
  method: "POST",
  fields: [{ name: "content", type: "textarea" }],
};

const xssSteps = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", form, "/tmp/c.txt");
check("XSS: genera 1 step (1 campo de texto)", xssSteps.length === 1);
check("XSS: apunta al action del form", xssSteps[0].args.includes("https://x/products/28/comments"));
check("XSS: incluye el payload de XSS reflejado en el body", xssSteps[0].args.some((a) => a.includes(XSS_REFLECTION_PAYLOAD)));
check("XSS: reusa la cookie jar", xssSteps[0].args.includes("/tmp/c.txt"));

const sqliSteps = sqliFormProbeSteps(fakeStep, "p2-formsqli", "https://x", form, "/tmp/c.txt");
check("SQLi: genera 1 step (1 campo de texto)", sqliSteps.length === 1);
check("SQLi: apunta al action del form", sqliSteps[0].args.includes("https://x/products/28/comments"));

const multiFieldForm = {
  action: "/search",
  method: "GET",
  fields: [
    { name: "q", type: "text" },
    { name: "category", type: "text" },
  ],
};
const multiXss = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", multiFieldForm, "/tmp/c.txt");
check("XSS: 1 step por campo (2 campos -> 2 steps)", multiXss.length === 2);
check(
  "XSS: cada step rellena los OTROS campos con valor benigno",
  multiXss[0].args.some((a) => a.includes("category=x")),
);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
```

- [ ] **Step 2: Correr y confirmar que falla**

Run: `cd /home/kali/dark_spear && node scripts/test-form-probes.mjs`
Expected: FAIL — `xssFormProbeSteps is not a function` (o similar, export inexistente)

- [ ] **Step 3: Implementar en `backend/js/vuln-kb.js`**

Agregar al final del archivo (reusa `XSS_REFLECTION_PAYLOAD` ya existente, línea ~525):

```js
/**
 * Sondas de XSS reflejado / SQLi genérico contra un formulario DESCUBIERTO
 * (no una ruta fija adivinada): un step por cada campo de texto del form,
 * con ese campo llevando el payload y el resto de campos en un valor
 * benigno fijo para no romper la validación del form por campos faltantes.
 */
const SQLI_GENERIC_PAYLOAD = "x' OR '1'='1";

function buildFormBody(form, targetField, payload) {
  return form.fields
    .map((f) => `${encodeURIComponent(f.name)}=${encodeURIComponent(f.name === targetField ? payload : "x")}`)
    .join("&");
}

function formProbeSteps(step, prefix, baseUrl, form, cookieFile, payload, desc, maxTime) {
  const textFields = form.fields.filter((f) => f.type !== "checkbox" && f.type !== "radio");
  return textFields.map((field) => {
    const body = buildFormBody(form, field.name, payload);
    const url = baseUrl + form.action;
    if (form.method === "GET") {
      return step(`${prefix}-${field.name}`, "curl", [
        "-s", "-L", "-b", cookieFile, "-c", cookieFile, "--max-time", maxTime,
        "-G", "--data-urlencode", `${field.name}=${payload}`,
        url,
      ], null, { desc: `${desc} — campo ${field.name}` });
    }
    return step(`${prefix}-${field.name}`, "curl", [
      "-s", "-L", "-b", cookieFile, "-c", cookieFile, "--max-time", maxTime,
      "-X", "POST", "-d", body,
      url,
    ], null, { desc: `${desc} — campo ${field.name}` });
  });
}

export function xssFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, XSS_REFLECTION_PAYLOAD, "Sonda de XSS reflejado en formulario descubierto", maxTime);
}

export function sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, SQLI_GENERIC_PAYLOAD, "Sonda de SQLi genérico en formulario descubierto", maxTime);
}
```

- [ ] **Step 4: Correr y confirmar que pasa**

Run: `cd /home/kali/dark_spear && node scripts/test-form-probes.mjs`
Expected: 8 checks, RESULTADO: OK

- [ ] **Step 5: Commit**

```bash
cd /home/kali/dark_spear
git add backend/js/vuln-kb.js scripts/test-form-probes.mjs
git commit -m "feat: xssFormProbeSteps/sqliFormProbeSteps - sondas genéricas contra formularios descubiertos"
```

---

## Task 4: Wiring en `playbook.js` — login al inicio de Fase 1, forms descubiertos alimentan Fase 2

**Files:**
- Modify: `backend/js/playbook.js`
- Test: `scripts/test-playbook-weblogin.mjs`

**Interfaces:**
- Consumes: `buildLoginSteps` (Task 1), `extractForms` (Task 2), `xssFormProbeSteps`/`sqliFormProbeSteps` (Task 3).
- Modifica: `buildPlaybookContext` (agrega `webLoginUrl`, `webUser`, `webPassword`, `webLoginPageHtml`, `discoveredForms` al objeto de contexto devuelto), `phase1Steps` (inserta los 2 steps de login al inicio cuando `ctx.webLoginUrl` está seteado), agrega función `phase2FormProbeSteps(baseUrl, ctx)` y la integra en el generador de steps de Fase 2 existente (`stepsForPhase`).

- [ ] **Step 1: Escribir test que falla (`scripts/test-playbook-weblogin.mjs`)**

```js
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

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
```

- [ ] **Step 2: Correr y confirmar que falla**

Run: `cd /home/kali/dark_spear && node scripts/test-playbook-weblogin.mjs`
Expected: FAIL — `discoveredForms` es `undefined`, no existen los steps `p1-webauth-*`/`p2-formxss-*`/`p2-formsqli-*`

- [ ] **Step 3: Modificar `backend/js/playbook.js`**

Agregar el import al inicio del archivo:

```js
import { buildLoginSteps } from "./web-auth.js";
import { extractForms } from "./form-discovery.js";
import { xssFormProbeSteps, sqliFormProbeSteps } from "./vuln-kb.js";
```

(ajustar el import existente de `vuln-kb.js` para incluir los dos nombres nuevos en la lista ya presente, en vez de un import separado, si el archivo ya importa varios símbolos de `vuln-kb.js` en una sola línea — confirmar contra el import real antes de editar).

En `buildPlaybookContext` (después del campo `bruteDiscovered`, antes del `return`), agregar:

```js
    webLoginUrl: String(ctx.webLoginUrl || "").trim(),
    webUser: String(ctx.webUser || "").trim(),
    webPassword: ctx.webPassword != null ? String(ctx.webPassword) : "",
    webLoginPageHtml: ctx.webLoginPageHtml || rawBlob,
    discoveredForms: (ctx.discoveredForms && ctx.discoveredForms.length)
      ? ctx.discoveredForms
      : extractForms(rawBlob),
```

En `phase1Steps`, al inicio del array `steps` (antes de `step("p1-nmap-sV", ...)`), agregar:

```js
    ...(ctx.webLoginUrl ? buildLoginSteps(step, ctx.webLoginUrl, ctx.webUser, ctx.webPassword, cookie) : []),
```

Agregar función nueva antes de `export function stepsForPhase`:

```js
function phase2FormProbeSteps(baseUrl, ctx) {
  const forms = ctx.discoveredForms || [];
  const steps = [];
  forms.forEach((form, i) => {
    steps.push(...xssFormProbeSteps(step, `p2-formxss-${i}`, baseUrl, form, ctx.cookieFile));
    steps.push(...sqliFormProbeSteps(step, `p2-formsqli-${i}`, baseUrl, form, ctx.cookieFile));
  });
  return steps;
}
```

Dentro de `stepsForPhase`, en la rama `case 2` (o el bloque equivalente que arma los steps de Fase 2 — confirmar el nombre real de la función/bloque contra el archivo antes de editar, dado que el código real puede llamarse `phase2Steps` u otra convención), agregar al array de steps devuelto:

```js
    ...phase2FormProbeSteps(baseUrl, ctx),
```

- [ ] **Step 4: Correr y confirmar que pasa**

Run: `cd /home/kali/dark_spear && node scripts/test-playbook-weblogin.mjs`
Expected: 9 checks, RESULTADO: OK

- [ ] **Step 5: Correr toda la suite de regresión existente (isolamiento por-paso, DVWA, etc.)**

Run: `cd /home/kali/dark_spear && node /tmp/claude-1000/-home-kali/1d4e47f1-a31d-4c3d-aa18-befaed710aee/scratchpad/verify_full_isolation.mjs && node /tmp/claude-1000/-home-kali/1d4e47f1-a31d-4c3d-aa18-befaed710aee/scratchpad/verify_dvwa_fix.mjs`
Expected: ambos `RESULTADO: OK`

- [ ] **Step 6: Commit**

```bash
cd /home/kali/dark_spear
git add backend/js/playbook.js scripts/test-playbook-weblogin.mjs
git commit -m "feat: wiring de login web + sondas por formulario en playbook.js (Fase 1+2)"
```

---

## Task 5: Finding informativo de login no confirmado / bloqueado por CAPTCHA-2FA

**Files:**
- Modify: `backend/js/finding-heuristics.js`
- Test: `scripts/test-weblogin-findings.mjs`

**Interfaces:**
- Consumes: `probeIdx` (ya existente en `collectHeuristicFindings`), IDs de step `p1-webauth-get`/`p1-webauth-post` (Task 1/4).
- Modifica: `buildProbeIndex` (agrega el mapeo de `p1-webauth-post` → clave `webauth-post`), `collectHeuristicFindings` (agrega el check de login no confirmado / CAPTCHA-2FA).

- [ ] **Step 1: Escribir test que falla (`scripts/test-weblogin-findings.mjs`)**

```js
#!/usr/bin/env node
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

const asset = "https://x.com";

// Login exitoso (redirect 302 tras el POST): NO debe generar el finding de
// "login no confirmado".
const successRecords = [
  { id: "p1-webauth-post", text: "HTTP/1.1 302 Found\nSet-Cookie: session=abc123" },
];
const successFindings = collectHeuristicFindings("", asset, {}, successRecords);
check(
  "login exitoso NO genera finding de login no confirmado",
  !successFindings.some((f) => /Login web no confirmado/i.test(f.title)),
);

// Login fallido (200 sin redirect, sin cookie de sesión nueva): SÍ genera
// el finding informativo.
const failRecords = [
  { id: "p1-webauth-post", text: "HTTP/1.1 200 OK\n<html>credenciales inválidas</html>" },
];
const failFindings = collectHeuristicFindings("", asset, {}, failRecords);
check(
  "login fallido SÍ genera finding de login no confirmado",
  failFindings.some((f) => /Login web no confirmado/i.test(f.title)),
);

// CAPTCHA detectado: genera el finding específico, NO el genérico de "no
// confirmado".
const captchaRecords = [
  { id: "p1-webauth-post", text: "HTTP/1.1 200 OK\n<div class=\"g-recaptcha\"></div>" },
];
const captchaFindings = collectHeuristicFindings("", asset, {}, captchaRecords);
check(
  "CAPTCHA detectado genera finding específico",
  captchaFindings.some((f) => /CAPTCHA/i.test(f.title)),
);
check(
  "CAPTCHA detectado NO genera también el finding genérico de no confirmado",
  !captchaFindings.some((f) => /Login web no confirmado/i.test(f.title)),
);

// Sin intento de login (sin p1-webauth-post en stepRecords): ningún finding
// de login en absoluto.
const noLoginRecords = [{ id: "p1-osint-curl-head-root", text: "<title>x</title>" }];
const noLoginFindings = collectHeuristicFindings("", asset, {}, noLoginRecords);
check(
  "sin intento de login: cero findings relacionados a login web",
  !noLoginFindings.some((f) => /Login web/i.test(f.title) || /CAPTCHA/i.test(f.title)),
);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
```

- [ ] **Step 2: Correr y confirmar que falla**

Run: `cd /home/kali/dark_spear && node scripts/test-weblogin-findings.mjs`
Expected: FAIL — ninguno de los 4 checks positivos pasa (la lógica no existe)

- [ ] **Step 3: Implementar en `backend/js/finding-heuristics.js`**

En `buildProbeIndex`, agregar (junto a los demás `if (r.id === "...")`):

```js
    if (r.id === "p1-webauth-post") push("webauth-post", text);
```

En `collectHeuristicFindings`, agregar (después del bloque de `securityLowOnRoot`):

```js
  const webauthText = probeIdx["webauth-post"] || "";
  if (webauthText) {
    const hasCaptcha = /recaptcha|hcaptcha|g-recaptcha/i.test(webauthText);
    const hasRedirect = /^HTTP\/[\d.]+\s+30[123]\b/im.test(webauthText);
    const hasNewSessionCookie = /set-cookie:/i.test(webauthText);
    const loginConfirmed = hasRedirect || hasNewSessionCookie;

    if (hasCaptcha) {
      add(
        "Login web bloqueado por CAPTCHA/2FA — requiere intervención manual",
        "Info",
        "El POST de login devolvió una página con CAPTCHA (recaptcha/hcaptcha) o un segundo factor. El motor no reintenta ni intenta bypasear controles de este tipo.",
        "Completar el login manualmente y reusar la cookie de sesión resultante si se necesita continuar el escaneo autenticado.",
        ["p1-webauth-post"],
      );
    } else if (!loginConfirmed) {
      add(
        "Login web no confirmado — descubrimiento de formularios corre sin sesión autenticada",
        "Info",
        "El POST de login no devolvió un redirect (302/303) ni una cookie de sesión nueva. El resto del engagement corre como si no se hubiera logueado.",
        "Verificar usuario/contraseña, o que la URL de login sea la correcta. Revisar la evidencia cruda del paso p1-webauth-post.",
        ["p1-webauth-post"],
      );
    }
  }
```

- [ ] **Step 4: Correr y confirmar que pasa**

Run: `cd /home/kali/dark_spear && node scripts/test-weblogin-findings.mjs`
Expected: 5 checks, RESULTADO: OK

- [ ] **Step 5: Correr toda la suite de regresión existente otra vez (nada debe romperse)**

Run: `cd /home/kali/dark_spear && node /tmp/claude-1000/-home-kali/1d4e47f1-a31d-4c3d-aa18-befaed710aee/scratchpad/verify_full_isolation.mjs && node /tmp/claude-1000/-home-kali/1d4e47f1-a31d-4c3d-aa18-befaed710aee/scratchpad/verify_dvwa_fix.mjs`
Expected: ambos `RESULTADO: OK`

- [ ] **Step 6: Sincronizar el motor hacia el panel**

Run: `cd /home/kali/dark_spear && python3 scripts/sync-engine-js.py`
Expected: lista de archivos sincronizados incluyendo `finding-heuristics.js`, `playbook.js`, `vuln-kb.js`

- [ ] **Step 7: Commit (incluye los 3 archivos fuente modificados + sus copias sincronizadas en panel/vendor/engine/js/ + BUILD)**

```bash
cd /home/kali/dark_spear
git add backend/js/finding-heuristics.js scripts/test-weblogin-findings.mjs
git add panel/vendor/engine/js/finding-heuristics.js panel/vendor/engine/js/playbook.js panel/vendor/engine/js/vuln-kb.js panel/vendor/engine/js/web-auth.js panel/vendor/engine/js/form-discovery.js panel/vendor/engine/BUILD
git commit -m "feat: finding informativo de login web no confirmado / bloqueado por CAPTCHA-2FA"
```

**Nota:** verificar con `git status --short` ANTES de este `git add` que no se cuelan archivos ajenos de WIP preexistente (`backend/js/playbook.js`/`vuln-kb.js` ya tenían cambios sin commitear de otra sesión antes de empezar este plan) — si `panel/vendor/engine/js/playbook.js` o `vuln-kb.js` muestran en su diff contenido que NO corresponde a los cambios de este plan (Tasks 3/4), separar manualmente o consultar antes de commitear, siguiendo la misma disciplina aplicada en el fix de DVWA de esta sesión.

---

## Task 6: UI — campos de login web en el panel

**Files:**
- Modify: `panel/start-engagement.html`
- Modify: `panel/vendor/engine-panel.js`
- Modify: `panel/vendor/i18n.js`

**Interfaces:**
- Produces: 3 inputs nuevos en el HTML (`web-login-url`, `web-user`, `web-password`), leídos por `engine-panel.js` hacia el objeto `run` guardado en `sessionStorage` (mismo patrón que `adDomain`/`adUser`/`adPassword`), y propagados desde `run` hacia los parámetros pasados al motor (`webLoginUrl`, `webUser`, `webPassword`).

Este task es HTML/JS de panel sin lógica de negocio nueva (mismo patrón mecánico ya usado para los campos AD) — no requiere test automatizado nuevo; se verifica con smoke test manual.

- [ ] **Step 1: Agregar los 3 campos en `panel/start-engagement.html`**

Ubicar el bloque de los campos `ad-domain`/`ad-user`/`ad-password` (líneas ~325-334 según exploración de esta sesión) y agregar, en un bloque separado con su propio encabezado ("Login web (opcional)"):

```html
<label class="font-label-md text-label-md text-on-surface-variant" for="web-login-url" data-i18n="start.webLoginUrl">URL de login</label>
<input id="web-login-url" name="web-login-url" class="fluent-input bg-surface-container-lowest rounded px-md py-sm font-body-md text-body-md text-on-surface w-full" placeholder="https://target.com/login" type="text" autocomplete="off"/>

<label class="font-label-md text-label-md text-on-surface-variant" for="web-user" data-i18n="start.webUser">Usuario</label>
<input id="web-user" name="web-user" class="fluent-input bg-surface-container-lowest rounded px-md py-sm font-body-md text-body-md text-on-surface w-full" placeholder="usuario@target.com" type="text" autocomplete="off"/>

<label class="font-label-md text-label-md text-on-surface-variant" for="web-password" data-i18n="start.webPassword">Contraseña</label>
<input id="web-password" name="web-password" class="fluent-input bg-surface-container-lowest rounded px-md py-sm font-body-md text-body-md text-on-surface w-full" type="password" autocomplete="off"/>
```

(clases CSS copiadas literal de los campos `ad-user`/`ad-password` ya existentes — confirmar contra el archivo real que las clases coinciden antes de pegar, dado que pueden variar levemente).

- [ ] **Step 2: Leer los campos en `panel/vendor/engine-panel.js` (línea ~1135, junto a `adUser`/`adPassword`)**

```js
        webLoginUrl: (document.getElementById("web-login-url")?.value || "").trim(),
        webUser: (document.getElementById("web-user")?.value || "").trim(),
        webPassword: document.getElementById("web-password")?.value || "",
```

- [ ] **Step 3: Propagar `run.webLoginUrl`/`run.webUser`/`run.webPassword` hacia el motor (línea ~1614, junto a `adUser`/`adPassword`)**

```js
      webLoginUrl: run.webLoginUrl || "",
      webUser: run.webUser || "",
      webPassword: run.webPassword || "",
```

- [ ] **Step 4: Agregar labels en `panel/vendor/i18n.js`**

Junto a las claves `"start.adUser"` existentes (español e inglés), agregar:

```js
      "start.webLoginUrl": "URL de login",
      "start.webUser": "Usuario",
      "start.webPassword": "Contraseña",
```

y su equivalente en inglés:

```js
      "start.webLoginUrl": "Login URL",
      "start.webUser": "Username",
      "start.webPassword": "Password",
```

- [ ] **Step 5: Smoke test manual**

Arrancar `python3 backend/bridge.py`, abrir `http://127.0.0.1:8080/start-engagement.html`, confirmar visualmente que los 3 campos nuevos aparecen bajo un encabezado separado de los campos AD, completar una URL de login + usuario + password de prueba, iniciar el engagement, y confirmar en la consola del navegador (o en el feed de steps del panel) que aparecen los steps `p1-webauth-get`/`p1-webauth-post` al principio de la Fase 1.

- [ ] **Step 6: Commit**

```bash
cd /home/kali/dark_spear
git add panel/start-engagement.html panel/vendor/engine-panel.js panel/vendor/i18n.js
git commit -m "feat: campos de login web (URL/usuario/contraseña) en el panel de start-engagement"
```

---

## Self-Review (completado antes de entregar el plan)

- **Cobertura del spec (Fase 1):** campos separados de AD (Task 6) ✅; `detectCsrfToken`/`detectUserField`/`buildLoginSteps` con fallback genérico sin token (Task 1) ✅; login insertado al inicio de Fase 1 solo si `ctx.webLoginUrl` está seteado, cero cambio de comportamiento si está vacío (Task 4, tests explícitos de ambos caminos) ✅; `extractForms` sobre HTML ya recolectado, sin requests nuevas (Task 2) ✅; sondas XSS+SQLi genéricas por campo de texto de cada form descubierto, reusando `XSS_REFLECTION_PAYLOAD` existente (Task 3) ✅; evidencia por-paso nunca contra el blob acumulado (Task 5, `probeIdx["webauth-post"]`) ✅; CAPTCHA/2FA → finding informativo sin reintento ni bypass (Task 5) ✅.
- **Sin placeholders:** todo el código de cada step está completo.
- **Consistencia de tipos:** `buildLoginSteps(step, loginUrl, user, password, cookieFile)` (Task 1) se llama con la misma firma en `phase1Steps` (Task 4); `extractForms(html)` (Task 2) se llama con la misma firma en `buildPlaybookContext` (Task 4); `xssFormProbeSteps`/`sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime)` (Task 3) se llaman con la misma firma en `phase2FormProbeSteps` (Task 4).
- **Fuera de alcance respetado:** WordPress, IDOR/NoSQLi contra forms, crawling activo quedan documentados como Fases 2-4 en el spec, sin tocar en este plan.
- **Riesgo identificado y mitigado explícitamente:** WIP preexistente sin commitear en `playbook.js`/`vuln-kb.js`/otros archivos de panel — Task 5 incluye nota explícita de verificar `git status --short` antes de cada commit para no mezclar con el fix de DVWA ya commiteado en `2a830b1` ni con trabajo ajeno de otra sesión.
