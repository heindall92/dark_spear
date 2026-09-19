#!/usr/bin/env node
import { xssFormProbeSteps, sqliFormProbeSteps, XSS_REFLECTION_PAYLOAD, buildFormBody } from "../backend/js/vuln-kb.js";

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
check("XSS: incluye el payload de XSS reflejado en el body (URL-encodeado)", xssSteps[0].args.some((a) => a.includes(encodeURIComponent(XSS_REFLECTION_PAYLOAD))));
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

// form.action absoluto FUERA de scope (ej. formulario que postea a otro
// dominio/puerto): el motor NO debe mandar payloads ahí — el target
// controla ese valor, no es una decisión del playbook. Sin root, o con
// root que no matchea, se omite el form entero (fail-closed).
const absoluteActionForm = {
  action: "https://otro-dominio.com/endpoint",
  method: "POST",
  fields: [{ name: "content", type: "text" }],
};
const absoluteStepsNoRoot = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", absoluteActionForm, "/tmp/c.txt");
check(
  "action absoluto fuera de scope, SIN root: no genera steps (fail-closed)",
  absoluteStepsNoRoot.length === 0,
);
const absoluteStepsWrongRoot = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", absoluteActionForm, "/tmp/c.txt", "12", "x");
check(
  "action absoluto fuera de scope, CON root que no matchea: no genera steps",
  absoluteStepsWrongRoot.length === 0,
);

// action absoluto que SÍ resuelve al mismo host que root: debe seguir
// funcionando exactamente como antes (comportamiento legítimo preservado).
const sameHostAbsoluteForm = {
  action: "https://x/other-path",
  method: "POST",
  fields: [{ name: "content", type: "text" }],
};
const sameHostSteps = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", sameHostAbsoluteForm, "/tmp/c.txt", "12", "x");
check(
  "action absoluto que SÍ apunta al mismo host que root: genera el step normalmente",
  sameHostSteps.length === 1 && sameHostSteps[0].args.includes("https://x/other-path"),
);

// buildFormBody debe URL-encodear valores (campo o payload) que contengan
// & o = — de lo contrario un payload futuro con esos caracteres rompería
// el body POST al insertar pares clave=valor espurios.
const specialCharForm = { fields: [{ name: "q", type: "text" }] };
const specialBody = buildFormBody(specialCharForm, "q", "a=b&c=d");
check(
  "buildFormBody: URL-encodea & y = dentro del valor del payload",
  specialBody === "q=a%3Db%26c%3Dd",
);

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
