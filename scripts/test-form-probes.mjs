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
