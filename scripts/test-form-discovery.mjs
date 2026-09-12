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
