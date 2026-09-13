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
