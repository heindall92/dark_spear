// Verifica JWT (crackeo HS256 débil + bypass alg=none) y detección CORS.
// Estas funciones ya existían en vuln-kb.js sin ningún test — este archivo
// las cubre construyendo fixtures con crypto real de Node (independiente
// de la implementación SHA-256/HMAC puro-JS que se está probando).
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  crackJwtHs256Secret,
  forgeAlgNoneToken,
  JWT_TOKEN_RE,
  JWT_WEAK_SECRETS,
  corsFinding,
  CORS_PROBE_ORIGIN,
} from "../backend/js/vuln-kb.js";

// polyfill de globals de navegador que vuln-kb.js usa (atob/btoa/TextEncoder/TextDecoder)
if (typeof globalThis.atob === "undefined") {
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  globalThis.btoa = (bin) => Buffer.from(bin, "binary").toString("base64");
}

let failures = 0;
function ok(name, cond) {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    failures++;
    console.log(`FAIL ${name}`);
  }
}

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function signHs256(header, payload, secret) {
  const h = b64url(Buffer.from(JSON.stringify(header)));
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}

// --- crackJwtHs256Secret ---------------------------------------------------

{
  const token = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "admin", role: "admin" }, "secret");
  const found = crackJwtHs256Secret(token);
  ok("crackJwtHs256Secret encuentra secreto débil conocido ('secret')", found === "secret");
}

{
  const token = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "admin" }, "supersecret");
  const found = crackJwtHs256Secret(token);
  ok("crackJwtHs256Secret encuentra otro secreto del diccionario", found === "supersecret");
}

{
  const token = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "admin" }, "this-is-a-genuinely-random-256bit-secret-xyz789");
  const found = crackJwtHs256Secret(token);
  ok("crackJwtHs256Secret no rompe secreto fuerte fuera del diccionario", found === null);
}

{
  // RS256 no es crackeable así (clave asimétrica) — debe devolver null, no
  // intentar HMAC contra un alg que no es HS256.
  const h = b64url(Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const p = b64url(Buffer.from(JSON.stringify({ sub: "admin" })));
  const token = `${h}.${p}.${b64url(Buffer.from("fake-rsa-sig"))}`;
  ok("crackJwtHs256Secret ignora alg=RS256", crackJwtHs256Secret(token) === null);
}

ok("crackJwtHs256Secret token malformado -> null", crackJwtHs256Secret("no.es.un.jwt.valido") === null);
ok("crackJwtHs256Secret vacío -> null", crackJwtHs256Secret("") === null);
ok("JWT_WEAK_SECRETS es un array no vacío", Array.isArray(JWT_WEAK_SECRETS) && JWT_WEAK_SECRETS.length > 10);

// --- forgeAlgNoneToken ------------------------------------------------------

{
  const original = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "admin", role: "admin" }, "whatever");
  const forged = forgeAlgNoneToken(original);
  const parts = forged.split(".");
  ok("forgeAlgNoneToken produce 3 partes (header.payload.)", parts.length === 3);
  ok("forgeAlgNoneToken deja firma vacía", parts[2] === "");
  const header = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
  ok("forgeAlgNoneToken header alg=none", header.alg === "none");
  const originalPayloadB64 = original.split(".")[1];
  ok("forgeAlgNoneToken conserva el payload original intacto (mismos claims)", parts[1] === originalPayloadB64);
}

ok("forgeAlgNoneToken token malformado -> null", forgeAlgNoneToken("solo-un-string") === null);

// --- JWT_TOKEN_RE ------------------------------------------------------------

{
  const token = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "x" }, "s");
  const blob = `{"success":true,"token":"${token}"}`;
  const m = blob.match(JWT_TOKEN_RE);
  ok("JWT_TOKEN_RE extrae el token embebido en una respuesta JSON", m && m[0] === token);
}
ok("JWT_TOKEN_RE no dispara con texto sin JWT", !JWT_TOKEN_RE.test("no hay token aquí"));

// --- corsFinding -------------------------------------------------------------

ok("corsFinding null sin cabecera ACAO", corsFinding("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") === null);

{
  const f = corsFinding("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\n");
  ok("corsFinding detecta wildcard + credentials (High)", f && f.severity === "High" && /wildcard|comodín/i.test(f.title + f.description));
}

{
  const f = corsFinding(`HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: ${CORS_PROBE_ORIGIN}\r\n`);
  ok("corsFinding detecta reflejo de Origin sin credentials (High, sin Critical)", f && f.severity === "High");
}

{
  const f = corsFinding(`HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: ${CORS_PROBE_ORIGIN}\r\nAccess-Control-Allow-Credentials: true\r\n`);
  ok("corsFinding reflejo + credentials -> Critical", f && f.severity === "Critical");
}

{
  const f = corsFinding("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://app.example.com\r\n");
  ok("corsFinding origen fijo legítimo (no el probe) -> null", f === null);
}

if (failures) {
  console.log(`\n${failures} fallo(s)`);
  process.exit(1);
}
console.log("\nOK jwt-cors: crackeo HS256, bypass alg=none y detección CORS");
