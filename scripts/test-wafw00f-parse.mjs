#!/usr/bin/env node
/**
 * Parseo de salida de wafw00f (JSON y texto) y cableado al playbook.
 */
import {
  wafw00fFindings,
  missingWafFinding,
  dropContradictoryWafFindings,
} from "../backend/js/vuln-kb.js";
import { stepsForPhase } from "../backend/js/playbook.js";
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const jsonHit = JSON.stringify([{
  url: "https://www.example.com",
  detected: true,
  firewall: "Cloudflare",
  manufacturer: "Cloudflare Inc.",
}]);
const jsonMiss = JSON.stringify([{
  url: "http://127.0.0.1:8888",
  detected: false,
  firewall: "None",
  manufacturer: "None",
}]);
const textHit = "[*] Checking https://www.example.com\n[+] The site https://www.example.com is behind Imperva Incapsula (Imperva Inc.) WAF.\n[~] Number of requests: 6\n";
const textMiss = "[*] Checking http://127.0.0.1:3000\n[-] No WAF detected by the generic detection\n";

const fromJson = wafw00fFindings(jsonHit);
assert(fromJson.length === 1, "JSON detectado → 1 hallazgo");
assert(/Cloudflare/i.test(fromJson[0].title), "título lleva el producto");
assert(/WAF\/CDN identificado/i.test(fromJson[0].title), "mismo molde que la huella pasiva");

assert(wafw00fFindings(jsonMiss).length === 0, "detected:false no inventa WAF");
assert(wafw00fFindings("").length === 0, "salida vacía no inventa WAF");

const fromText = wafw00fFindings(textHit);
assert(fromText.length === 1, "texto clásico → 1 hallazgo");
assert(/Imperva/i.test(fromText[0].title), "parsea 'is behind … WAF'");
assert(wafw00fFindings(textMiss).length === 0, "No WAF detected → vacío");

assert(
  missingWafFinding("HTTP/1.1 200 OK\nServer: nginx", "HTTP/1.1 200 OK\n", true, jsonHit).length === 0,
  "wafw00f positivo anula 'sin WAF'",
);

const dropped = dropContradictoryWafFindings([
  { title: "Sin WAF/CDN identificable desde caja negra" },
  { title: fromJson[0].title },
]);
assert(dropped.length === 1 && /identificado/i.test(dropped[0].title), "mutuamente excluyentes con wafw00f");

const p1 = stepsForPhase(1, "http://127.0.0.1:8888", { host: "127.0.0.1" });
const ww = p1.find((s) => s.id === "p1-wafw00f");
assert(ww && ww.tool === "wafw00f", "fase 1 incluye p1-wafw00f");
assert(Array.isArray(ww.args) && ww.args.includes("http://127.0.0.1:8888"), "wafw00f recibe la URL");

const heuristic = collectHeuristicFindings(
  jsonHit,
  "https://www.example.com",
  { host: "www.example.com" },
  [{ id: "p1-osint-curl-head-root", text: "HTTP/1.1 200 OK\nServer: nginx\n" }, { id: "p1-wafw00f", text: jsonHit }],
);
assert(heuristic.some((f) => /WAF\/CDN identificado: Cloudflare/i.test(f.title)), "heurística lee p1-wafw00f");
assert(!heuristic.some((f) => /Sin WAF/i.test(f.title)), "no contradice con ausencia");

console.log("OK — wafw00f parseo + playbook + heurística");
