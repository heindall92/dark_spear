#!/usr/bin/env node
/**
 * proofLevel: distinguishes findings backed by actual exploitation
 * ("proven" — sqlmap extracted real DB names, JWT alg=none bypass accepted
 * by the server) from findings backed only by signature/version detection
 * ("detected" — the default for everything else, e.g. nuclei/testssl).
 */
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";
import { sqlmapFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const sqlmapOut = "Parameter: id (GET)\n    Type: boolean-based blind\nsqlmap identified the following injection point(s)";
const sqlmapOnly = sqlmapFindings(sqlmapOut);
check("sqlmapFindings sin parametros detectables -> proofLevel proven", sqlmapOnly.length === 0 || sqlmapOnly[0].proofLevel === "proven");

const sqlmapWithParam = "Parameter: id (GET)\nsqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:\n---\nParameter: id (GET)\n    Type: boolean-based blind\n---";
const found = sqlmapFindings(sqlmapWithParam);
check("sqlmapFindings con parametro -> al menos 1 finding proofLevel proven", found.length > 0 && found.every((f) => f.proofLevel === "proven"));

const stepRecords = [{ id: "p1-jwt-algnone-1", text: "DS_HTTP:200\n{\"role\":\"admin\"}" }];
const jwtFindings = collectHeuristicFindings("", "https://x.example.com", {}, stepRecords)
  .filter((f) => /alg=none/i.test(f.title));
check("bypass JWT alg=none confirmado -> proofLevel proven", jwtFindings.length > 0 && jwtFindings.every((f) => f.proofLevel === "proven"));

const dvwaStepRecords = [{ id: "head-root", text: "<title>Login :: Damn Vulnerable Web Application</title>" }];
const dvwaFindings = collectHeuristicFindings("", "https://x.example.com", {}, dvwaStepRecords)
  .filter((f) => /DVWA expuesta/i.test(f.title));
check("deteccion pasiva DVWA -> proofLevel detected (default)", dvwaFindings.length > 0 && dvwaFindings.every((f) => f.proofLevel === "detected"));

// Regresión: los findings de sqlmapFindings() (vuln-kb.js) se vuelven a
// envolver dentro de finding-heuristics.js vía add(f.title, f.severity, ...)
// antes de sumarse al array final. Ese re-wrap debe reenviar f.proofLevel
// (6to arg de add()) — si no lo hace, el finding pierde su etiqueta "proven"
// y cae al default "detected" de add(), aunque sqlmapFindings() sí la puso.
const sqlmapStepRecords = [{
  id: "p3-sqlmap-forms",
  text: "Parameter: id (GET)\nsqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:\n---\nParameter: id (GET)\n    Type: boolean-based blind\n---",
}];
const sqlmapViaHeuristics = collectHeuristicFindings("", "https://x.example.com", {}, sqlmapStepRecords)
  .filter((f) => /sqlmap/i.test(f.title));
check(
  "sqlmap finding reenvuelto por finding-heuristics.js conserva proofLevel proven end-to-end (no cae a 'detected')",
  sqlmapViaHeuristics.length > 0 && sqlmapViaHeuristics.every((f) => f.proofLevel === "proven"),
);

process.exit(ok ? 0 : 1);
