#!/usr/bin/env node
/**
 * Verifica extractDangerousCodePatterns() y codeDangerProbeSteps() contra
 * un fixture sintético que cubre las 4 firmas del catálogo.
 */
import { extractDangerousCodePatterns, codeDangerProbeSteps } from "../backend/js/vuln-kb.js";

let ok = true;

const blob = [
  "whereRaw(\"code = '\" . $request->code . \"'\")->where('is_active', true)",
  "file_get_contents($_GET['url'])",
  "echo $_GET['q'];",
  "Route::get('/admin/export', [ExportController::class, 'run']);",
].join("\n");

const hits = extractDangerousCodePatterns(blob);

const check1 = hits.length === 4;
console.log((check1 ? "OK" : "FAIL") + `: encuentra las 4 firmas (obtenido: ${hits.length})`);
ok = ok && check1;

const sqli = hits.find((h) => h.kind === "sqli_concat");
const check2 = !!sqli && sqli.param === "code";
console.log((check2 ? "OK" : "FAIL") + ": sqli_concat captura el parámetro 'code'");
ok = ok && check2;

const lfi = hits.find((h) => h.kind === "lfi_include");
const check3 = !!lfi && lfi.param === "url";
console.log((check3 ? "OK" : "FAIL") + ": lfi_include captura el parámetro 'url'");
ok = ok && check3;

const authz = hits.find((h) => h.kind === "authz_missing_middleware");
const check4 = !!authz && authz.route === "/admin/export";
console.log((check4 ? "OK" : "FAIL") + ": authz_missing_middleware captura la ruta '/admin/export'");
ok = ok && check4;

const step = (id, tool, args, when, meta) => ({ id, tool, args, when, meta });
const steps = codeDangerProbeSteps(step, hits, "http://target.local/coupon");
const check5 = steps.length === 3; // capped at 3
console.log((check5 ? "OK" : "FAIL") + `: codeDangerProbeSteps limita a 3 sondas (obtenido: ${steps.length})`);
ok = ok && check5;

const sqliStep = steps.find((s) => s.meta.codeDangerKind === "sqli_concat");
const check6 = !!sqliStep && sqliStep.args.some((a) => String(a).includes("code="));
console.log((check6 ? "OK" : "FAIL") + ": la sonda sqli_concat referencia el parámetro capturado");
ok = ok && check6;

process.exit(ok ? 0 : 1);
