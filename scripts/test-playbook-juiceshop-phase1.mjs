#!/usr/bin/env node
/**
 * Verificación rápida (solo fase 1) de las heurísticas nuevas contra
 * Juice Shop: bypass de login por SQLi, seguimiento de robots.txt→/ftp/,
 * y sondas de superficie REST/API (metrics, source maps, directorios).
 *
 * Reevalúa las heurísticas DESPUÉS DE CADA PASO (como hace agent.js de
 * verdad vía runHeuristicFindings), no solo al final — así reproduce la
 * condición de carrera real entre sondas que comparten patrón.
 *
 * Uso: node scripts/test-playbook-juiceshop-phase1.mjs [target]
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { stepsForPhase, buildPlaybookContext } from "../backend/js/playbook.js";
import { collectHeuristicFindings, heuristicAssetFromTarget } from "../backend/js/finding-heuristics.js";

const execFileAsync = promisify(execFile);
const target = process.argv[2] || "http://127.0.0.1:3000";

function runCmd(tool, args) {
  return execFileAsync(tool, args, { maxBuffer: 4 * 1024 * 1024, timeout: 30000 })
    .then(({ stdout, stderr }) => ({ stdout: stdout || "", stderr: stderr || "", exit_code: 0, verdict: "ok" }))
    // No usar err.message como stderr: con curl -s (silencia sus propios
    // errores), execFile sintetiza el argv completo ahí, filtrando nuestros
    // propios payloads inyectados como si fueran respuesta del servidor.
    .catch((err) => ({ stdout: err.stdout || "", stderr: err.stderr || "", exit_code: err.code ?? 1, verdict: "error" }));
}

function resolveArgs(spec, ctx) {
  return typeof spec.args === "function" ? spec.args(ctx) : spec.args;
}

async function runPass(target, ctx, outputs, stepRecords, executed, asset, seenTitles) {
  for (const spec of stepsForPhase(1, target, ctx)) {
    if (spec.when) continue;
    if (executed.has(spec.id)) continue;
    if (typeof spec.skipIf === "function" && spec.skipIf(ctx)) continue;
    if (spec.tool !== "curl") { executed.add(spec.id); continue; }
    const args = resolveArgs(spec, ctx);
    if (!args) continue;
    const result = await runCmd(spec.tool, args);
    executed.add(spec.id);
    const out = result.stdout || "";
    const err = result.stderr || "";
    if (out) outputs.push(out);
    if (err) outputs.push(err);
    stepRecords.push({ id: spec.id, text: [out, err].filter(Boolean).join("\n") });
    ctx = buildPlaybookContext(outputs, ctx);
    console.log(`  ${spec.id} -> ${(out || err || "(vacío)").slice(0, 80).replace(/\n/g, " ")}`);
    // Igual que runHeuristicFindings en agent.js: reevaluar tras CADA paso,
    // no solo al final. Si algo se marca prematuramente aquí, es un bug.
    const midFindings = collectHeuristicFindings(outputs.join("\n"), asset, ctx, stepRecords);
    midFindings.forEach((f) => {
      if (!seenTitles.has(f.title)) {
        seenTitles.set(f.title, spec.id);
        console.log(`    >> nuevo hallazgo tras ${spec.id}: [${f.severity}] ${f.title}`);
      }
    });
  }
  return ctx;
}

async function main() {
  console.log("=== Verificación heurísticas nuevas — Juice Shop (reevaluación por paso) ===");
  console.log("Target:", target, "\n");

  let ctx = { scope: target, host: new URL(target).hostname };
  const outputs = [];
  const stepRecords = [];
  const executed = new Set();
  const asset = heuristicAssetFromTarget(target);
  const seenTitles = new Map();

  console.log("-- Pasada 1 --");
  ctx = await runPass(target, ctx, outputs, stepRecords, executed, asset, seenTitles);
  console.log("-- Pasada 2 (pasos dinámicos: robots-follow) --");
  ctx = await runPass(target, ctx, outputs, stepRecords, executed, asset, seenTitles);
  console.log("-- Pasada 3 --");
  ctx = await runPass(target, ctx, outputs, stepRecords, executed, asset, seenTitles);

  console.log("\nrobotsDisallowed:", ctx.robotsDisallowed);

  const findings = collectHeuristicFindings(outputs.join("\n"), asset, ctx, stepRecords);
  console.log("\n--- Hallazgos heurísticos finales:", findings.length, "---");
  findings.forEach((f) => console.log(`  [${f.severity}] ${f.title}`));

  const falsePositives = [
    /Directorio \/backup\/ listable/,
    /Directorio \/files\/ listable/,
    /Directorio \/uploads\/ listable/,
    /Directorio \/storage\/ listable/,
  ];
  const wrong = falsePositives.filter((re) => findings.some((f) => re.test(f.title)));
  const wantTitles = [
    /Bypass de autenticación por SQL injection en login/,
    /Ruta oculta en robots\.txt.*expone un listado de directorio/,
    /Directorio \/ftp\/ listable/,
  ];
  const missing = wantTitles.filter((re) => !findings.some((f) => re.test(f.title)));

  console.log("");
  if (wrong.length) console.log(`FAIL: ${wrong.length} falsos positivos (directorios que NO son reales)`);
  if (missing.length) console.log(`FAIL: faltan ${missing.length} hallazgos esperados`);
  if (!wrong.length && !missing.length) console.log("OK: sin falsos positivos y todos los hallazgos esperados aparecieron");
  process.exit(wrong.length || missing.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
