#!/usr/bin/env node
/**
 * Simula fase 1 del playbook contra DVWA y evalúa heurísticas de hallazgos.
 * Uso: node scripts/test-playbook-dvwa.mjs [target]
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { stepsForPhase, buildPlaybookContext, isMeaningfulToolOutput, parseTarget } from "../backend/js/playbook.js";
import { collectHeuristicFindings, heuristicAssetFromTarget } from "../backend/js/finding-heuristics.js";

const execFileAsync = promisify(execFile);
const target = process.argv[2] || "http://127.0.0.1:8888";
const cookie = "/tmp/ds-test-playbook-cookies.txt";

function runCmd(tool, args) {
  return execFileAsync(tool, args, { maxBuffer: 2 * 1024 * 1024, timeout: 120000 })
    .then(({ stdout, stderr }) => ({
      stdout: stdout || "",
      stderr: stderr || "",
      exit_code: 0,
      verdict: "ok",
    }))
    .catch((err) => ({
      // OJO: err.message de execFile incluye la línea de comando completa
      // (con nuestros propios payloads inyectados, p. ej. marcador XSS) si
      // el proceso falla con stdout/stderr vacíos (curl -s silencia sus
      // propios errores). Nunca usar err.message como stderr: filtraría el
      // argv como si fuera respuesta real del servidor. bridge.py en
      // producción tampoco lo hace (subprocess.run no sintetiza ese texto).
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      exit_code: err.code ?? 1,
      verdict: "error",
    }));
}

function appendStepEvidence(spec, result, outputs) {
  const out = String(result.stdout ?? "").trim();
  const code = (out.match(/DS_HTTP:(\d{3})/) || out.match(/^(\d{3})$/) || [])[1] || "";
  const redir = (out.match(/DS_REDIRECT:([^\n]*)/) || [])[1] || "";
  if (spec.id === "p1-login-post" && code === "302" && /index\.php/i.test(redir)) {
    outputs.push("EVIDENCE: login.php POST admin/password → HTTP 302 index.php");
  }
  if (spec.id === "p1-login-post" && code === "200") {
    outputs.push("EVIDENCE: login.php POST returned 200 (revisar CSRF/sesión)");
  }
  if (spec.id === "p1-curl-setup" && /200\s+OK/i.test(out)) {
    outputs.push("EVIDENCE: setup.php HTTP 200 OK");
  }
  if (spec.id === "p1-curl-config" && /^\d{3}$/.test(out)) {
    outputs.push(`EVIDENCE: config.inc.php HTTP ${out}`);
  }
  if ((spec.id === "p1-curl-phpinfo" || spec.id === "p1-curl-phpinfo-auth") && /^\d{3}$/.test(out)) {
    outputs.push(`EVIDENCE: phpinfo.php HTTP ${out}`);
  }
  if ((/p[123]-curl-phpini/.test(spec.id)) && (/\[PHP\]|allow_url_fopen/i.test(out) || out === "200")) {
    outputs.push("EVIDENCE: php.ini HTTP 200");
  }
  if ((/p[123]-curl-config-bak/.test(spec.id)) && (/db_password|\$_DVWA/i.test(out) || out === "200")) {
    outputs.push("EVIDENCE: config.inc.php.bak HTTP 200");
  }
  if ((spec.id === "p1-curl-vulns-index" || spec.id === "p2-curl-vulns-index") && /vulnerabilities/i.test(out)) {
    outputs.push("EVIDENCE: authenticated GET /vulnerabilities/ returned content");
  }
}

async function execDvwaLoginPost(target, cookieFile) {
  const { baseUrl } = parseTarget(target);
  const loginUrl = `${baseUrl}/login.php`;
  const get = await runCmd("curl", ["-s", "-c", cookieFile, "-b", cookieFile, loginUrl]);
  const html = get.stdout || "";
  const m = html.match(/name=['"]user_token['"][^>]*value=['"]([^'"]+)['"]/i)
    || html.match(/value=['"]([^'"]+)['"][^>]*name=['"]user_token['"]/i);
  const token = m ? m[1] : "";
  if (!token) {
    return { stdout: "", stderr: "no user_token", exit_code: 1, verdict: "error" };
  }
  return runCmd("curl", [
    "-s", "-c", cookieFile, "-b", cookieFile,
    "-e", loginUrl,
    "-X", "POST",
    "--data-urlencode", "username=admin",
    "--data-urlencode", "password=password",
    "--data-urlencode", "Login=Login",
    "--data-urlencode", `user_token=${token}`,
    "-o", "/dev/null",
    "-w", "\nDS_HTTP:%{http_code}\nDS_REDIRECT:%{redirect_url}\n",
    loginUrl,
  ]);
}

function resolveArgs(spec, playbookCtx) {
  return typeof spec.args === "function" ? spec.args(playbookCtx) : spec.args;
}

async function execSpec(spec, target, cookieFile, playbookCtx) {
  if (spec.id === "p1-login-post") {
    const result = await execDvwaLoginPost(target, cookieFile);
    return { spec, result, meaningful: isMeaningfulToolOutput(result.stdout, result.stderr) };
  }
  const resolvedArgs = resolveArgs(spec, playbookCtx);
  if (!resolvedArgs) {
    return { spec, result: { stdout: "", stderr: "", exit_code: 0, verdict: "skip" }, meaningful: false, skipped: true };
  }
  const result = await runCmd(spec.tool, resolvedArgs);
  const meaningful = isMeaningfulToolOutput(result.stdout, result.stderr);
  return { spec, result, meaningful, resolvedArgs };
}

async function main() {
  console.log("=== Test playbook DVWA ===");
  console.log("Target:", target);
  console.log("");

  const ctx = { scope: target, cookieFile: cookie };
  let playbookCtx = { ...ctx, host: new URL(target).hostname };
  const outputs = [];
  const stepRecords = [];
  const skipped = [];
  const empty = [];
  const executed = [];

  const specs = stepsForPhase(1, target, playbookCtx);

  for (const spec of specs) {
    if (spec.when) continue;
    if (typeof spec.skipIf === "function" && spec.skipIf(playbookCtx)) {
      skipped.push({ id: spec.id, reason: "skipIf" });
      continue;
    }
    const { result, meaningful, skipped: dynSkip, resolvedArgs } = await execSpec(spec, target, cookie, playbookCtx);
    if (dynSkip) { skipped.push({ id: spec.id, reason: "dynamic-args-pending" }); continue; }
    const out = result.stdout || "";
    const err = result.stderr || "";
    appendStepEvidence(spec, result, outputs);
    if (out) outputs.push(out);
    if (err) outputs.push(err);
    stepRecords.push({ id: spec.id, text: [out, err].filter(Boolean).join("\n") });
    playbookCtx = buildPlaybookContext(outputs, playbookCtx);

    executed.push({
      id: spec.id,
      tool: spec.tool,
      args: (resolvedArgs || []).join(" ").slice(0, 80),
      meaningful,
      outPreview: (out || err || "(vacío)").slice(0, 120).replace(/\n/g, " "),
    });
    if (!meaningful) empty.push(spec.id);
  }

  playbookCtx = buildPlaybookContext(outputs, playbookCtx);
  for (const spec of stepsForPhase(1, target, playbookCtx)) {
    if (spec.when) continue;
    if (executed.some((e) => e.id === spec.id)) continue;
    if (typeof spec.skipIf === "function" && spec.skipIf(playbookCtx)) {
      skipped.push({ id: spec.id, reason: "skipIf-pass2" });
      continue;
    }
    const { result, meaningful, skipped: dynSkip, resolvedArgs } = await execSpec(spec, target, cookie, playbookCtx);
    if (dynSkip) { skipped.push({ id: spec.id, reason: "dynamic-args-pending-pass2" }); continue; }
    const out = result.stdout || "";
    const err = result.stderr || "";
    appendStepEvidence(spec, result, outputs);
    if (out) outputs.push(out);
    if (err) outputs.push(err);
    stepRecords.push({ id: spec.id, text: [out, err].filter(Boolean).join("\n") });
    playbookCtx = buildPlaybookContext(outputs, playbookCtx);
    executed.push({
      id: spec.id,
      tool: spec.tool,
      args: (resolvedArgs || []).join(" ").slice(0, 80),
      meaningful,
      outPreview: (out || err || "(vacío)").slice(0, 120).replace(/\n/g, " "),
    });
  }

  // Segunda pasada (when)
  playbookCtx = buildPlaybookContext(outputs, playbookCtx);
  for (const spec of stepsForPhase(1, target, playbookCtx)) {
    if (!spec.when) continue;
    const { result, meaningful } = await execSpec(spec, target, cookie, playbookCtx);
    const out = result.stdout || "";
    if (out) outputs.push(out);
    stepRecords.push({ id: spec.id, text: out });
    executed.push({ id: spec.id, tool: spec.tool, meaningful, outPreview: out.slice(0, 80) });
    if (!meaningful) empty.push(spec.id);
  }

  const asset = heuristicAssetFromTarget(target);
  const blob = outputs.join("\n");
  const findings = collectHeuristicFindings(blob, asset, playbookCtx, stepRecords);

  console.log("--- Contexto detectado ---");
  console.log(JSON.stringify(playbookCtx, null, 2));
  console.log("");
  console.log("--- Pasos omitidos (skipIf) ---", skipped.length);
  skipped.forEach((s) => console.log(" ", s.id));
  console.log("");
  console.log("--- Pasos sin salida útil ---", empty.length);
  empty.forEach((id) => console.log(" ", id));
  console.log("");
  console.log("--- Últimos pasos ejecutados ---");
  executed.slice(-15).forEach((e) => {
    console.log(`${e.meaningful ? "✓" : "·"} ${e.id} [${e.tool}] → ${e.outPreview}`);
  });
  console.log("");
  console.log("--- Hallazgos heurísticos ---", findings.length);
  findings.forEach((f) => console.log(`  [${f.severity}] ${f.title}`));

  const falseConfig = findings.some((f) => /config\.inc\.php accesible/i.test(f.title));
  const phpinfo = findings.some((f) => /phpinfo\.php accesible/i.test(f.title));
  console.log(falseConfig ? "FAIL: config.inc.php marcado accesible pese a HTTP 404" : "OK: config.inc.php 404 no genera hallazgo");
  console.log(phpinfo ? "OK: phpinfo.php autenticado HTTP 200 genera hallazgo" : "INFO: phpinfo.php no propuesto");

  // Diagnóstico reglas que NO dispararon
  console.log("");
  console.log("--- Diagnóstico regex ---");
  const checks = [
    ["DVWA", /dvwa|damn vulnerable web application/i.test(blob)],
    ["security=low", /set-cookie:[^\n]*security=low/i.test(blob)],
    ["PHPSESSID sin HttpOnly", /set-cookie:[^\n]*phpsessid/i.test(blob) && !/httponly/i.test(blob)],
    ["Server version", /^server:\s*([^\r\n]+)/im.test(blob)],
    ["setup.php 200", /setup\.php/i.test(blob) && /HTTP\/[\d.]+\s+200\s+OK/i.test(blob)],
    ["login EVIDENCE", /EVIDENCE: login\.php POST admin\/password → HTTP 302/i.test(blob)],
    ["setup EVIDENCE", /EVIDENCE: setup\.php HTTP 200/i.test(blob)],
    ["vulnerabilities EVIDENCE", /EVIDENCE:.*vulnerabilities/i.test(blob)],
    ["solo 302 en blob", /\b302\b/.test(blob)],
    ["login.php en blob", /login\.php/i.test(blob)],
    ["password=password en blob", /password=password/i.test(blob)],
    ["vulnerabilities/", /vulnerabilities\//i.test(blob)],
  ];
  checks.forEach(([name, ok]) => console.log(`  ${ok ? "OK" : "FAIL"}: ${name}`));

  // Fase 2 (contexto persistido desde fase 1)
  console.log("");
  console.log("=== Fase 2 (ctx persistido) ===");
  const shared = { ctx: { ...playbookCtx, cookieFile: cookie, scope: target }, outputs: [...outputs], stepRecords: [...stepRecords] };
  const p2Executed = [];
  for (const spec of stepsForPhase(2, target, shared.ctx)) {
    if (spec.when) continue;
    if (typeof spec.skipIf === "function" && spec.skipIf(shared.ctx)) {
      console.log("  skip", spec.id);
      continue;
    }
    const { result, meaningful } = await execSpec(spec, target, cookie, shared.ctx);
    const out = result.stdout || "";
    const err = result.stderr || "";
    if (out) shared.outputs.push(out);
    shared.stepRecords.push({ id: spec.id, text: [out, err].filter(Boolean).join("\n") });
    shared.ctx = buildPlaybookContext(shared.outputs, shared.ctx);
    p2Executed.push({ id: spec.id, meaningful, preview: (out || result.stderr || "").slice(0, 80) });
  }
  const p2Findings = collectHeuristicFindings(shared.outputs.join("\n"), asset, shared.ctx, shared.stepRecords);
  console.log("Pasos fase 2:", p2Executed.length, "| isDvwa:", shared.ctx.isDvwa);
  p2Executed.forEach((e) => console.log(`  ${e.meaningful ? "✓" : "·"} ${e.id} → ${e.preview}`));
  console.log("Hallazgos extra fase 2:", p2Findings.length);
  p2Findings.forEach((f) => console.log(`  [${f.severity}] ${f.title}`));

  // --- Test unitario de aislamiento por-paso (anti falso-positivo) ---
  // Objetivo: probar que un patrón de confirmación que aparece en OTRA
  // respuesta (decoy) no dispara el hallazgo si el paso propio de esa ruta
  // no lo confirma, y que sí lo dispara cuando el paso propio es real.
  console.log("");
  console.log("=== Test unitario: aislamiento por-paso ===");
  let unitFail = false;

  function check(label, ok, isFail) {
    console.log(`  ${ok ? "OK" : "FAIL"}: ${label}`);
    if (!ok && isFail !== false) unitFail = true;
  }

  const decoyBlob = [
    "HTTP/1.1 404 Not Found",
    "un comentario de deploy menciona ref: refs/heads/main sin relación con .git",
  ].join("\n");
  const decoyRecords = [
    { id: "p1-exposure-git-head", text: "HTTP/1.1 404 Not Found" },
    { id: "p1-osint-curl-root", text: "un comentario de deploy menciona ref: refs/heads/main sin relación con .git" },
  ];
  const decoyFindings = collectHeuristicFindings(decoyBlob, asset, {}, decoyRecords);
  check(
    "decoy en el blob (otra respuesta) NO marca .git expuesto si el paso propio dio 404",
    !decoyFindings.some((f) => /Repositorio \.git expuesto/i.test(f.title)),
  );

  const realRecords = [{ id: "p1-exposure-git-head", text: "ref: refs/heads/main\n" }];
  const realFindings = collectHeuristicFindings("ref: refs/heads/main", asset, {}, realRecords);
  check(
    ".git/HEAD real (su propio paso) SÍ marca el hallazgo",
    realFindings.some((f) => /Repositorio \.git expuesto/i.test(f.title)),
  );

  const legacyFindings = collectHeuristicFindings("ref: refs/heads/main", asset, {});
  check(
    "sin stepRecords (compat hacia atrás) sigue funcionando por blob",
    legacyFindings.some((f) => /Repositorio \.git expuesto/i.test(f.title)),
  );

  const dvwaDecoyBlob = '<a href="/vulnerabilities/sqli/">SQL Injection</a>';
  const dvwaDecoyRecords = [
    { id: "p2-dvwa-sqli", text: "<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10</title>" },
  ];
  const dvwaDecoyFindings = collectHeuristicFindings(dvwaDecoyBlob, asset, { isDvwa: true }, dvwaDecoyRecords);
  check(
    "nav link a /vulnerabilities/sqli/ en el blob NO confirma el módulo si el paso propio redirigió a login",
    !dvwaDecoyFindings.some((f) => /Módulo SQL Injection \(DVWA\) accesible/i.test(f.title)),
  );

  const dvwaRealRecords = [
    { id: "p2-dvwa-sqli", text: "<title>Vulnerability: SQL Injection :: DVWA</title><p>mysql_fetch reachable</p>" },
  ];
  const dvwaRealFindings = collectHeuristicFindings("", asset, { isDvwa: true }, dvwaRealRecords);
  check(
    "módulo SQLi confirmado con la respuesta real de su propio paso",
    dvwaRealFindings.some((f) => /Módulo SQL Injection \(DVWA\) accesible/i.test(f.title)),
  );

  // Regresión: dos sondas que comparten el MISMO patrón de confirmación
  // (p. ej. "listado de directorio" en /ftp/ y /backup/) no deben marcar
  // la segunda como confirmada solo porque la primera YA corrió y su texto
  // quedó en el blob acumulado — las heurísticas se reevalúan tras CADA
  // paso, así que a mitad de fase el blob tiene contenido de sondas que
  // SÍ corrieron pero no de las que faltan.
  const raceBlob = "<title>listing directory /ftp/</title>";
  const raceRecordsPartial = [
    { id: "p1-api-dir-ftp", text: "<title>listing directory /ftp/</title>" },
    // dir-backup TODAVÍA no corrió: sin registro propio.
  ];
  const raceFindingsPartial = collectHeuristicFindings(raceBlob, asset, {}, raceRecordsPartial);
  check(
    "sonda /backup/ (aún sin correr) NO se confirma por el texto de /ftp/ ya en el blob",
    !raceFindingsPartial.some((f) => /Directorio \/backup\/ listable/i.test(f.title)),
  );
  check(
    "sonda /ftp/ (su propio paso real) SÍ se confirma",
    raceFindingsPartial.some((f) => /Directorio \/ftp\/ listable/i.test(f.title)),
  );

  // Regresión: "Aplicación DVWA expuesta" y "security=low" no deben
  // confirmar contra el blob acumulado de TODA la sesión — solo contra la
  // respuesta propia de la sonda de la raíz (head-root), con filtro de
  // página negativa y evidence_step_ids reales.
  const dvwaCrossContamBlob = "algo random dvwa mencionado en un script de terceros";
  const dvwaCrossContamRecords = [
    { id: "p1-osint-curl-head-root", text: "<title>Vantek · Tu cuenta</title>" },
  ];
  const dvwaCrossContamFindings = collectHeuristicFindings(
    dvwaCrossContamBlob,
    asset,
    {},
    dvwaCrossContamRecords,
  );
  check(
    "\"dvwa\" suelto en el blob acumulado (no en la sonda de la raíz) NO confirma \"Aplicación DVWA expuesta\"",
    !dvwaCrossContamFindings.some((f) => /Aplicación DVWA expuesta/i.test(f.title)),
  );

  const dvwaRootRealRecords = [
    { id: "p1-osint-curl-head-root", text: "<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10</title>" },
  ];
  const dvwaRootRealFindings = collectHeuristicFindings("", asset, {}, dvwaRootRealRecords);
  const dvwaRootRealFinding = dvwaRootRealFindings.find((f) => /Aplicación DVWA expuesta/i.test(f.title));
  check(
    "\"dvwa\" real en la sonda de la raíz SÍ confirma, con evidence_step_ids poblado",
    Boolean(dvwaRootRealFinding) && dvwaRootRealFinding.evidence_step_ids.length > 0,
  );

  const securityLowCrossContamRecords = [
    { id: "p1-osint-curl-head-root", text: "<title>Vantek · Tu cuenta</title>" },
  ];
  const securityLowCrossContamFindings = collectHeuristicFindings(
    "set-cookie: security=low",
    asset,
    {},
    securityLowCrossContamRecords,
  );
  check(
    "\"security=low\" en el blob acumulado (no en la sonda de la raíz) NO confirma \"DVWA con nivel de seguridad en «low»\"",
    !securityLowCrossContamFindings.some((f) => /DVWA con nivel de seguridad/i.test(f.title)),
  );

  console.log("");
  console.log(unitFail ? "RESULTADO: FAIL — hay regresiones en el aislamiento por-paso" : "RESULTADO: OK — todas las verificaciones pasaron");

  process.exit(findings.length > 0 && !unitFail ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
