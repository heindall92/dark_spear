import { askAgent } from "./ollama.js";
import { execTool, QuotaExhaustedError, proposeFinding, advancePhase, getStatus, scanSource } from "./bridge_client.js";
import { checkAndRecordAxis, peekAxisAgent } from "./axis.js";
import { stepsForPhase, buildPlaybookContext, isMeaningfulToolOutput, parseTarget, scopeRoot, isIpHost } from "./playbook.js";
import { collectHeuristicFindings, heuristicAssetFromTarget } from "./finding-heuristics.js";
import { looksLikeSourceCode, semgrepFindings, guessSourceExtension } from "./vuln-kb.js";
import { addStep, getSteps } from "./db.js";

export const DANGEROUS_TOOLS = new Set([
  "secretsdump.py", "secretsdump",
  "ntdsutil",
  "dcsync",
  "hashcat",
  "hydra",
  "crackmapexec", "netexec",
  "ntlmrelayx.py",
  "ticketer.py",
]);

// Denylist-by-binary-name alone is bypassable (e.g. crackmapexec/netexec
// can dump credentials via modules, not just their base name) — also gate
// on argument patterns that indicate a destructive/credential-dumping
// action regardless of which tool carries it.
const DANGEROUS_ARG_PATTERNS = [
  /--sam\b/i, /--lsa\b/i, /--ntds\b/i, /--dcsync\b/i,
  /mimikatz/i, /-M\s*mimikatz/i, /secretsdump/i,
];

// Mirrors bridge.py's PHASE_TOOLS/PHASE_NAMES by hand (same convention as
// ALLOWED_TOOLS_HINT in ollama.js) — this is a PROMPT HINT only, never
// enforcement. The server is the only thing that actually blocks a
// phase-locked tool; this just cuts down on wasted rejected attempts.
export const PHASE_NAMES = {
  1: "Intelligence Gathering",
  2: "Enumeration & Vulnerability Analysis",
  3: "Exploitation",
  4: "Post-Exploitation",
};

const PHASE_TOOLS = {
  1: ["nmap", "whatweb", "wafw00f", "subfinder", "httpx", "cloud_enum", "testssl.sh", "semgrep", "dig", "nslookup", "dnsrecon", "ldapsearch",
      "enum4linux", "rpcclient", "smbclient", "netexec", "echo", "curl", "ufw", "iptables", "nft"],
  2: ["gobuster", "ffuf", "feroxbuster", "nikto", "wpscan", "nuclei", "katana", "wapiti", "arjun", "dalfox", "GetNPUsers.py",
      "GetUserSPNs.py", "bloodhound-python", "lookupsid.py", "samrdump.py",
      "searchsploit", "adscan", "certipy", "findDelegation.py"],
  3: ["sqlmap", "hydra", "secretsdump.py", "wmiexec.py", "psexec.py",
      "smbexec.py", "atexec.py", "dcomexec.py", "mssqlclient.py",
      "ntlmrelayx.py", "crackmapexec", "netexec", "ticketer.py",
      "getST.py", "raiseChild.py"],
  4: ["hashcat", "john"],
};

export function cumulativePhaseTools(phase) {
  const result = new Set();
  for (let n = 1; n <= phase; n += 1) {
    for (const tool of PHASE_TOOLS[n] || []) result.add(tool);
  }
  return result;
}

function isDangerous(tool, args) {
  if (DANGEROUS_TOOLS.has(tool)) return true;
  const joined = (args || []).join(" ");
  return DANGEROUS_ARG_PATTERNS.some((re) => re.test(joined));
}

function findingFingerprint(title, asset) {
  const blob = `${title || ""} ${asset || ""}`.toLowerCase();
  if ((/cookie|session/.test(blob)) && /security|httponly|secure|low/.test(blob)) {
    return `cookie-session:${(asset || "").toLowerCase()}`;
  }
  const words = blob.replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/)
    .filter((w) => w.length > 3)
    .sort()
    .slice(0, 6);
  if (words.length) return words.join("-");
  return blob.slice(0, 48) || "finding";
}

function parseCurlMeta(stdout) {
  const out = String(stdout ?? "");
  const code = (out.match(/DS_HTTP:(\d{3})/) || out.match(/^(\d{3})\s*$/m) || [])[1] || "";
  const redir = (out.match(/DS_REDIRECT:([^\n]*)/) || [])[1] || "";
  return { out: out.trim(), code, redir: redir.trim() };
}

function loginRedirectIsSession(redir, out) {
  const blob = `${redir}\n${out}`;
  if (/login\.php/i.test(redir)) return false;
  return /index\.php|\/index(?:\.php)?(?:$|\?)/i.test(blob);
}

function appendStepEvidence(spec, result, outputs) {
  const { out, code, redir } = parseCurlMeta(result.stdout);
  const httpCode = code;
  if (spec.id === "p1-login-post" && httpCode === "302" && loginRedirectIsSession(redir, out)) {
    outputs.push("EVIDENCE: login.php POST admin/password → HTTP 302 index.php");
  }
  if (spec.id === "p1-login-post" && httpCode === "200") {
    outputs.push("EVIDENCE: login.php POST returned 200 (revisar CSRF/sesión)");
  }
  if (spec.id === "p1-curl-setup" && /200\s+OK/i.test(out)) {
    outputs.push("EVIDENCE: setup.php HTTP 200 OK");
  }
  if (spec.id === "p1-curl-config" && httpCode === "200" && /<\?php|\$[a-zA-Z_]\w*\s*=|_DVWA|mysqli_|PDO::/i.test(out)) {
    outputs.push(`EVIDENCE: config.inc.php HTTP ${httpCode}`);
  }
  if ((spec.id === "p1-curl-phpinfo" || spec.id === "p1-curl-phpinfo-auth" || spec.id === "p4-dvwa-phpinfo-auth") && httpCode === "200" && /phpinfo\s*\(|PHP Version/i.test(out)) {
    outputs.push(`EVIDENCE: phpinfo.php HTTP ${httpCode}`);
  }
  if ((/p[123]-curl-phpini/.test(spec.id)) && (httpCode || /\[PHP\]|allow_url_fopen/i.test(out))) {
    outputs.push(`EVIDENCE: php.ini HTTP ${httpCode || "200"}`);
  }
  if ((/p[123]-curl-config-bak/.test(spec.id)) && (httpCode || /db_password|\$_DVWA/i.test(out))) {
    outputs.push(`EVIDENCE: config.inc.php.bak HTTP ${httpCode || "200"}`);
  }
  if ((/p[123]-curl-config-dist/.test(spec.id)) && (httpCode || /\$DBMS|\$_DVWA/i.test(out))) {
    outputs.push(`EVIDENCE: config.inc.php.dist HTTP ${httpCode || "200"}`);
  }
  if ((spec.id === "p1-curl-vulns-index" || spec.id === "p2-curl-vulns-index") && /vulnerabilities/i.test(out)) {
    outputs.push("EVIDENCE: authenticated GET /vulnerabilities/ returned content");
  }
}

async function execDvwaLoginPost(target, cookieFile) {
  const { baseUrl } = parseTarget(target);
  const loginUrl = `${baseUrl}/login.php`;
  const get = await execTool("curl", ["-s", "-c", cookieFile, "-b", cookieFile, loginUrl], target);
  const html = get.stdout || "";
  const m = html.match(/name=['"]user_token['"][^>]*value=['"]([^'"]+)['"]/i)
    || html.match(/value=['"]([^'"]+)['"][^>]*name=['"]user_token['"]/i)
    || html.match(/user_token['"]\s+value=['"]([^'"]+)['"]/i);
  const token = m ? m[1] : "";
  if (!token) {
    return {
      stdout: "",
      stderr: "DVWA: no se encontró user_token en login.php (¿CSRF activo?)",
      exit_code: 1,
      verdict: "error",
    };
  }
  return execTool("curl", [
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
  ], target);
}

async function recordProposedFinding(db, engagementId, payload, seenFindings, reportedTitles, onFindingProposed, onStep, phase) {
  const fp = findingFingerprint(payload.title, payload.asset);
  if (seenFindings.has(fp)) return false;
  try {
    const finding = await proposeFinding(payload);
    seenFindings.add(fp);
    if (finding.duplicate) {
      reportedTitles.push(finding.title);
      return false;
    }
    reportedTitles.push(finding.title);
    const summary = `${finding.title} [${finding.severity}] ${finding.asset}`;
    const stepId = await addStep(db, {
      engagementId,
      tool: "(finding)",
      args: [finding.title, finding.severity, finding.id],
      output: finding.description || summary,
      stderr: "",
      exitCode: 0,
      verdict: "ok",
      phase,
    });
    onStep(normalizeStep(stepId, engagementId, {
      tool: "(finding)",
      args: [finding.title, finding.severity, finding.id],
      output: finding.description || summary,
      verdict: "ok",
      phase,
    }));
    onFindingProposed(finding);
    return true;
  } catch (err) {
    onStep(normalizeStep(null, engagementId, {
      tool: "(agent)", args: [],
      stderr: `Hallazgo no registrado (${payload.title}): ${err.message || err}`,
      verdict: "agent_error",
      phase,
    }));
    return false;
  }
}

/**
 * Cuando una sonda cualquiera filtra algo que pinta como código fuente
 * real (looksLikeSourceCode), lo manda a semgrep (análisis estático,
 * fichero temporal server-side, nunca se guarda) en vez de depender solo
 * de las firmas regex a mano de JS_CODE_DANGER_SIGNATURES. Nunca revienta
 * el flujo principal del paso si el escaneo falla — es un enriquecimiento
 * best-effort, no un paso obligatorio del playbook.
 */
async function maybeScanLeakedSource({ db, engagementId, target, phase, spec, sourceText, seenFindings, reportedTitles, onFindingProposed, onStep }) {
  try {
    const filename = `${spec.id}${guessSourceExtension(sourceText)}`;
    const result = await scanSource("semgrep", filename, sourceText, target);
    if (result.verdict && result.verdict !== "ok") return;
    const hits = semgrepFindings(result.stdout, filename);
    for (const hit of hits) {
      await recordProposedFinding(
        db, engagementId,
        { title: hit.title, asset: target, severity: hit.severity, description: hit.description, remediation: hit.remediation },
        seenFindings, reportedTitles, onFindingProposed, onStep, phase,
      );
    }
  } catch {
    // best-effort: un fallo de semgrep no debe tumbar el paso que lo disparó
  }
}

async function runHeuristicFindings(db, engagementId, target, outputs, playbookCtx, seenFindings, reportedTitles, onFindingProposed, onStep, phase, stepRecords) {
  if (!outputs.length) return;
  const asset = heuristicAssetFromTarget(target);
  const candidates = collectHeuristicFindings(outputs.join("\n"), asset, playbookCtx, stepRecords);
  for (const payload of candidates) {
    await recordProposedFinding(
      db, engagementId, payload, seenFindings, reportedTitles, onFindingProposed, onStep, phase,
    );
  }
}

function stepOutput(step) {
  if (step.verdict === "agent_error" || step.tool === "(agent)") return "";
  const out = step.output ?? step.stdout ?? "";
  return sanitizeUntrustedOutput(String(out).slice(0, 800));
}

/**
 * Wraps raw tool/HTTP output before it enters the LLM prompt. This content
 * comes from the target (a page body, a header, a file the target served)
 * and is therefore untrusted — it can contain text engineered to look like
 * a system instruction and hijack the next tool call the model picks.
 * We don't strip the content (the model/operator still needs to see it to
 * do the pentest) — we defang the two things that make injected text read
 * as an instruction instead of as inert data:
 *   1. Line-start role labels ("SYSTEM:", "ASSISTANT:", "USER:", "###
 *      Instruction:") get a zero-width marker spliced in so they no longer
 *      match at line-start for any prompt-format the model was trained on.
 *   2. The whole blob is wrapped in an explicit <untrusted-tool-output>
 *      delimiter so the system prompt's rule has something concrete to
 *      point at.
 */
export function sanitizeUntrustedOutput(text) {
  const defanged = text.replace(
    /^(\s*)(SYSTEM|ASSISTANT|USER|HUMAN|###\s*Instruction)(\s*:)/gim,
    "$1$2​$3",
  );
  return `<untrusted-tool-output>\n${defanged}\n</untrusted-tool-output>`;
}

function normalizeStep(id, engagementId, fields) {
  return {
    id,
    engagementId,
    tool: fields.tool,
    args: fields.args || [],
    output: fields.output ?? fields.stdout ?? "",
    stderr: fields.stderr ?? "",
    exitCode: fields.exitCode ?? fields.exit_code ?? 0,
    verdict: fields.verdict,
    phase: fields.phase ?? null,
  };
}

function buildUserPrompt(target, steps, axisWarning, phase, reportedTitles) {
  const history = steps
    .filter((s) => s.verdict !== "agent_error" && s.tool !== "(agent)")
    .slice(-8)
    .map((s) => `[#${s.id} ${s.tool} ${JSON.stringify(s.args)}] -> exit=${s.exitCode ?? s.exit_code} verdict=${s.verdict}\n${stepOutput(s) || "(no output)"}`)
    .join("\n---\n");
  const toolsNow = [...cumulativePhaseTools(phase)].join(", ");
  const already = reportedTitles.length
    ? `\nFindings already logged (do NOT repeat): ${reportedTitles.join("; ")}.`
    : "";
  let prompt = `Target: ${target}\nFase actual: ${phase}/4 — ${PHASE_NAMES[phase]}.\nTools disponibles ahora: ${toolsNow}.${already}\nRecent history:\n${history || "(no steps yet)"}`;
  if (axisWarning) {
    prompt += `\n\nWARNING: you already tried this same action (same URL/method/body) 3+ times with identical output. Change vector — different path, parameter, tool, or propose a finding. Do NOT repeat curl against the same endpoint.`;
  }
  return prompt;
}

function hasStepContent({ stdout, stderr, exit_code, verdict }) {
  if (verdict && verdict !== "ok") return true;
  if (exit_code != null && exit_code !== 0) return true;
  return isMeaningfulToolOutput(stdout, stderr);
}

async function runPlaybookSteps({
  db, engagementId, target, phase, onStep, doneIds, ctx = {},
  sharedState = null,
  onFindingProposed = () => {}, seenFindings = new Set(), reportedTitles = [],
}) {
  const cookieFile = (sharedState?.ctx?.cookieFile) || ctx.cookieFile || `/tmp/ds-cookies-${engagementId}.txt`;
  const { host } = parseTarget(target);
  const outputs = sharedState?.outputs ?? (sharedState ? (sharedState.outputs = []) : []);
  // Registro por-paso (spec.id -> texto de ESE paso). A diferencia de `outputs`
  // (blob acumulado, usado para señales genéricas tipo "aparece en algún
  // lado"), esto permite confirmar señales atadas a una ruta concreta
  // (módulos DVWA, sondas de exposición, CORS, TRACE) contra la respuesta
  // real de ESA petición y no contra cualquier otra salida de la fase.
  const stepRecords = sharedState?.stepRecords ?? (sharedState ? (sharedState.stepRecords = []) : []);
  let playbookCtx = buildPlaybookContext(outputs, {
    ...(sharedState?.ctx || ctx),
    cookieFile,
    host,
    scope: (sharedState?.ctx?.scope) || ctx.scope || target,
    isIpTarget: isIpHost(scopeRoot(host, (sharedState?.ctx?.scope) || ctx.scope || target)),
  });
  if (!Array.isArray(playbookCtx.previousFindingTitles) || playbookCtx.previousFindingTitles.length === 0) {
    try {
      const st = await getStatus();
      const rows = st && st.previous_scan && Array.isArray(st.previous_scan.findings)
        ? st.previous_scan.findings
        : [];
      playbookCtx.previousFindingTitles = rows.map((f) => f && f.title).filter(Boolean);
      playbookCtx.previousScanDir = (st && st.previous_scan && st.previous_scan.engagement_dir) || null;
    } catch {
      playbookCtx.previousFindingTitles = playbookCtx.previousFindingTitles || [];
    }
  }

  async function execSpec(spec) {
    if (doneIds.has(spec.id)) return null;
    if (typeof spec.skipIf === "function" && spec.skipIf(playbookCtx)) {
      // No marcar done: hasWebStack/isDvwa pueden activarse más tarde en la misma fase.
      return null;
    }
    // Algunos pasos (p. ej. seguir una ruta Disallow de robots.txt) solo
    // conocen sus args DESPUÉS de que un paso anterior corriera en esta
    // misma fase: spec.args puede ser una función del contexto actual.
    const resolvedArgs = typeof spec.args === "function" ? spec.args(playbookCtx) : spec.args;
    if (!resolvedArgs) {
      // Aún no hay datos para este paso dinámico; no marcar done por si
      // el contexto se completa más adelante en la misma fase.
      return null;
    }
    try {
      onStep(normalizeStep(null, engagementId, {
        tool: "(agent)", args: [spec.id],
        stderr: `Ejecutando ${spec.tool}…`,
        verdict: "status",
        phase,
      }));
      let result;
      if (spec.id === "p1-login-post") {
        result = await execDvwaLoginPost(target, cookieFile);
      } else if (["nikto", "gobuster", "ffuf", "feroxbuster", "wpscan", "hydra", "bloodhound-python", "katana", "wapiti", "arjun", "dalfox", "cloud_enum"].includes(spec.tool)) {
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [spec.id],
          stderr: `${spec.tool} en curso (puede tardar 1–2 min)…`,
          verdict: "status",
          phase,
        }));
        result = await execTool(spec.tool, resolvedArgs, target);
      } else {
        result = await execTool(spec.tool, resolvedArgs, target);
      }
      assertExecAllowed(result);
      await checkAndRecordAxis(db, engagementId, spec.tool, resolvedArgs, result.stdout ?? "", { agent: false });
      doneIds.add(spec.id);
      const out = result.stdout ?? "";
      const errOut = result.stderr ?? "";
      appendStepEvidence(spec, result, outputs);
      if (out) outputs.push(out);
      if (errOut) outputs.push(errOut);
      stepRecords.push({ id: spec.id, text: [out, errOut].filter(Boolean).join("\n") });
      playbookCtx = buildPlaybookContext(outputs, playbookCtx);
      if (spec.id === "p1-webauth-get" && out) {
        playbookCtx.webLoginPageHtml = out;
        if (sharedState?.ctx) sharedState.ctx.webLoginPageHtml = out;
      }
      if (looksLikeSourceCode(out)) {
        await maybeScanLeakedSource({
          db, engagementId, target, phase, spec, sourceText: out,
          seenFindings, reportedTitles, onFindingProposed, onStep,
        });
      }
      if (!hasStepContent(result)) {
        return out;
      }
      const stepId = await addStep(db, {
        engagementId, tool: spec.tool, args: resolvedArgs,
        output: result.stdout, stderr: result.stderr,
        exitCode: result.exit_code, verdict: result.verdict,
        phase,
      });
      const step = normalizeStep(stepId, engagementId, {
        tool: spec.tool, args: resolvedArgs,
        output: result.stdout, stderr: result.stderr,
        exitCode: result.exit_code, verdict: result.verdict,
        phase,
      });
      onStep(step);
      await runHeuristicFindings(
        db, engagementId, target, outputs, playbookCtx,
        seenFindings, reportedTitles, onFindingProposed, onStep, phase, stepRecords,
      );
      return out;
    } catch (err) {
      if (err instanceof QuotaExhaustedError) throw err;
      if (err instanceof AgentStoppedError) throw err;
      doneIds.add(spec.id);
      onStep(normalizeStep(null, engagementId, {
        tool: spec.tool, args: resolvedArgs,
        stderr: `Paso ${spec.id} falló: ${err.message || err}`,
        verdict: "error",
        phase,
      }));
      return null;
    }
  }

  const allSpecs = stepsForPhase(phase, target, playbookCtx);

  for (const spec of allSpecs) {
    if (spec.when) continue;
    await execSpec(spec);
  }

  playbookCtx = buildPlaybookContext(outputs, playbookCtx);
  for (const spec of stepsForPhase(phase, target, playbookCtx)) {
    if (spec.when) continue;
    await execSpec(spec);
  }

  await runHeuristicFindings(
    db, engagementId, target, outputs, playbookCtx,
    seenFindings, reportedTitles, onFindingProposed, onStep, phase, stepRecords,
  );

  playbookCtx = buildPlaybookContext(outputs, playbookCtx);

  for (const spec of stepsForPhase(phase, target, playbookCtx)) {
    if (!spec.when) continue;
    await execSpec(spec);
  }

  await runHeuristicFindings(
    db, engagementId, target, outputs, playbookCtx,
    seenFindings, reportedTitles, onFindingProposed, onStep, phase, stepRecords,
  );

  playbookCtx = buildPlaybookContext(outputs, { ...playbookCtx, emitScanDelta: true });
  await runHeuristicFindings(
    db, engagementId, target, outputs, playbookCtx,
    seenFindings, reportedTitles, onFindingProposed, onStep, phase, stepRecords,
  );

  if (sharedState) {
    sharedState.ctx = { ...playbookCtx, cookieFile };
    sharedState.outputs = outputs;
    sharedState.stepRecords = stepRecords;
  }
}

const MAX_CONSECUTIVE_AGENT_ERRORS = 5;

export class AgentStoppedError extends Error {
  constructor(reason = "stopped") {
    super(reason);
    this.name = "AgentStoppedError";
  }
}

function assertExecAllowed(result) {
  const verdict = result && result.verdict;
  if (verdict === "engagement_superseded" || verdict === "scope_violation") {
    throw new AgentStoppedError(verdict);
  }
  return result;
}

async function waitForRunControl(control) {
  if (!control || typeof control.check !== "function") return;
  while (true) {
    const state = await control.check();
    if (state === "run") return;
    if (state === "stop") throw new AgentStoppedError("finished");
    if (state === "pause") {
      if (typeof control.onPaused === "function") control.onPaused();
      await new Promise((r) => setTimeout(r, 1200));
      continue;
    }
    await new Promise((r) => setTimeout(r, 800));
  }
}

export async function runAgentLoop({ db, engagementId, model, target, scope, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {}, onFindingProposed = () => {}, phaseState, useAi = true, control = null, adDomain = "", adUser = "", adPassword = "" }) {
  let steps = await getSteps(db, engagementId);
  let axisWarning = false;
  let agentErrorHint = "";
  let reportedTitles = [];
  let consecutiveErrors = 0;
  let duplicateStreak = 0;
  const seenFindings = new Set();
  const playbookDone = new Set();
  let lastPlaybookPhase = 0;
  const playbookShared = {
    ctx: {
      scope: scope || target,
      cookieFile: `/tmp/ds-cookies-${engagementId}.txt`,
      adDomain: String(adDomain || "").trim(),
      adUser: String(adUser || "").trim(),
      adPassword: adPassword != null ? String(adPassword) : "",
    },
    outputs: [],
  };
  // Reanudación (reload de página o fase ya avanzada en el servidor): el
  // estado en memoria de este módulo nace vacío, pero puede haber pasos
  // persistidos (IndexedDB) de una corrida previa. Sin esto, ctx.isDvwa/
  // hasLogin nunca se detectan de nuevo y la fase actual ejecuta con un
  // contexto en blanco (típicamente 0 pasos si además el host es una IP).
  for (const s of steps) {
    if (s.tool === "(agent)" || s.tool === "(finding)") continue;
    const out = s.output ?? s.stdout ?? "";
    const errOut = s.stderr ?? "";
    if (out) playbookShared.outputs.push(String(out));
    if (errOut) playbookShared.outputs.push(String(errOut));
  }
  const JSON_ONLY_HINT = "\n\nJSON only: {\"tool\":\"...\",\"args\":[...]} or {\"finding\":{...}} or {\"done\":true}. No prose.";
  const MAX_PHASE = 4;

  const runPhasePlaybook = async () => {
    if (lastPlaybookPhase === phaseState.current) return;
    await runPlaybookSteps({
      db, engagementId, target, phase: phaseState.current, onStep, doneIds: playbookDone,
      sharedState: playbookShared,
      onFindingProposed, seenFindings, reportedTitles,
    });
    lastPlaybookPhase = phaseState.current;
    steps = await getSteps(db, engagementId);
  };

  // Si arrancamos ya en fase > 1 sin ningún paso previo (p. ej. la fase se
  // avanzó en el servidor antes de ejecutar nada), el contexto de recon
  // nunca se construye y la fase actual encuentra 0 pasos que hacer.
  // Recorremos las fases anteriores para levantar ese contexto real.
  if (phaseState.current > 1 && playbookShared.outputs.length === 0) {
    for (let p = 1; p < phaseState.current; p += 1) {
      await runPlaybookSteps({
        db, engagementId, target, phase: p, onStep, doneIds: playbookDone,
        sharedState: playbookShared,
        onFindingProposed, seenFindings, reportedTitles,
      });
      steps = await getSteps(db, engagementId);
    }
  }

  await runPhasePlaybook();

  /* Modo playbook: sin LLM; avanza fases automáticamente tras cada bloque PTES. */
  if (!useAi) {
    const noteId = await addStep(db, {
      engagementId, tool: "(agent)", args: [],
      output: "Modo playbook + heurísticas: recorriendo fases 1–4 automáticamente (sin IA).",
      stderr: "", exitCode: 0, verdict: "playbook_only",
      phase: phaseState.current,
    });
    onStep(normalizeStep(noteId, engagementId, {
      tool: "(agent)", args: [],
      output: "Modo playbook + heurísticas: recorriendo fases 1–4 automáticamente (sin IA).",
      verdict: "playbook_only",
      phase: phaseState.current,
    }));
    while (phaseState.current < MAX_PHASE) {
      await waitForRunControl(control);
      onStep(normalizeStep(null, engagementId, {
        tool: "(agent)", args: [],
        stderr: `Fase ${phaseState.current} completada — avanzando…`,
        verdict: "status",
        phase: phaseState.current,
      }));
      try {
        const adv = await advancePhase();
        phaseState.current = adv.phase || phaseState.current + 1;
        lastPlaybookPhase = 0;
      } catch (err) {
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: `No se pudo avanzar de fase: ${err.message || err}`,
          verdict: "agent_error",
          phase: phaseState.current,
        }));
        break;
      }
      await waitForRunControl(control);
      await runPhasePlaybook();
    }
    {
      const doneMsg = "Auditoría finalizada — playbook PTES completado (4/4).";
      const doneId = await addStep(db, {
        engagementId, tool: "(agent)", args: [],
        output: doneMsg, stderr: "", exitCode: 0, verdict: "done",
        phase: phaseState.current,
      });
      onStep(normalizeStep(doneId, engagementId, {
        tool: "(agent)", args: [],
        output: doneMsg,
        verdict: "done",
        phase: phaseState.current,
      }));
    }
    return;
  }

  while (true) {
    await waitForRunControl(control);
    await runPhasePlaybook();
    let decision;
    try {
      await waitForRunControl(control);
      onStep(normalizeStep(null, engagementId, {
        tool: "(agent)", args: [],
        stderr: `Playbook fase ${phaseState.current} listo. Esperando al modelo (o pulsa Avanzar fase).`,
        verdict: "status",
        phase: phaseState.current,
      }));
      const bumpAtStart = phaseState.bump || 0;
      const phaseAtStart = phaseState.current;
      const llm = askAgent({
        model,
        systemPrompt,
        userPrompt: buildUserPrompt(target, steps, axisWarning, phaseState.current, reportedTitles) + agentErrorHint,
        endpoint,
      }).then((d) => ({ decision: d }));
      const watch = (async () => {
        while (true) {
          await new Promise((r) => setTimeout(r, 400));
          if ((phaseState.bump || 0) !== bumpAtStart || phaseState.current !== phaseAtStart) {
            return { phaseChanged: true };
          }
        }
      })();
      const winner = await Promise.race([llm, watch]);
      if (winner.phaseChanged) {
        lastPlaybookPhase = 0;
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: `Fase cambiada a ${phaseState.current} — ejecutando playbook…`,
          verdict: "status",
          phase: phaseState.current,
        }));
        continue;
      }
      decision = winner.decision;
    } catch (err) {
      if (err instanceof QuotaExhaustedError) {
        const stepId = await addStep(db, {
          engagementId, tool: "(agent)", args: [],
          output: "", stderr: `all API keys exhausted, retry in ~${Math.ceil(err.retryAfterHint / 60)}min`,
          exitCode: -1, verdict: "waiting_for_quota",
          phase: phaseState.current,
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: "(agent)", args: [],
          stderr: `all API keys exhausted, retry in ~${Math.ceil(err.retryAfterHint / 60)}min`,
          verdict: "waiting_for_quota",
          phase: phaseState.current,
        });
        steps = [...steps, step];
        onStep(step);
        onWaitingForQuota(err.retryAfterHint);
        const waitMs = Math.max(0, Math.min(err.retryAfterHint, 300)) * 1000;
        await new Promise((resolve) => setTimeout(resolve, waitMs));
        continue;
      }
      consecutiveErrors += 1;
      agentErrorHint = JSON_ONLY_HINT;
      if (consecutiveErrors >= MAX_CONSECUTIVE_AGENT_ERRORS) {
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: "El modelo no devolvió JSON válido. Revisa el modelo y reinicia el engagement.",
          verdict: "agent_error",
          phase: phaseState.current,
        }));
        return;
      }
      continue;
    }
    consecutiveErrors = 0;
    agentErrorHint = "";

    if (decision.done) {
      if (phaseState.current < MAX_PHASE) {
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: "El modelo marcó done; el playbook continúa hasta fase 4.",
          verdict: "status",
          phase: phaseState.current,
        }));
        try {
          const adv = await advancePhase();
          phaseState.current = adv.phase || phaseState.current + 1;
          lastPlaybookPhase = 0;
        } catch (err) {
          onStep(normalizeStep(null, engagementId, {
            tool: "(agent)", args: [],
            stderr: `No se pudo avanzar de fase: ${err.message || err}`,
            verdict: "agent_error",
            phase: phaseState.current,
          }));
          return;
        }
        continue;
      }
      {
        const doneMsg = decision.reasoning || "Auditoría finalizada — playbook PTES completado (4/4).";
        const doneId = await addStep(db, {
          engagementId, tool: "(agent)", args: [],
          output: doneMsg, stderr: "", exitCode: 0, verdict: "done",
          phase: phaseState.current,
        });
        onStep(normalizeStep(doneId, engagementId, {
          tool: "(agent)", args: [],
          output: doneMsg,
          verdict: "done",
          phase: phaseState.current,
        }));
      }
      return;
    }

    if (decision.finding) {
      const fp = findingFingerprint(decision.finding.title, decision.finding.asset);
      if (seenFindings.has(fp)) {
        duplicateStreak += 1;
        agentErrorHint = `\n\nFinding already logged. Do not repeat it. Next: a different finding, a tool JSON, or {"done":true}.`;
        if (duplicateStreak >= 12) return;
        continue;
      }
      const ok = await recordProposedFinding(
        db, engagementId, decision.finding, seenFindings, reportedTitles, onFindingProposed, onStep, phaseState.current,
      );
      if (!ok) {
        consecutiveErrors += 1;
        agentErrorHint = JSON_ONLY_HINT;
        if (consecutiveErrors >= MAX_CONSECUTIVE_AGENT_ERRORS) return;
        continue;
      }
      duplicateStreak = 0;
      steps = await getSteps(db, engagementId);
      consecutiveErrors = 0;
      agentErrorHint = "\n\nFinding saved. Next JSON: a different finding or a tool. No prose.";
      continue;
    }

    if (isDangerous(decision.tool, decision.args)) {
      const approved = await new Promise((resolve) => onPauseForConfirmation(decision, resolve));
      if (!approved) {
        const stepId = await addStep(db, {
          engagementId, tool: decision.tool, args: decision.args,
          output: "", stderr: "rejected by operator", exitCode: -1, verdict: "rejected",
          phase: phaseState.current,
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: decision.tool, args: decision.args,
          stderr: "rejected by operator", verdict: "rejected",
          phase: phaseState.current,
        });
        steps = [...steps, step];
        onStep(step);
        continue;
      }
    }

    try {
      const prior = await peekAxisAgent(db, engagementId, decision.tool, decision.args);
      if (prior && prior.agentAttemptCount >= 5) {
        axisWarning = true;
        agentErrorHint = "\n\nBLOCKED (silent): esa URL/comando ya se repitió varias veces. Revisa el historial del playbook, elige otro módulo (/vulnerabilities/sqli/, /xss_r/, etc.), propone un hallazgo, o {\"done\":true}. No repitas curl a /, /login.php, /robots.txt, /index.php.";
        continue;
      }

      const result = await execTool(decision.tool, decision.args, target, "agent");
      assertExecAllowed(result);
      const axisResult = await checkAndRecordAxis(db, engagementId, decision.tool, decision.args, result.stdout ?? "", { agent: true });
      axisWarning = axisResult.warn || axisResult.blocked;
      if (hasStepContent(result)) {
        const stepId = await addStep(db, {
          engagementId, tool: decision.tool, args: decision.args,
          output: result.stdout, stderr: result.stderr,
          exitCode: result.exit_code, verdict: result.verdict,
          phase: phaseState.current,
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: decision.tool, args: decision.args,
          output: result.stdout, stderr: result.stderr,
          exitCode: result.exit_code, verdict: result.verdict,
          phase: phaseState.current,
        });
        steps = [...steps, step];
        onStep(step);
      }
      if (result.verdict === "phase_locked") {
        agentErrorHint = `\n\nFase ${phaseState.current}: ${decision.tool} bloqueado. Pulsa «Avanzar fase» en el panel o elige otra herramienta de la fase actual.`;
      } else if (axisResult.blocked) {
        agentErrorHint = "\n\nBLOCKED: petición repetida. Cambia de vector o propone un hallazgo con la evidencia existente.";
      }
      duplicateStreak = 0;
    } catch (err) {
      if (err instanceof QuotaExhaustedError) throw err;
      const stepId = await addStep(db, {
        engagementId, tool: decision.tool, args: decision.args,
        output: "", stderr: err.message, exitCode: -1, verdict: "error",
        phase: phaseState.current,
      });
      const step = normalizeStep(stepId, engagementId, {
        tool: decision.tool, args: decision.args,
        stderr: err.message, verdict: "error",
        phase: phaseState.current,
      });
      steps = [...steps, step];
      onStep(step);
    }
  }
}
