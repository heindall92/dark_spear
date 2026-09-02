const ENGINE_DEFAULT = "http://127.0.0.1:8420";
const OLLAMA_CHAT_ENDPOINT = "https://ollama.com/v1/chat/completions";
const ENGINE_JS = new URL("./engine/js/", import.meta.url);
const TOKEN_KEY = "ds-engine-token";
const URL_KEY = "ds-engine-url";
const RUN_KEY = "ds-engine-run";
const MODEL_KEY = "ds-engine-model";
const ENGAGEMENT_ID_KEY = "ds-engagement-id";
const AGENT_HEARTBEAT_KEY = "ds-agent-heartbeat";
const AGENT_OWNER_KEY = "ds-agent-owner";

function engineBase() {
  if (typeof window !== "undefined") {
    const port = window.location.port;
    if (port === "8080" || port === "8081") {
      return `${window.location.origin}/bridge`;
    }
  }
  return sessionStorage.getItem(URL_KEY) || ENGINE_DEFAULT;
}

function loadRunFromStorage() {
  try {
    return JSON.parse(sessionStorage.getItem(RUN_KEY) || "null");
  } catch {
    return null;
  }
}

function saveRunToStorage(run) {
  if (!run) return;
  sessionStorage.setItem(RUN_KEY, JSON.stringify(run));
  if (run.model) sessionStorage.setItem(MODEL_KEY, run.model);
}

function getTabId() {
  let id = sessionStorage.getItem("ds-tab-id");
  if (!id) {
    id = Math.random().toString(36).slice(2, 10);
    sessionStorage.setItem("ds-tab-id", id);
  }
  return id;
}

function isAgentRunningElsewhere() {
  const hb = parseInt(localStorage.getItem(AGENT_HEARTBEAT_KEY) || "0", 10);
  const owner = localStorage.getItem(AGENT_OWNER_KEY);
  return Date.now() - hb < 12000 && owner && owner !== getTabId();
}

function claimAgentOwnership() {
  localStorage.setItem(AGENT_OWNER_KEY, getTabId());
  localStorage.setItem(AGENT_HEARTBEAT_KEY, String(Date.now()));
  if (window._agentHeartbeatTimer) clearInterval(window._agentHeartbeatTimer);
  window._agentHeartbeatTimer = setInterval(() => {
    localStorage.setItem(AGENT_HEARTBEAT_KEY, String(Date.now()));
  }, 3000);
}

function releaseAgentOwnership() {
  if (window._agentHeartbeatTimer) {
    clearInterval(window._agentHeartbeatTimer);
    window._agentHeartbeatTimer = null;
  }
  if (localStorage.getItem(AGENT_OWNER_KEY) === getTabId()) {
    localStorage.removeItem(AGENT_OWNER_KEY);
    localStorage.removeItem(AGENT_HEARTBEAT_KEY);
  }
}

function dbStepToFeedStep(s) {
  return {
    tool: s.tool,
    args: s.args,
    output: s.output,
    stdout: s.output,
    stderr: s.stderr,
    verdict: s.verdict,
    exit_code: s.exitCode,
    phase: s.phase,
  };
}

async function resolveRunFromBridge(api, existingRun) {
  let status = { active: false };
  try {
    status = await api.bridge.getStatus();
  } catch {
    /* bridge down */
  }
  let run = existingRun;
  if (status.active) {
    const existingDir = existingRun?.engagementDir || "";
    const statusDir = status.engagement_dir || "";
    if (existingDir && statusDir && existingDir !== statusDir) {
      return { run: existingRun, status, motorTaken: true };
    }
    run = {
      name: status.name || existingRun?.name || "",
      objective: status.objective || existingRun?.objective || status.name || "",
      target: status.target,
      scope: status.scope || existingRun?.scope || status.target,
      model: existingRun?.model || sessionStorage.getItem(MODEL_KEY) || "",
      useAi: status.use_ai != null ? !!status.use_ai : (existingRun?.useAi !== false),
      engagementDir: status.engagement_dir || existingRun?.engagementDir || sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "",
    };
    saveRunToStorage(run);
    if (run.engagementDir) sessionStorage.setItem(ENGAGEMENT_ID_KEY, run.engagementDir);
  }
  return { run, status };
}

function syncFindingsToInbox(findings) {
  if (!window.DarkSpearFindings || !Array.isArray(findings)) return;
  findings.forEach((f) => {
    if (f && f.title && f.status !== "rejected") DarkSpearFindings.push(f);
  });
}

function pageName() {
  return (location.pathname.split("/").pop() || "").toLowerCase();
}

function banner(el, msg, isError) {
  if (!el) return;
  el.hidden = false;
  el.textContent = msg;
  el.classList.add("whitespace-pre-wrap", "break-words", "leading-relaxed");
  el.classList.toggle("border-error", !!isError);
  el.classList.toggle("bg-error-container", !!isError);
  el.classList.toggle("text-on-error-container", !!isError);
  el.classList.toggle("border-outline-variant/40", !isError);
  el.classList.toggle("bg-surface-container-low", !isError);
  el.classList.toggle("text-on-surface", !isError);
}

async function callEngagementControl(api, action, engId) {
  const method = `${action}Engagement`;
  if (api?.bridge && typeof api.bridge[method] === "function") {
    return api.bridge[method](engId || "");
  }
  const token = sessionStorage.getItem(TOKEN_KEY) || "";
  const res = await fetch(`${engineBase()}/engagements/${action}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-Auditor-Token": token } : {}),
    },
    body: JSON.stringify(engId ? { engagement_dir: engId } : {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function syncScanControlButtons({ paused, finished, active }) {
  const pauseBtn = document.getElementById("pause-scan-btn");
  const resumeBtn = document.getElementById("resume-scan-btn");
  const finishBtn = document.getElementById("finish-scan-btn");
  const advanceBtn = document.getElementById("advance-phase-btn");
  const on = active !== false && !finished;
  if (pauseBtn) pauseBtn.hidden = !on || !!paused;
  if (resumeBtn) resumeBtn.hidden = !on || !paused;
  if (finishBtn) finishBtn.hidden = !on;
  if (advanceBtn) advanceBtn.disabled = !!paused || !on;
}

async function bridgeAlive(base) {
  try {
    const res = await fetch(`${base}/session`, { method: "GET", mode: "cors", cache: "no-store" });
    if (res.ok) return true;
    const res2 = await fetch(`${base}/`, { method: "GET", mode: "cors", cache: "no-store" });
    return res2.ok;
  } catch {
    return false;
  }
}

async function verifyOllamaKeyDirect(apiKey) {
  const res = await fetch(`${window.location.origin}/api/verify-ollama-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (!res.ok) {
    if (data.error === "invalid_api_key") throw new Error("invalid_api_key");
    throw new Error(data.detail || data.error || `verify_error_${res.status}`);
  }
  return data;
}

async function loadEngine() {
  let build = String(Date.now());
  try {
    const res = await fetch(new URL("./engine/BUILD", import.meta.url), { cache: "no-store" });
    if (res.ok) build = (await res.text()).trim() || build;
  } catch {
    /* BUILD opcional */
  }
  const base = new URL("./", ENGINE_JS);
  const q = (name) => new URL(`${name}?v=${encodeURIComponent(build)}`, base);
  const [bridge, agent, db] = await Promise.all([
    import(q("bridge_client.js")),
    import(q("agent.js")),
    import(q("db.js")),
  ]);
  bridge.setBridgeUrl(engineBase());
  if (typeof window !== "undefined") window.__DS_ENGINE_BUILD = build;
  return { bridge, agent, db, build };
}

function t(key, fallback) {
  if (typeof window !== "undefined" && window.DarkSpear?.t) {
    const value = window.DarkSpear.t(key);
    return value !== key ? value : fallback;
  }
  return fallback;
}

function populateModelSelect(select, models, previous) {
  if (!select) return;
  select.innerHTML = "";
  if (!models?.length) {
    select.innerHTML = `<option value="">${t("start.modelsEmpty", "Sin modelos disponibles")}</option>`;
    select.disabled = true;
    return;
  }
  for (const id of models) {
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = id;
    select.appendChild(opt);
  }
  if (previous && models.includes(previous)) select.value = previous;
  else if (models.includes("gpt-oss:20b")) select.value = "gpt-oss:20b";
  else select.selectedIndex = 0;
  select.disabled = false;
}

const FIELD_ERROR_CLASS = "border-error ring-1 ring-error/40";
const FIELD_ERROR_TOKENS = FIELD_ERROR_CLASS.split(" ");

function clearFieldErrors(fields) {
  for (const el of fields) {
    el?.classList.remove(...FIELD_ERROR_TOKENS);
  }
}

function collectStartValidation(hasKeys, nameInput, targetInput, scopeInput, modelInput, useAi) {
  const missing = [];
  if (!nameInput?.value.trim()) {
    missing.push({ label: t("start.missingName", "Nombre / objetivo"), el: nameInput });
  }
  if (!targetInput.value.trim()) {
    missing.push({ label: t("start.missingTarget", "Target"), el: targetInput });
  }
  if (!scopeInput.value.trim()) {
    missing.push({ label: t("start.missingScope", "Scope"), el: scopeInput });
  }
  if (useAi) {
    if (!hasKeys) {
      missing.push({ label: t("start.missingKeySelect", "Agrega y selecciona al menos una API key") });
    }
    if (!modelInput.value.trim()) {
      missing.push({ label: t("start.missingModel", "Modelo"), el: modelInput });
    }
  }
  return missing;
}

function showModalById(id) {
  const modal = document.getElementById(id);
  if (!modal) return () => {};
  modal.classList.add("flex");
  modal.removeAttribute("hidden");
  if (window.lucide) lucide.createIcons();
  return () => {
    modal.classList.remove("flex");
    modal.setAttribute("hidden", "");
  };
}

function showAiTokenModal() {
  return new Promise((resolve) => {
    const modal = document.getElementById("start-ai-token-modal");
    const confirmBtn = document.getElementById("start-ai-token-confirm");
    const cancelBtn = document.getElementById("start-ai-token-cancel");
    if (!modal || !confirmBtn || !cancelBtn) {
      resolve(true);
      return;
    }
    const close = showModalById("start-ai-token-modal");
    const finish = (ok) => {
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      modal.onclick = null;
      close();
      resolve(ok);
    };
    confirmBtn.onclick = () => finish(true);
    cancelBtn.onclick = () => finish(false);
    modal.onclick = (e) => { if (e.target === modal) finish(false); };
  });
}

function showValidationModal(missing) {
  const modal = document.getElementById("start-validation-modal");
  const list = document.getElementById("start-validation-list");
  const closeBtn = document.getElementById("start-validation-close");
  if (!modal || !list) return;
  list.innerHTML = "";
  for (const item of missing) {
    const li = document.createElement("li");
    li.textContent = item.label;
    list.appendChild(li);
    item.el?.classList.add(...FIELD_ERROR_TOKENS);
  }
  modal.classList.add("flex");
  modal.removeAttribute("hidden");
  modal.style.display = "flex";
  const close = () => {
    modal.classList.remove("flex");
    modal.setAttribute("hidden", "");
    modal.style.display = "";
    closeBtn.onclick = null;
    modal.onclick = null;
  };
  closeBtn.onclick = close;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  if (window.lucide) lucide.createIcons();
}

async function loadModels(api, note) {
  const select = document.getElementById("model");
  const hint = document.getElementById("model-hint");
  if (!select) return [];
  const previous = select.value;
  select.disabled = true;
  select.innerHTML = `<option value="">${t("start.modelsLoading", "Cargando modelos…")}</option>`;
  if (hint) hint.hidden = true;

  try {
    const data = await api.bridge.listModels(OLLAMA_CHAT_ENDPOINT);
    const models = Array.isArray(data.models) ? data.models : [];
    populateModelSelect(select, models, previous);
    if (!models.length && hint) {
      hint.textContent = t("start.modelsNeedKey", "Agrega y verifica una API key de Ollama Cloud.");
      hint.hidden = false;
    }
    return models;
  } catch (err) {
    const msg = String(err.message || err);
    select.innerHTML = `<option value="">${t("start.modelsError", "Error al cargar modelos")}</option>`;
    select.disabled = true;
    if (hint) {
      hint.textContent = msg.includes("no_keys_for_models")
        ? t("start.modelsNeedKey", "Agrega y verifica una API key de Ollama Cloud.")
        : msg.replace(/^bridge_error_\d+:\s*/, "");
      hint.hidden = false;
    }
    return [];
  }
}

async function ensureSession(api) {
  const params = new URLSearchParams(location.search);
  const fromUrl = params.get("token");
  if (fromUrl) {
    api.bridge.setSessionToken(fromUrl);
    sessionStorage.setItem(TOKEN_KEY, fromUrl);
    return fromUrl;
  }
  const cached = sessionStorage.getItem(TOKEN_KEY);
  if (cached) {
    api.bridge.setSessionToken(cached);
    try {
      await api.bridge.listKeys();
      return cached;
    } catch {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  }
  const data = await api.bridge.fetchSession();
  sessionStorage.setItem(TOKEN_KEY, data.token);
  return data.token;
}

async function ensureBridge(note) {
  const base = engineBase();
  if (await bridgeAlive(base)) return true;
  banner(
    note,
    "El motor no está corriendo. En otra terminal: cd ~/dark_spear/backend && python3 bridge.py — luego recarga esta página.",
    true,
  );
  return false;
}

function toolIcon(tool, verdict) {
  if (verdict === "agent_error" || verdict === "error") return "circle-alert";
  if (verdict === "timeout" || verdict === "waiting_for_quota") return "hourglass";
  if (verdict === "rejected") return "ban";
  if (tool === "nmap") return "network";
  if (tool === "curl") return "globe";
  if (tool === "whatweb") return "scan-search";
  if (tool === "gobuster" || tool === "ffuf") return "folder-search";
  if (tool === "nikto") return "bug";
  if (tool === "(agent)") return "bot";
  return "terminal";
}

function verdictStyle(verdict) {
  if (verdict === "ok") return "bg-tertiary-container/10 text-tertiary-container border-tertiary-container/20";
  if (verdict === "agent_error" || verdict === "error") return "bg-error-container text-error border-error/20";
  if (verdict === "timeout" || verdict === "waiting_for_quota") return "bg-primary-fixed text-on-primary-fixed border-primary-fixed-dim";
  if (verdict === "rejected" || verdict === "scope_violation" || verdict === "phase_locked" || verdict === "axis_blocked") {
    return "bg-error-container text-error border-error/20";
  }
  return "bg-surface-variant text-on-surface-variant border-outline-variant/30";
}

function renderPhaseBar(phase) {
  const fill = document.getElementById("phase-fill");
  const pct = Math.max(0, Math.min(1, (Number(phase) - 1) / 3));
  if (fill) fill.style.width = `${pct * 100}%`;
  const icons = { 1: "radar", 2: "search", 3: "unplug", 4: "flag" };
  document.querySelectorAll("[data-phase-step]").forEach((el) => {
    const n = Number(el.getAttribute("data-phase-step"));
    const iconWrap = el.querySelector("[data-phase-icon]");
    const label = el.querySelector("[data-phase-label]");
    const glyph = icons[n] || "circle";
    if (n < phase) {
      iconWrap.className = "rounded-full bg-tertiary-container text-on-tertiary-container flex items-center justify-center border-2 border-surface shadow-sm";
      iconWrap.innerHTML = '<i data-lucide="check" class="icon-sm"></i>';
      if (label) label.className = "font-label-md text-label-md text-on-surface";
    } else if (n === phase) {
      iconWrap.className = "rounded-full bg-primary-container text-on-primary-container flex items-center justify-center border-2 border-primary-fixed shadow-md ring-4 ring-primary-container/20";
      iconWrap.innerHTML = `<i data-lucide="${glyph}" class="icon-sm"></i>`;
      if (label) label.className = "font-label-md text-label-md text-primary-container font-bold";
    } else {
      iconWrap.className = "rounded-full bg-surface-variant text-outline flex items-center justify-center border-2 border-surface";
      iconWrap.innerHTML = `<i data-lucide="${glyph}" class="icon-sm"></i>`;
      if (label) label.className = "font-label-md text-label-md text-outline";
    }
  });
  if (window.lucide) lucide.createIcons();
}

const feedState = { tool: "all", search: "", hideNoise: true, steps: [] };

function stepCategory(step) {
  const tool = String(step.tool || "");
  const args = (step.args || []).join(" ").toLowerCase();
  if (tool === "(finding)") return "findings";
  if (["axis_blocked", "phase_locked", "agent_error"].includes(step.verdict)) return "noise";
  if (["nmap", "whatweb", "dig", "dnsrecon", "nslookup"].includes(tool)) return "recon";
  if (["gobuster", "ffuf", "feroxbuster", "nikto", "wpscan"].includes(tool)) return "enum";
  if (["sqlmap", "hydra"].includes(tool)) return "exploit";
  if (tool === "curl") {
    if (/vulnerabilities|sqli|xss|brute|exec|upload|csrf/.test(args)) return "exploit";
    return "recon";
  }
  return "other";
}

function stepDetailText(step) {
  return [step.output, step.stdout, step.stderr]
    .filter((s) => s != null && String(s).trim())
    .join("\n")
    .trim();
}

// Narración transitoria del agente ("Ejecutando nmap…", "Fase completada — avanzando…"):
// no trae resultado propio, es ruido de proceso y no debe ocupar una tarjeta en el feed.
const AGENT_NOISE_VERDICTS = new Set(["status"]);

function isMeaningfulOutput(text) {
  const t = String(text || "").trim();
  if (!t) return false;
  if (/^0+$/.test(t.replace(/\s/g, ""))) return false;
  return true;
}

/** Solo mostrar pasos con salida útil, hallazgos o eventos relevantes (errores, pausa, etc.). */
function isIpOsintNoise(step) {
  const args = (step.args || []).join(" ");
  const tool = String(step.tool || "");
  const text = stepDetailText(step);
  const lastArg = args.trim().split(/\s+/).pop() || "";
  if (["nslookup", "dig", "dnsrecon"].includes(tool) && /^\d{1,3}(\.\d{1,3}){3}$/.test(lastArg)) return true;
  if (/rdap\.org\/domain\/\d/.test(args)) return true;
  if (/crt\.sh\//.test(args) && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(args)) return true;
  if (/https:\/\/(www|mail|vpn|dev|api|staging)\.\d+\.\d+\.\d+\.\d+/.test(args)) return true;
  if (tool === "nmap" && /ssl-cert/.test(args) && /-p\s*443/.test(args) && /closed/i.test(text) && !/\bopen\b/i.test(text)) return true;
  if (/404 Not Found/i.test(text) && /Apache\/[\d.]+.*Server at/i.test(text) && text.length < 800) return true;
  if (/502 Bad Gateway/i.test(text) && /nginx/i.test(text) && text.length < 500) return true;
  return false;
}

/** Solo se muestran tarjetas con un resultado real (hallazgo, salida, error con mensaje).
 * Las tarjetas con info en blanco se consideran ruido y se descartan del feed. */
function shouldShowStepInFeed(step) {
  if (step.tool === "(finding)") return true;
  const verdict = step.verdict || "";
  if (step.tool === "(agent)" && AGENT_NOISE_VERDICTS.has(verdict)) return false;
  if (isIpOsintNoise(step)) return false;
  return isMeaningfulOutput(stepDetailText(step));
}

function matchesFeedFilter(step) {
  if (!shouldShowStepInFeed(step)) return false;
  if (feedState.hideNoise && stepCategory(step) === "noise") return false;
  if (feedState.tool !== "all" && stepCategory(step) !== feedState.tool) return false;
  if (feedState.search.trim()) {
    const hay = `${step.tool} ${(step.args || []).join(" ")} ${step.output || step.stderr || ""}`.toLowerCase();
    if (!hay.includes(feedState.search.trim().toLowerCase())) return false;
  }
  return true;
}

function findingCardMeta(step) {
  const args = Array.isArray(step.args) ? step.args : [];
  const idLike = (s) => /^f-\d+$/i.test(String(s || "").trim());
  let title = args[0] || "";
  let sev = args[1] || "";
  if (idLike(title)) {
    const out = String(step.output || "");
    const m = out.match(/^(.+?)\s+\[([^\]]+)\]/);
    title = m ? m[1] : (out.split("\n")[0] || title);
    sev = sev && !idLike(sev) ? sev : (m ? m[2] : "");
  }
  if (!title || title === "(finding)") {
    title = String(step.output || "").split("\n")[0] || "Hallazgo";
  }
  const desc = String(step.output || "").trim();
  return { title, sev, desc };
}

const PHASE_LABELS = { 1: "Fase 1 · Recon", 2: "Fase 2 · Enum", 3: "Fase 3 · Explotación", 4: "Fase 4 · Post" };

function phaseBadgeHtml(phase) {
  if (phase == null) return "";
  const label = PHASE_LABELS[phase] || `Fase ${phase}`;
  return `<span class="px-sm py-xs rounded font-label-md text-label-md bg-surface-variant/60 text-on-surface-variant border border-outline-variant/20 shrink-0">${label}</span>`;
}

function severityBadgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "bg-error/10 text-error";
  if (s === "high") return "bg-tertiary-container/20 text-tertiary";
  if (s === "medium") return "bg-secondary-container/40 text-on-secondary-container";
  if (s === "low" || s === "info") return "bg-surface-variant text-on-surface-variant";
  return "bg-surface-container text-on-surface-variant";
}

function appendStepCard(step) {
  if (!shouldShowStepInFeed(step)) return;
  if (step.verdict === "agent_error") {
    const msg = String(step.stderr || "");
    if (msg.length > 400 && /ollama_|invalid_json|empty_content|missing_tool/.test(msg)) return;
  }
  // Hallazgos: tarjetas compactas en el feed (el filtro "findings" las necesita)
  if (step.tool === "(finding)") {
    const feed = document.getElementById("engine-feed");
    if (!feed) return;
    const card = document.createElement("div");
    card.className = "glass-panel rounded-lg p-md flex items-start gap-md border-l-4 border-primary cursor-pointer hover:bg-surface-container-low/40";
    card.dataset.feedCategory = "findings";
    card.setAttribute("role", "button");
    const meta = findingCardMeta(step);
    const desc = meta.desc && meta.desc !== meta.title
      ? `<p class="font-body-sm text-on-surface-variant mt-xs line-clamp-3">${String(meta.desc).replace(/</g, "&lt;")}</p>`
      : "";
    // step.args = [title, severity, finding.id] (ver recordProposedFinding
    // en agent.js): con el id real enlazamos directo a esa revisión en vez
    // de abrir el panel lateral genérico de "Hallazgos" — ese panel solo
    // hace scroll automático si hay pendientes, y en viewport angosto
    // (< lg) queda apilado debajo de todo el feed, así que a simple vista
    // parecía que el click "no hacía nada".
    const findingId = Array.isArray(step.args) ? step.args[2] : null;
    const scanId = sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "";
    const detailHref = findingId
      ? `finding-detail.html?id=${encodeURIComponent(findingId)}${scanId ? `&scan=${encodeURIComponent(scanId)}` : ""}`
      : null;
    card.innerHTML = `
<div class="w-10 h-10 rounded bg-primary-container/15 text-primary flex items-center justify-center shrink-0"><i data-lucide="bug"></i></div>
<div class="min-w-0 flex-1">
  <div class="flex items-center gap-sm flex-wrap">
    <h3 class="font-headline-md text-headline-md text-on-surface">${String(meta.title).replace(/</g, "&lt;")}</h3>
    ${meta.sev ? `<span class="px-sm py-xs rounded font-label-md text-label-md ${severityBadgeClass(meta.sev)}">${String(meta.sev).replace(/</g, "&lt;")}</span>` : ""}
    ${phaseBadgeHtml(step.phase)}
  </div>
  ${desc}
  ${detailHref
    ? `<a href="${detailHref}" class="font-body-sm text-primary mt-xs inline-block hover:underline">Abrir revisión →</a>`
    : `<p class="font-body-sm text-primary mt-xs">Abrir revisión →</p>`}
</div>`;
    if (!detailHref) {
      card.addEventListener("click", () => {
        document.getElementById("engine-findings-btn")?.click();
      });
    }
    feed.appendChild(card);
    if (window.lucide) lucide.createIcons();
    return;
  }
  if (step.tool === "(agent)" && !["waiting_for_quota", "agent_error", "done"].includes(step.verdict)) return;
  const feed = document.getElementById("engine-feed");
  if (!feed) return;
  const card = document.createElement("div");
  card.className = "glass-panel rounded-lg overflow-hidden flex flex-col hover:shadow-md transition-shadow";
  card.dataset.feedCategory = stepCategory(step);
  card.dataset.feedTool = step.tool || "";
  const args = Array.isArray(step.args) ? step.args.join(" ") : "";
  const detail = [step.output || step.stdout || "", step.stderr || ""].filter(Boolean).join("\n");
  const hideOut = step.verdict === "ok" && !detail;
  card.innerHTML = `
<div class="p-md flex items-center justify-between border-b border-outline-variant/20 bg-surface-container-lowest/50">
  <div class="flex items-center gap-md min-w-0">
    <div class="w-10 h-10 rounded bg-surface-container flex items-center justify-center text-primary border border-outline-variant/20 shrink-0">
      <i data-lucide="${toolIcon(step.tool, step.verdict)}"></i>
    </div>
    <div class="min-w-0">
      <h3 class="font-headline-md text-headline-md text-on-surface truncate">${step.tool}</h3>
      <div class="flex items-center gap-xs mt-xs">
        <i data-lucide="terminal" class="icon-sm text-outline shrink-0"></i>
        <code class="font-mono-md text-mono-md text-secondary bg-surface-container-low px-xs rounded text-[11px] truncate max-w-[42rem]">${args || "—"}</code>
      </div>
    </div>
  </div>
  <div class="flex items-center gap-sm shrink-0">
    ${phaseBadgeHtml(step.phase)}
    <span class="px-sm py-xs rounded font-label-md text-label-md flex items-center gap-xs border ${verdictStyle(step.verdict)}">${step.verdict || ""}</span>
    <button class="text-on-surface-variant hover:bg-surface-variant/50 p-xs rounded transition-colors" type="button" data-toggle-out aria-label="Toggle output">
      <i data-lucide="chevron-down"></i>
    </button>
  </div>
</div>
<div class="output-panel ${hideOut || step.verdict === "ok" ? "hidden" : ""} bg-[#1e2329] p-md">
  <pre class="font-mono-md text-mono-md text-gray-300 text-[12px] whitespace-pre-wrap">${(detail || "").replace(/</g, "&lt;")}</pre>
</div>`;
  const toggle = card.querySelector("[data-toggle-out]");
  toggle.addEventListener("click", () => {
    card.querySelector(".output-panel").classList.toggle("hidden");
  });
  feed.appendChild(card);
  feed.scrollTop = feed.scrollHeight;
  if (window.lucide) lucide.createIcons();
}

function rerenderFeed() {
  const feed = document.getElementById("engine-feed");
  if (!feed) return;
  feed.innerHTML = "";
  let shown = 0;
  for (const step of feedState.steps) {
    if (matchesFeedFilter(step)) {
      const before = feed.children.length;
      appendStepCard(step);
      if (feed.children.length > before) shown += 1;
    }
  }
  if (!shown) {
    const empty = document.createElement("div");
    empty.className = "glass-panel rounded-lg p-lg text-center";
    empty.id = "engine-feed-empty";
    const total = feedState.steps.length;
    empty.innerHTML = total
      ? `<p class="font-body-md text-on-surface-variant">Ningún paso coincide con el filtro.</p>
         <button type="button" id="engine-feed-reset-filter" class="mt-sm text-primary font-label-md hover:underline">Mostrar todo el feed</button>`
      : `<p class="font-body-md text-on-surface-variant">Esperando actividad con resultados…</p>
         <p class="font-body-sm text-on-surface-variant mt-xs">Solo se muestran pasos con salida (hallazgos, errores, datos de recon).</p>`;
    feed.appendChild(empty);
    document.getElementById("engine-feed-reset-filter")?.addEventListener("click", () => {
      const sel = document.getElementById("engine-feed-filter");
      if (sel) sel.value = "all";
      const hide = document.getElementById("engine-feed-hide-noise");
      if (hide) hide.checked = false;
      feedState.tool = "all";
      feedState.hideNoise = false;
      rerenderFeed();
    });
  }
}

function appendStep(step) {
  feedState.steps.push(step);
  // Quitar placeholder vacío
  document.getElementById("engine-feed-empty")?.remove();
  if (matchesFeedFilter(step)) appendStepCard(step);
  else if (!document.querySelector("#engine-feed .glass-panel:not(#engine-feed-empty)") && !document.getElementById("engine-feed-empty")) {
    rerenderFeed();
  }
}

function initFeedFilters() {
  const sel = document.getElementById("engine-feed-filter");
  const hideNoise = document.getElementById("engine-feed-hide-noise");
  if (sel) sel.value = "all";
  const apply = () => {
    feedState.tool = sel?.value || "all";
    feedState.search = "";
    feedState.hideNoise = hideNoise ? hideNoise.checked : true;
    rerenderFeed();
  };
  sel?.addEventListener("change", apply);
  hideNoise?.addEventListener("change", apply);
  apply();
}

function showEngagementIdle() {
  document.getElementById("engine-idle")?.removeAttribute("hidden");
  document.getElementById("engine-live")?.setAttribute("hidden", "");
  document.getElementById("engine-toolbar")?.setAttribute("hidden", "");
  document.getElementById("engine-confirm")?.setAttribute("hidden", "");
  document.getElementById("engine-findings")?.setAttribute("hidden", "");
  const crumb = document.getElementById("engine-target-crumb");
  const lead = document.getElementById("engine-target-lead");
  if (crumb) crumb.textContent = "—";
  if (lead) lead.textContent = "—";
  if (window.lucide) lucide.createIcons();
}

function showEngagementLive() {
  document.getElementById("engine-idle")?.setAttribute("hidden", "");
  document.getElementById("engine-live")?.removeAttribute("hidden");
  document.getElementById("engine-toolbar")?.removeAttribute("hidden");
}

function showConfirmModal(decision, onApprove, onReject) {
  const modal = document.getElementById("engine-confirm");
  const text = document.getElementById("engine-confirm-text");
  if (!modal || !text) return;
  text.textContent = `${decision.tool} ${JSON.stringify(decision.args)} — ${decision.reasoning || ""}`;
  modal.classList.add("flex");
  modal.removeAttribute("hidden");
  const approve = document.getElementById("engine-confirm-approve");
  const reject = document.getElementById("engine-confirm-reject");
  const cleanup = () => {
    modal.classList.remove("flex");
    modal.setAttribute("hidden", "");
    approve.onclick = null;
    reject.onclick = null;
  };
  approve.onclick = () => { cleanup(); onApprove(); };
  reject.onclick = () => { cleanup(); onReject(); };
  if (window.lucide) lucide.createIcons();
}

function bridgeErrorMessage(err, fallback) {
  const msg = String(err?.message || err || "");
  if (/unknown endpoint|bridge_error_404/.test(msg)) {
    return t(
      "start.motorOutdated",
      "El motor está desactualizado. Reinícialo: cd backend && python3 bridge.py — luego recarga esta página.",
    );
  }
  const jsonTail = msg.replace(/^bridge_error_\d+:\s*/, "");
  if (
    /bridge_unreachable|Connection refused|bridge_down|session_unavailable|motor no está|Inicia el motor|AUDITOR_KEYSTORE/i.test(msg)
    || /bridge_unreachable|bridge_down|session_unavailable/i.test(jsonTail)
  ) {
    return t(
      "start.motorDown",
      "El motor no está en marcha. Abre otra terminal, ejecuta:\ncd backend && python3 bridge.py\nEscribe tu passphrase (no se ve al tipear; es normal) y recarga esta página.",
    );
  }
  try {
    const data = JSON.parse(jsonTail);
    if (data?.error === "bridge_unreachable" || data?.error === "bridge_down" || data?.error === "session_unavailable") {
      return t(
        "start.motorDown",
        "El motor no está en marcha. Abre otra terminal, ejecuta:\ncd backend && python3 bridge.py\nEscribe tu passphrase (no se ve al tipear; es normal) y recarga esta página.",
      );
    }
  } catch {
    /* not JSON */
  }
  return jsonTail || fallback;
}

async function bootStart() {
  const params = new URLSearchParams(location.search);
  const nameInput = document.getElementById("engagement-name");
  const targetInput = document.getElementById("target");
  const scopeInput = document.getElementById("scope");
  const modelInput = document.getElementById("model");
  const useAiInput = document.getElementById("use-ai");
  const aiBlock = document.getElementById("ai-required-block");
  const aiHint = document.getElementById("ai-mode-hint");
  const keyValueInput = document.getElementById("key-value");
  const keyLabelInput = document.getElementById("key-label");
  const keyWindowInput = document.getElementById("key-window");
  const keyList = document.getElementById("key-list");
  const cta = document.getElementById("primary-cta");
  const form = document.getElementById("start-form");
  const note = document.getElementById("engine-banner");
  const selected = new Set();
  let pendingKey = null;
  let modelsCache = [];
  let starting = false;
  let motorFeatures = {};
  let aiToggleSilent = false;

  if (params.get("target")) targetInput.value = params.get("target");
  if (params.get("scope")) scopeInput.value = params.get("scope");
  if (nameInput && (params.get("name") || params.get("engagement-name"))) {
    nameInput.value = params.get("name") || params.get("engagement-name");
  }
  if (!keyWindowInput.value) keyWindowInput.value = "24";

  const formFields = [nameInput, targetInput, scopeInput, modelInput, keyValueInput, keyLabelInput, keyWindowInput];

  const isUseAi = () => !!(useAiInput && useAiInput.checked);

  const syncAiUi = () => {
    const on = isUseAi();
    if (useAiInput) useAiInput.setAttribute("aria-checked", on ? "true" : "false");
    if (aiBlock) {
      // Tailwind `flex` overrides native [hidden] { display:none } — force visibility.
      aiBlock.hidden = !on;
      if (on) {
        aiBlock.removeAttribute("hidden");
        aiBlock.classList.remove("hidden");
        aiBlock.style.display = "";
      } else {
        aiBlock.setAttribute("hidden", "");
        aiBlock.classList.add("hidden");
        aiBlock.style.display = "none";
      }
    }
    if (aiHint) {
      aiHint.textContent = on
        ? t("start.aiOnHint", "Modo IA: cada paso del agente consume tokens de Ollama Cloud.")
        : t("start.aiOffHint", "Modo playbook: no se consume cuota de Ollama.");
    }
    if (modelInput) modelInput.required = on;
  };

  syncAiUi();

  useAiInput?.addEventListener("change", async () => {
    if (aiToggleSilent) return;
    if (useAiInput.checked) {
      const ok = await showAiTokenModal();
      if (!ok) {
        aiToggleSilent = true;
        useAiInput.checked = false;
        aiToggleSilent = false;
      }
    }
    syncAiUi();
  });

  const renderKeys = (keys, pending = null) => {
    const list = Array.isArray(keys) ? keys : [];
    if (!keyList) return;
    keyList.innerHTML = "";
    if (!list.length && !pending) {
      const empty = document.createElement("p");
      empty.className = "font-body-sm text-body-sm text-on-surface-variant italic";
      empty.textContent = t("engine.noKeys", "Todavía no hay ninguna API key guardada.");
      keyList.appendChild(empty);
      return;
    }
    if (pending) {
      const row = document.createElement("div");
      row.className = "glass-panel rounded-lg p-md flex items-center justify-between gap-md border border-dashed border-primary-container/40";
      row.innerHTML = `
<div class="flex items-center gap-md min-w-0 flex-1">
  <input class="w-5 h-5 shrink-0" type="checkbox" checked disabled/>
  <div class="bg-primary-container/20 text-primary-container p-sm rounded flex items-center justify-center shrink-0">
    <i data-lucide="clock"></i>
  </div>
  <div class="flex flex-col min-w-0">
    <span class="font-label-md text-label-md text-on-surface">${pending.label}</span>
    <span class="font-body-sm text-body-sm text-on-surface-variant">${t("start.keyPendingSave", "Verificada — pendiente de guardar en el motor")}</span>
  </div>
</div>`;
      keyList.appendChild(row);
    }
    for (const k of list) {
      if (!selected.has(k.label)) selected.add(k.label);
      const row = document.createElement("div");
      row.className = "glass-panel rounded-lg p-md flex items-center justify-between gap-md";
      row.innerHTML = `
<div class="flex items-center gap-md min-w-0 flex-1">
  <input class="w-5 h-5 shrink-0 text-primary-container border-outline-variant focus:ring-primary-container cursor-pointer key-checkbox" type="checkbox" value="${k.label}" ${selected.has(k.label) ? "checked" : ""}/>
  <div class="bg-tertiary-container text-on-tertiary-container p-sm rounded flex items-center justify-center shrink-0">
    <i data-lucide="key-round"></i>
  </div>
  <div class="flex flex-col min-w-0">
    <span class="font-label-md text-label-md text-on-surface">${k.label}</span>
    <span class="font-body-sm text-body-sm text-on-surface-variant">****${k.last4} · ${k.window_hours}h · ${t("start.keyVerified", "verificada")}</span>
  </div>
</div>
<div class="flex items-center gap-xs shrink-0">
  <button type="button" class="key-edit-btn px-sm py-xs rounded border border-outline-variant text-secondary font-label-md text-label-md hover:bg-surface-variant/30" data-label="${k.label}" data-hours="${k.window_hours}">${t("start.editKey", "Editar")}</button>
  <button type="button" class="key-delete-btn px-sm py-xs rounded border border-error/30 text-error font-label-md text-label-md hover:bg-error-container/20" data-label="${k.label}" aria-label="${t("start.deleteKey", "Eliminar")}">
    <i data-lucide="trash-2" class="icon-sm"></i>
  </button>
</div>`;
      const cb = row.querySelector(".key-checkbox");
      cb.addEventListener("change", () => {
        if (cb.checked) selected.add(k.label);
        else selected.delete(k.label);
      });
      row.querySelector(".key-delete-btn").addEventListener("click", async () => {
        if (!motorFeatures.keys_delete) {
          banner(note, bridgeErrorMessage({ message: "unknown endpoint" }), true);
          return;
        }
        if (!confirm(`${t("start.deleteKey", "Eliminar")} "${k.label}"?`)) return;
        try {
          await ensureSession(api);
          await api.bridge.deleteKey(k.label);
          selected.delete(k.label);
          await refreshKeys();
          banner(note, `"${k.label}" eliminada.`, false);
        } catch (err) {
          banner(note, bridgeErrorMessage(err), true);
        }
      });
      row.querySelector(".key-edit-btn").addEventListener("click", async () => {
        if (!motorFeatures.keys_update) {
          banner(note, bridgeErrorMessage({ message: "unknown endpoint" }), true);
          return;
        }
        const next = prompt(t("start.keyWindow", "Ventana (h)"), String(k.window_hours));
        if (next == null) return;
        const hours = parseFloat(next);
        if (!hours || hours <= 0) {
          banner(note, "Ventana inválida.", true);
          return;
        }
        try {
          await ensureSession(api);
          const updated = await api.bridge.updateKey(k.label, hours);
          if (updated.label !== k.label) {
            selected.delete(k.label);
            selected.add(updated.label);
          }
          await refreshKeys();
          banner(note, `"${updated.label}" · ${updated.window_hours}h`, false);
        } catch (err) {
          banner(note, bridgeErrorMessage(err), true);
        }
      });
      keyList.appendChild(row);
    }
    if (window.lucide) lucide.createIcons();
  };

  let api;
  let sessionOk = false;
  const enginePromise = loadEngine().then(function (loaded) {
    api = loaded;
    return loaded;
  });

  const hasKeysForStart = () => selected.size > 0 || !!pendingKey;

  const connectMotor = async () => {
    await ensureSession(api);
    try {
      const session = await api.bridge.fetchSession();
      motorFeatures = session.features || {};
    } catch {
      motorFeatures = {};
    }
    sessionOk = true;
    return true;
  };

  const refreshKeys = async () => {
    try {
      if (!sessionOk) await connectMotor();
      const keys = await api.bridge.listKeys();
      renderKeys(keys, pendingKey);
      if (keys.length && !modelsCache.length) {
        modelsCache = await loadModels(api, note);
      } else if (modelsCache.length) {
        populateModelSelect(modelInput, modelsCache, modelInput.value);
      }
      return keys;
    } catch (err) {
      sessionOk = false;
      renderKeys([], pendingKey);
      throw err;
    }
  };

  const saveKeyToMotor = async (label, value, windowHours) => {
    await connectMotor();
    const stored = await api.bridge.addKey(label, value, windowHours, false);
    selected.add(stored.label || label);
    pendingKey = null;
    keyValueInput.value = "";
    await refreshKeys();
    return stored;
  };

  const refreshModels = async () => {
    if (modelsCache.length) {
      populateModelSelect(modelInput, modelsCache, modelInput.value);
      return;
    }
    if (!sessionOk || !hasKeysForStart()) return;
    modelsCache = await loadModels(api, note);
  };

  const tryConnectMotor = async () => {
    try {
      await connectMotor();
      if (pendingKey) {
        await saveKeyToMotor(pendingKey.label, pendingKey.apiKey, pendingKey.windowHours);
        pendingKey = null;
      } else {
        await refreshKeys();
      }
      return true;
    } catch (err) {
      sessionOk = false;
      return false;
    }
  };

  const ensureKeysInMotor = async () => {
    await connectMotor();
    if (pendingKey) {
      await saveKeyToMotor(pendingKey.label, pendingKey.apiKey, pendingKey.windowHours);
      pendingKey = null;
    }
    const labels = [...selected];
    if (!labels.length) {
      const keys = await api.bridge.listKeys();
      keys.forEach((k) => selected.add(k.label));
      if (!selected.size) throw new Error(t("start.missingKeySelect", "Agrega y selecciona al menos una API key"));
      return [...selected];
    }
    return labels;
  };

  const runStartAnalysis = async () => {
    if (starting) return;
    clearFieldErrors(formFields);
    const useAi = isUseAi();
    const missing = collectStartValidation(
      useAi ? hasKeysForStart() : true,
      nameInput,
      targetInput,
      scopeInput,
      modelInput,
      useAi,
    );
    if (missing.length) {
      showValidationModal(missing);
      banner(note, t("start.validationTitle", "Faltan datos obligatorios"), true);
      note?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }

    if (useAi) {
      const ok = await showAiTokenModal();
      if (!ok) {
        banner(note, t("start.tokenCancelled", "Inicio cancelado. Puedes desactivar IA y usar solo playbook."), false);
        return;
      }
    }

    starting = true;
    cta.disabled = true;
    if (!api) {
      banner(note, t("start.engineLoading", "Cargando el motor… un segundo y arranca el análisis."), false);
    } else {
      banner(note, t("start.analyze", "Iniciar análisis") + "…", false);
    }

    try {
      try {
        api = await enginePromise;
      } catch (loadErr) {
        banner(
          note,
          t("start.engineLoadFail", "No se pudo cargar el motor en el navegador. Recarga la página. El panel debe estar en http://127.0.0.1:8080 (cd panel && python3 server.py).") +
            " " + (loadErr && loadErr.message ? loadErr.message : ""),
          true,
        );
        return;
      }
      banner(note, t("start.analyze", "Iniciar análisis") + "…", false);

      const name = (nameInput?.value || "").trim();
      const target = targetInput.value.trim();
      const scope = scopeInput.value.trim();
      const model = useAi ? modelInput.value.trim() : "";

      const token = await ensureSession(api);
      sessionStorage.setItem(TOKEN_KEY, token);

      if (useAi) {
        const labels = await ensureKeysInMotor();
        await api.bridge.selectKeys(labels);
      } else {
        await connectMotor();
      }

      const started = await api.bridge.startEngagement(target, scope, {
        name,
        objective: name,
        useAi,
      });
      const engagementDir = started?.engagement_dir || "";
      if (engagementDir) sessionStorage.setItem(ENGAGEMENT_ID_KEY, engagementDir);
      if (typeof api.bridge.setActiveEngagementDir === "function") {
        api.bridge.setActiveEngagementDir(engagementDir);
      }
      sessionStorage.setItem(RUN_KEY, JSON.stringify({
        name,
        objective: name,
        target,
        scope,
        model,
        useAi,
        endpoint: OLLAMA_CHAT_ENDPOINT,
        startedAt: Date.now(),
        engagementDir,
      }));
      if (model) sessionStorage.setItem(MODEL_KEY, model);
      window.location.href = "engagement.html";
    } catch (err) {
      banner(note, bridgeErrorMessage(err, String(err.message || err)), true);
    } finally {
      starting = false;
      cta.disabled = false;
    }
  };

  ["engagement-name", "target", "scope"].forEach((id) => {
    document.getElementById(id)?.addEventListener("input", () => {
      clearFieldErrors(formFields);
    });
  });
  modelInput?.addEventListener("change", () => clearFieldErrors(formFields));
  keyValueInput?.addEventListener("input", () => clearFieldErrors(formFields));
  document.getElementById("refresh-models-btn")?.addEventListener("click", refreshModels);

  document.getElementById("add-key-btn")?.addEventListener("click", async () => {
    const label = keyLabelInput.value.trim() || `ollama-${(keyValueInput.value.trim().slice(-4) || "key")}`;
    const value = keyValueInput.value.trim();
    const windowHours = parseFloat(keyWindowInput.value) || 24;
    const btn = document.getElementById("add-key-btn");
    if (!value) {
      showValidationModal([{ label: "API Key", el: keyValueInput }]);
      keyValueInput?.classList.add(...FIELD_ERROR_TOKENS);
      return;
    }
    btn.disabled = true;
    clearFieldErrors(formFields);
    banner(note, t("start.verifyingKey", "Verificando API key con Ollama Cloud (ollama.com)…"), false);
    try {
      const verified = await verifyOllamaKeyDirect(value);
      modelsCache = Array.isArray(verified.models) ? verified.models : [];
      populateModelSelect(modelInput, modelsCache, modelInput.value);

      try {
        await saveKeyToMotor(label, value, windowHours);
        keyLabelInput.value = "";
        banner(note, t("start.keyAdded", "API key verificada con ollama.com. Modelos cargados."), false);
      } catch (saveErr) {
        pendingKey = { apiKey: value, label, windowHours };
        renderKeys([], pendingKey);
        selected.add(label);
        banner(note, bridgeErrorMessage(saveErr, String(saveErr.message || saveErr)), true);
      }
    } catch (err) {
      const msg = String(err.message || err);
      pendingKey = null;
      if (msg.includes("invalid_api_key")) {
        banner(note, t("start.keyInvalid", "API key inválida o inactiva. Revisa la key en ollama.com."), true);
      } else {
        banner(note, msg, true);
      }
    } finally {
      btn.disabled = false;
      if (window.lucide) lucide.createIcons();
    }
  });

  window.__dsStartAnalysis = runStartAnalysis;

  try {
    await enginePromise;
    await connectMotor();
    const keys = await refreshKeys();
    const outdated = !motorFeatures.keys_delete || !motorFeatures.keys_update;
    if (outdated) {
      banner(note, t("start.motorOutdated", "El motor está desactualizado. Reinícialo: cd backend && python3 bridge.py — luego recarga esta página."), true);
    } else if (keys.length) {
      banner(note, `${t("start.motorReady", "Motor listo. Completa target, scope y modelo.")} (${keys.length} key${keys.length === 1 ? "" : "s"})`, false);
    } else {
      banner(note, t("start.motorReady", "Motor listo. Completa target, scope y modelo."), false);
    }
  } catch (err) {
    banner(
      note,
      bridgeErrorMessage(err, t("start.motorDownVerifyOk", "Motor apagado. Puedes verificar tu API key con ollama.com. Para analizar: cd backend && python3 bridge.py")),
      true,
    );
    if (pendingKey) renderKeys([], pendingKey);
  }
  if (window.lucide) lucide.createIcons();
}

async function bootEngagement() {
  const note = document.getElementById("engine-banner");
  feedState.steps = [];

  let api;
  try {
    api = await loadEngine();
    await ensureSession(api);
  } catch (err) {
    showEngagementIdle();
    banner(note, "No se pudo conectar al motor. " + err.message, true);
    return;
  }

  const { run, status, motorTaken } = await resolveRunFromBridge(api, loadRunFromStorage());
  if (!run?.target) {
    showEngagementIdle();
    if (status.active) {
      banner(note, "Escaneo activo en el motor pero falta configuración. Inicia de nuevo desde New Scan.", true);
    }
    return;
  }

  showEngagementLive();
  const displayName = run.name || run.objective || run.target;
  const crumb = document.getElementById("engine-target-crumb");
  const lead = document.getElementById("engine-target-lead");
  if (crumb) crumb.textContent = displayName;
  if (lead) lead.textContent = run.name ? `${run.name} · ${run.target}` : run.target;

  const phaseState = { current: status.phase || 1, bump: 0 };
  renderPhaseBar(phaseState.current);

  let startAgentIfNeeded = () => {};
  initFeedFilters();

  let agentTask = null;
  let forceStop = false;
  let scanPaused = !!status.paused;
  let currentEngId = status.engagement_dir || run.engagementDir || sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "";
  if (run.engagementDir) currentEngId = run.engagementDir;
  if (typeof api.bridge.setActiveEngagementDir === "function") {
    api.bridge.setActiveEngagementDir(currentEngId);
  }
  if (motorTaken) {
    banner(
      note,
      t(
        "eng.motorTaken",
        "El motor está ocupado con otro engagement. Este playbook no ejecutará más comandos aquí; los hallazgos ya guardados se conservan.",
      ),
      true,
    );
  }
  syncScanControlButtons({
    paused: scanPaused,
    active: !!status.active,
    finished: !status.active,
  });

  let db;
  let engagementId;
  try {
    db = await api.db.initDB();
    if (typeof api.db.getOrCreateEngagement !== "function") {
      throw new Error("Motor JS desactualizado (falta getOrCreateEngagement). Ejecuta: python3 scripts/sync-engine-js.py");
    }
    engagementId = await api.db.getOrCreateEngagement(db, { target: run.target, scope: run.scope });
  } catch (err) {
    banner(note, "No se pudo abrir el engagement local: " + (err.message || err), true);
    appendStep({
      tool: "(agent)",
      args: [],
      verdict: "agent_error",
      stderr: String(err.message || err),
    });
    return;
  }

  try {
    const stored = await api.db.getSteps(db, engagementId);
    feedState.steps = stored.map(dbStepToFeedStep);
    rerenderFeed();
  } catch {
    rerenderFeed();
  }

  const advanceBtn = document.getElementById("advance-phase-btn");
  const pauseBtn = document.getElementById("pause-scan-btn");
  const resumeBtn = document.getElementById("resume-scan-btn");
  const finishBtn = document.getElementById("finish-scan-btn");

  if (advanceBtn && !advanceBtn.dataset.bound) {
    advanceBtn.dataset.bound = "1";
    advanceBtn.addEventListener("click", async () => {
      advanceBtn.disabled = true;
      try {
        const result = await api.bridge.advancePhase();
        phaseState.current = result.phase || phaseState.current + 1;
        phaseState.bump = (phaseState.bump || 0) + 1;
        renderPhaseBar(phaseState.current);
        banner(note, `Fase ${phaseState.current} activa`, false);
        appendStep({
          tool: "(agent)",
          args: ["phase/advance"],
          verdict: "status",
          stderr: `Avance a fase ${phaseState.current}`,
        });
        if (!agentTask && !forceStop) startAgentIfNeeded();
      } catch (err) {
        banner(note, err.message || String(err), true);
      } finally {
        advanceBtn.disabled = !!status.paused;
      }
    });
  }

  const agentControl = {
    async check() {
      if (forceStop) return "stop";
      try {
        const s = await api.bridge.getStatus();
        if (!s.active) return "stop";
        if (s.paused) return "pause";
        return "run";
      } catch {
        return forceStop ? "stop" : "run";
      }
    },
    onPaused() {
      syncScanControlButtons({ paused: true, active: true, finished: false });
      banner(note, t("eng.paused", "Escaneo pausado"), false);
    },
  };

  function bindScanControl(btn, handler) {
    if (!btn || btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", handler);
  }

  bindScanControl(pauseBtn, async () => {
    if (!currentEngId) return;
    pauseBtn.disabled = true;
    try {
      await callEngagementControl(api, "pause", currentEngId);
      scanPaused = true;
      syncScanControlButtons({ paused: true, active: true, finished: false });
      banner(note, t("eng.paused", "Escaneo pausado"), false);
      appendStep({ tool: "(agent)", args: [], verdict: "status", stderr: t("eng.paused", "Escaneo pausado") });
    } catch (err) {
      banner(note, bridgeErrorMessage(err, String(err.message || err)), true);
    } finally {
      pauseBtn.disabled = false;
    }
  });

  bindScanControl(resumeBtn, async () => {
    if (!currentEngId) return;
    resumeBtn.disabled = true;
    try {
      await callEngagementControl(api, "resume", currentEngId);
      scanPaused = false;
      syncScanControlButtons({ paused: false, active: true, finished: false });
      banner(note, t("eng.resumed", "Escaneo reanudado"), false);
      appendStep({ tool: "(agent)", args: [], verdict: "status", stderr: t("eng.resumed", "Escaneo reanudado") });
      startAgentIfNeeded();
    } catch (err) {
      banner(note, bridgeErrorMessage(err, String(err.message || err)), true);
    } finally {
      resumeBtn.disabled = false;
    }
  });

  bindScanControl(finishBtn, async () => {
    if (!currentEngId) return;
    const msg = t(
      "eng.finishConfirm",
      "¿Finalizar este escaneo? Los hallazgos se conservan; dejará de estar en curso.",
    );
    if (!window.confirm(msg)) return;
    finishBtn.disabled = true;
    forceStop = true;
    try {
      await callEngagementControl(api, "finish", currentEngId);
      syncScanControlButtons({ paused: false, active: false, finished: true });
      releaseAgentOwnership();
      banner(note, t("eng.finished", "Escaneo finalizado"), false);
      appendStep({ tool: "(agent)", args: [], verdict: "status", stderr: t("eng.finished", "Escaneo finalizado") });
    } catch (err) {
      forceStop = false;
      banner(note, bridgeErrorMessage(err, String(err.message || err)), true);
    } finally {
      finishBtn.disabled = false;
    }
  });

  document.getElementById("engine-export-btn")?.addEventListener("click", async () => {
    try {
      const data = await api.db.exportEngagementJSON(db, engagementId);
      let findings = [];
      try {
        const raw = await api.bridge.listFindings();
        findings = Array.isArray(raw) ? raw : [];
      } catch {
        /* bridge sin engagement activo */
      }
      if (window.DarkSpearExport?.downloadEngagementBundle) {
        DarkSpearExport.downloadEngagementBundle({
          findings,
          steps: data.steps,
          engagementId,
          target: run.target,
        });
      }
    } catch (err) {
      banner(note, err.message || String(err), true);
    }
  });

  const findingsBtn = document.getElementById("engine-findings-btn");
  const findingsBtnLabel = document.getElementById("engine-findings-btn-label");
  const findingsPanel = document.getElementById("engine-findings");
  const findingsList = document.getElementById("engine-findings-list");
  let findingsDockDismissed = false;

  function setFindingsDockVisible(visible) {
    if (!findingsPanel) return;
    if (visible) {
      findingsPanel.hidden = false;
      findingsPanel.removeAttribute("hidden");
    } else {
      findingsPanel.hidden = true;
      findingsPanel.setAttribute("hidden", "");
    }
  }

  async function refreshFindings({ openDock = false } = {}) {
    try {
      let list = [];
      if (currentEngId && typeof api.bridge.listEngagementFindings === "function") {
        const payload = await api.bridge.listEngagementFindings(currentEngId);
        list = (payload && payload.findings) || [];
      } else {
        const findings = await api.bridge.listFindings(currentEngId);
        list = Array.isArray(findings) ? findings : ((findings && findings.findings) || []);
      }
      syncFindingsToInbox(list);
      const pending = list.filter((f) => f.status === "proposed" || f.status === "edited").length;
      const label = pending ? `Hallazgos (${pending} pendientes)` : `Hallazgos (${list.length})`;
      if (findingsBtnLabel) findingsBtnLabel.textContent = label;
      else if (findingsBtn) findingsBtn.textContent = label;
      if (findingsBtn) {
        findingsBtn.classList.toggle("bg-primary-container", pending > 0);
        findingsBtn.classList.toggle("text-on-primary-container", pending > 0);
        findingsBtn.classList.toggle("border-primary-container", pending > 0);
        findingsBtn.classList.toggle("text-secondary", pending === 0);
      }
      if (!findingsList) return list;
      findingsList.innerHTML = "";
      if (!list.length) {
        findingsList.innerHTML = `<p class="font-body-sm text-on-surface-variant">Aún no hay hallazgos de este engagement.</p>`;
      }
      for (const f of list) {
        const card = document.createElement("div");
        const isPending = f.status === "proposed" || f.status === "edited";
        card.className = "rounded-lg p-md flex flex-col gap-sm border border-outline-variant/30 bg-surface-container-lowest";
        const detailHref = f.id
          ? `finding-detail.html?id=${encodeURIComponent(f.id)}${currentEngId ? `&scan=${encodeURIComponent(currentEngId)}` : ""}`
          : "finding-detail.html";
        const sev = String(f.severity || "");
        card.innerHTML = `<div class="flex items-center justify-between gap-sm">
            <span class="px-sm py-xs rounded font-label-md text-label-md ${severityBadgeClass(sev)}">${sev.replace(/</g, "&lt;")} · ${String(f.status || "").replace(/</g, "&lt;")}</span>
          </div>
          <strong class="font-headline-md text-on-surface">${String(f.title || "").replace(/</g, "&lt;")}</strong>
          <p class="font-body-sm text-on-surface-variant whitespace-pre-wrap">${String(f.description || "").replace(/</g, "&lt;")}</p>
          ${f.remediation ? `<p class="font-body-sm text-on-surface"><span class="text-on-surface-variant">Remediación:</span> ${String(f.remediation).replace(/</g, "&lt;")}</p>` : ""}
          <a href="${detailHref}" class="text-primary font-label-md text-sm hover:underline">Ver informe →</a>`;
        if (isPending) {
          const row = document.createElement("div");
          row.className = "flex gap-sm flex-wrap";
          const acc = document.createElement("button");
          acc.type = "button";
          acc.className = "px-md py-sm rounded bg-primary-container text-on-primary-container font-label-md";
          acc.textContent = "Aceptar";
          acc.onclick = async () => {
            await api.bridge.reviewFinding(f.id, "accept", { edited_fields: {}, evidence_texts: [] });
            await refreshFindings();
          };
          const rej = document.createElement("button");
          rej.type = "button";
          rej.className = "px-md py-sm rounded border border-outline-variant font-label-md";
          rej.textContent = "Rechazar";
          rej.onclick = async () => {
            await api.bridge.reviewFinding(f.id, "reject");
            await refreshFindings();
          };
          row.append(acc, rej);
          card.appendChild(row);
        }
        findingsList.appendChild(card);
      }
      if (openDock && !findingsDockDismissed) {
        // Antes solo hacía scroll si había pendientes: con todo "accepted"
        // (0 pendientes, caso típico del modo playbook sin IA) el panel se
        // mostraba pero quedaba fuera de vista sin que nada lo trajera a
        // pantalla, especialmente apilado debajo del feed en viewport < lg.
        setFindingsDockVisible(true);
        findingsPanel?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "end" });
      }
      if (window.lucide) lucide.createIcons();
      return list;
    } catch {
      return [];
    }
  }

  findingsBtn?.addEventListener("click", async () => {
    findingsDockDismissed = false;
    await refreshFindings({ openDock: true });
    setFindingsDockVisible(true);
  });
  document.getElementById("engine-findings-close")?.addEventListener("click", () => {
    findingsDockDismissed = true;
    setFindingsDockVisible(false);
  });

  await refreshFindings({ openDock: true });

  let lastDbStepCount = feedState.steps.length;
  const observing = isAgentRunningElsewhere();

  setInterval(async () => {
    try {
      const st = await api.bridge.getStatus();
      if (st.active && st.phase) {
        phaseState.current = st.phase;
        renderPhaseBar(st.phase);
      }
    } catch { /* */ }
    // Siempre sincronizar steps desde IndexedDB
    try {
      const dbSteps = await api.db.getSteps(db, engagementId);
      if (dbSteps.length !== feedState.steps.length) {
        feedState.steps = dbSteps.map(dbStepToFeedStep);
        lastDbStepCount = dbSteps.length;
        rerenderFeed();
      } else if (dbSteps.length > lastDbStepCount) {
        lastDbStepCount = dbSteps.length;
      }
    } catch { /* */ }
    await refreshFindings();
  }, 3000);

  if (observing) {
    banner(note, `Modo observador · ${displayName} — el agente corre en otra pestaña`, false);
    return;
  }

  const useAi = run.useAi !== false && !!run.model;
  if (run.useAi !== false && !run.model) {
    banner(note, `Engagement ${displayName} — falta modelo en sesión. Vuelve a New Scan si el agente no arranca.`, true);
  } else if (!useAi) {
    banner(note, `Motor en vivo · playbook + heurísticas · ${displayName} · build ${api.build || ""}`, false);
  } else {
    banner(note, `Motor en vivo · IA · ${displayName} · build ${api.build || ""} — tras el playbook espera al modelo o pulsa Avanzar fase`, false);
  }

  claimAgentOwnership();

  const systemPrompt = `Eres un agente de pentest autorizado. Target en scope: ${run.target}. Objetivo: ${run.objective || run.name || run.target}. Laboratorio local (p.ej. DVWA). Trabaja paso a paso, una herramienta a la vez. Si el historial ya muestra un servidor HTTP, no repitas nmap: usa curl y propone hallazgos con evidencia. Responde solo JSON. Todo el texto libre que escribas dentro del JSON (reasoning, y especialmente title/description/remediation de un finding) debe estar en español — el operador y el informe final son en español.`;

  startAgentIfNeeded = function startAgentIfNeeded() {
    if (agentTask || forceStop || scanPaused || motorTaken) return;
    agentTask = api.agent.runAgentLoop({
      db,
      engagementId,
      model: run.model,
      target: run.target,
      scope: run.scope,
      systemPrompt,
      endpoint: run.endpoint || undefined,
      phaseState,
      useAi,
      control: agentControl,
      onStep: (step) => {
        appendStep(step);
        // Notificar en la campana cuando el playbook termina las 4 fases —
        // antes el fin de escaneo solo quedaba como una tarjeta más en el
        // feed y era fácil perdérselo si no se estaba mirando esa pestaña.
        if (step.tool === "(agent)" && step.verdict === "done" && window.DarkSpearFindings?.push) {
          DarkSpearFindings.push({
            id: `scan-done-${engagementId}`,
            title: `${t("eng.scanDoneTitle", "Escaneo completado")} · ${displayName}`,
            description: t("eng.scanDoneDesc", "El playbook terminó las 4 fases para {target}. Revisa los hallazgos pendientes.").replace("{target}", run.target || ""),
            severity: "info",
            asset: run.target || "",
            created_at: Date.now() / 1000,
          });
        }
      },
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
      onWaitingForQuota: () => {
        appendStep({ tool: "(agent)", args: [], verdict: "waiting_for_quota", stderr: "Keys agotadas, esperando cuota." });
      },
      onFindingProposed: async (finding) => {
        if (window.DarkSpearFindings && !finding.duplicate) DarkSpearFindings.push(finding);
        findingsDockDismissed = false;
        await refreshFindings({ openDock: !finding.duplicate });
      },
    }).catch((err) => {
      if (err?.name === "AgentStoppedError") {
        const reason = String(err.message || "");
        const msg = reason === "engagement_superseded"
          ? t("eng.superseded", "Este escaneo ya no es el activo en el motor (se inició otro). Se detuvo el playbook.")
          : reason === "scope_violation"
            ? t("eng.scopeStop", "El motor rechazó el target: no coincide con el scope activo. Playbook detenido.")
            : (err.message || t("eng.finished", "Escaneo finalizado"));
        appendStep({
          tool: "(agent)",
          args: [],
          verdict: "status",
          stderr: msg,
        });
        banner(note, msg, reason === "finished" ? false : true);
        return;
      }
      appendStep({ tool: "(agent)", args: [], verdict: "agent_error", stderr: err.message });
    }).finally(() => {
      agentTask = null;
      releaseAgentOwnership();
    });
  }

  if (!scanPaused && status.active !== false && !motorTaken) {
    startAgentIfNeeded();
  } else if (scanPaused) {
    banner(note, t("eng.paused", "Escaneo pausado"), false);
  }
}

async function bootActiveScans() {
  const empty = document.getElementById("active-scans-empty");
  const live = document.getElementById("active-scans-live");
  const cards = document.getElementById("active-scans-cards");
  const history = document.getElementById("active-scans-history");
  if (!empty || !live || !cards) return;

  let api = null;
  let deleting = false;

  function formatElapsed(sec) {
    sec = sec || 0;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function escapeHtml(s) {
    return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function agentSeemsRunning() {
    const hb = parseInt(localStorage.getItem(AGENT_HEARTBEAT_KEY) || "0", 10);
    return Date.now() - hb < 15000;
  }

  function resolveEngagementId(status, list) {
    const id = status?.engagement_dir || status?.id || "";
    if (id) return id;
    const run = loadRunFromStorage();
    if (run?.engagementDir) return run.engagementDir;
    const stored = sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "";
    if (stored) return stored;
    const target = (status?.target || run?.target || "").toLowerCase();
    if (target && Array.isArray(list)) {
      const hit = list.find((e) => String(e.target || "").toLowerCase() === target);
      if (hit) return hit.engagement_dir || hit.id || "";
    }
    return "";
  }

  function deleteBtn(engId, compact) {
    if (!engId) return "";
    const label = t("scans.delete", "Eliminar");
    const cls = compact
      ? "inline-flex items-center gap-xs px-sm py-xs rounded-lg border border-error/40 text-error hover:bg-error/10 font-label-md transition-colors"
      : "px-md py-sm rounded-lg border border-error/40 text-error hover:bg-error/10 font-label-md flex items-center gap-xs transition-colors shrink-0";
    return `<button type="button" class="${cls}" data-delete-scan="${escapeHtml(engId)}" title="${escapeHtml(label)}">
  <i data-lucide="trash-2" class="icon-sm"></i>
  <span>${escapeHtml(label)}</span>
</button>`;
  }

  function scanActionBtn(action, engId, compact) {
    const icons = { pause: "pause", resume: "play", finish: "square" };
    const labels = {
      pause: t("scans.pause", "Pausar"),
      resume: t("scans.resume", "Reanudar"),
      finish: t("scans.finish", "Finalizar"),
    };
    const label = labels[action] || action;
    const cls = compact
      ? "inline-flex items-center gap-xs px-sm py-xs rounded-lg border border-outline-variant/50 text-on-surface hover:bg-surface-container-low font-label-md transition-colors"
      : "px-md py-sm rounded-lg border border-outline-variant/50 text-on-surface hover:bg-surface-container-low font-label-md flex items-center gap-xs transition-colors shrink-0";
    return `<button type="button" class="${cls}" data-scan-action="${action}" data-scan-id="${escapeHtml(engId)}" title="${escapeHtml(label)}">
  <i data-lucide="${icons[action] || "circle"}" class="icon-sm"></i>
  <span>${escapeHtml(label)}</span>
</button>`;
  }

  function scanControlGroup(row, compact) {
    const engId = row.engagement_dir || row.id || "";
    if (!engId) return "";
    const st = String(row.status || row.run_status || "").toLowerCase();
    const paused = !!row.paused || st === "paused";
    const completed = st === "completed";
    const active = !!row.active || st === "running" || paused;
    if (completed) return deleteBtn(engId, compact);
    let html = "";
    if (active && !paused) html += scanActionBtn("pause", engId, compact);
    if (paused) html += scanActionBtn("resume", engId, compact);
    if (active) html += scanActionBtn("finish", engId, compact);
    html += deleteBtn(engId, compact);
    return html;
  }

  function renderCard(status) {
    const pct = status.progress_pct ?? 0;
    const paused = !!status.paused || status.run_status === "paused" || status.status === "paused";
    const badge = paused
      ? t("scans.pausedBadge", "Pausado")
      : (status.status_badge || (status.active ? "Scanning" : t("scans.localRun", "Sesión en este navegador")));
    const title = status.name || status.objective || status.target || "—";
    const sub = status.name
      ? `Target: ${escapeHtml(status.target || "—")} · Scope: ${escapeHtml(status.scope || "—")}`
      : `Scope: ${escapeHtml(status.scope || "—")}`;
    const note = status.bridge_gap
      ? `<p class="font-body-sm text-body-sm text-error mt-xs">${escapeHtml(t("scans.bridgeInactive", "El motor no tiene engagement activo; abre Engagement o reinicia desde New Scan."))}</p>`
      : "";
    const engId = status.engagement_dir || status.id || "";
    return `
<div class="acrylic rounded-xl p-md flex flex-col gap-md ambient-shadow" data-engagement-dir="${escapeHtml(engId)}">
  <div class="flex justify-between items-start gap-md">
    <div class="min-w-0">
      <h3 class="font-headline-md text-headline-md text-on-surface truncate">${escapeHtml(title)}</h3>
      <p class="font-mono-md text-mono-md text-secondary mt-xs truncate">${sub}</p>
      ${note}
    </div>
    <span class="bg-primary-container/15 text-primary font-label-md text-label-md px-sm py-xs rounded shrink-0">${escapeHtml(badge)}</span>
  </div>
  <div>
    <div class="flex justify-between font-body-sm text-body-sm text-secondary mb-xs">
      <span>Fase ${status.phase || 1}/4 — ${escapeHtml(status.phase_name || "")}</span>
      <span>${pct}%</span>
    </div>
    <div class="w-full bg-surface-variant rounded-full h-2">
      <div class="bg-primary-container h-2 rounded-full transition-all" style="width:${pct}%"></div>
    </div>
  </div>
  <div class="flex justify-between items-center border-t border-outline-variant/30 pt-sm gap-md">
    <div class="font-body-sm text-body-sm text-secondary">
      <span class="block font-label-md text-label-md text-on-surface">Tiempo</span>
      ${formatElapsed(status.elapsed_seconds)}
    </div>
    <div class="font-body-sm text-body-sm text-secondary min-w-0 text-right">
      <span class="block font-label-md text-label-md text-on-surface">Actividad</span>
      <span class="truncate block max-w-[14rem]">${escapeHtml(status.current_activity || "—")}</span>
    </div>
  </div>
  <div class="flex justify-between items-center gap-sm flex-wrap">
    <p class="font-body-sm text-on-surface-variant">${status.findings_accepted || 0} aceptados · ${status.findings_pending || 0} pendientes · ${status.step_count || 0} pasos</p>
    <div class="flex items-center gap-sm shrink-0 flex-wrap justify-end">
      ${scanControlGroup(status, false)}
      <a href="engagement.html" class="px-md py-sm bg-primary-container text-on-primary-container rounded-lg font-label-md flex items-center gap-xs hover:bg-primary transition-colors">
        <i data-lucide="activity" class="icon-sm"></i>
        <span>${escapeHtml(t("scans.viewLive", "Ver en vivo"))}</span>
      </a>
    </div>
  </div>
</div>`;
  }

  function renderHistory(rows) {
    if (!history) return;
    history.innerHTML = "";
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="py-sm text-on-surface-variant italic" colspan="5">Sin historial todavía</td>`;
      history.appendChild(tr);
      return;
    }
    for (const row of list.slice(0, 12)) {
      const tr = document.createElement("tr");
      tr.className = "border-b border-outline-variant/20";
      const started = row.started_at
        ? new Date((row.started_at < 1e12 ? row.started_at * 1000 : row.started_at)).toLocaleString()
        : "—";
      const label = row.name || row.objective || row.target || "—";
      const engId = row.engagement_dir || row.id || "";
      tr.innerHTML = `
<td class="py-sm pr-md"><span class="font-label-md text-on-surface">${escapeHtml(label)}</span>
<span class="block font-mono-md text-mono-md text-secondary">${escapeHtml(row.target || "—")}</span></td>
<td class="py-sm pr-md">${escapeHtml(row.status || "—")}</td>
<td class="py-sm pr-md">${row.phase ? `Fase ${row.phase}` : "—"}</td>
<td class="py-sm pr-md">${escapeHtml(started)}</td>
<td class="py-sm"><div class="flex flex-wrap gap-xs">${scanControlGroup(row, true)}</div></td>`;
      history.appendChild(tr);
    }
  }

  function cardFromRun(run, status) {
    if (!run?.target) return null;
    const elapsed = run.startedAt ? Math.max(0, Math.floor((Date.now() - run.startedAt) / 1000)) : (status?.elapsed_seconds || 0);
    return {
      active: true,
      name: run.name || status?.name || "",
      objective: run.objective || status?.objective || "",
      target: run.target || status?.target,
      scope: run.scope || status?.scope || run.target,
      phase: status?.phase || 1,
      phase_name: status?.phase_name || "",
      progress_pct: status?.progress_pct ?? (agentSeemsRunning() ? 15 : 5),
      elapsed_seconds: status?.elapsed_seconds ?? elapsed,
      current_activity: status?.current_activity || (agentSeemsRunning() ? "Agente en curso" : "Sesión local"),
      findings_accepted: status?.findings_accepted || 0,
      findings_pending: status?.findings_pending || 0,
      step_count: status?.step_count || 0,
      status_badge: status?.active ? (status.status_badge || "Scanning") : (agentSeemsRunning() ? "Running" : t("scans.localRun", "Sesión en este navegador")),
      bridge_gap: !status?.active,
      paused: !!status?.paused,
      run_status: status?.run_status || status?.status,
      status: status?.status || (status?.active ? "running" : "local"),
      engagement_dir: status?.engagement_dir || run.engagementDir || sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "",
    };
  }

  function clearLocalSessionIfMatch(deletedIds) {
    const gone = new Set(deletedIds || []);
    const run = loadRunFromStorage();
    const localId = run?.engagementDir || sessionStorage.getItem(ENGAGEMENT_ID_KEY) || "";
    const wipeSession = () => {
      sessionStorage.removeItem(RUN_KEY);
      sessionStorage.removeItem(ENGAGEMENT_ID_KEY);
      sessionStorage.removeItem("ds-findings-inbox");
      sessionStorage.removeItem("ds-findings-read");
      localStorage.removeItem(AGENT_HEARTBEAT_KEY);
      localStorage.removeItem(AGENT_OWNER_KEY);
      try {
        localStorage.setItem("ds-engagements-rev", String(Date.now()));
      } catch { /* */ }
    };
    // Tras borrar desde Escaneos activos: siempre limpia cachés de sesión
    // para que Dashboard / OSINT / MITRE no resuciten la tarjeta.
    if (!deletedIds || !deletedIds.length) return;
    if (localId && gone.has(localId)) {
      wipeSession();
      return;
    }
    wipeSession();
  }

  async function runScanAction(action, engId) {
    if (!engId || deleting) return;
    if (action === "finish") {
      const msg = t(
        "eng.finishConfirm",
        "¿Finalizar este escaneo? Los hallazgos se conservan; dejará de estar en curso.",
      );
      if (!window.confirm(msg)) return;
    }
    deleting = true;
    try {
      const result = await callEngagementControl(api, action, engId);
      if (action === "finish") {
        releaseAgentOwnership();
      }
      if (action === "resume" && result?.needs_engagement_page) {
        window.location.href = "engagement.html";
        return;
      }
      await poll();
    } catch (err) {
      window.alert(t("scans.actionFailed", "No se pudo completar la acción") + ": " + (err.message || err));
    } finally {
      deleting = false;
    }
  }

  async function deleteScan(engId) {
    if (!engId || deleting) return;
    const msg = [
      t("scans.deleteConfirm", "¿Eliminar este escaneo y todos sus hallazgos del disco? Dashboard, OSINT, MITRE e informes dejarán de mostrarlos."),
      t("scans.deleteRelated", "También se borrarán ejecuciones duplicadas del mismo target/objetivo."),
    ].join("\n\n");
    if (!window.confirm(msg)) return;
    deleting = true;
    try {
      let result = null;
      if (api && typeof api.bridge.deleteEngagement === "function") {
        result = await api.bridge.deleteEngagement(engId, true);
      } else {
        const token = sessionStorage.getItem(TOKEN_KEY) || "";
        const res = await fetch(`${engineBase()}/engagements/delete`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "X-Auditor-Token": token } : {}),
          },
          body: JSON.stringify({ engagement_dir: engId, related: true }),
        });
        result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);
      }
      const deleted = result?.deleted || [engId];
      clearLocalSessionIfMatch(deleted);
      await poll();
    } catch (err) {
      window.alert(t("scans.deleteFailed", "No se pudo eliminar el escaneo") + ": " + (err.message || err));
    } finally {
      deleting = false;
    }
  }

  if (!live.dataset.deleteBound) {
    live.dataset.deleteBound = "1";
    live.addEventListener("click", (ev) => {
      const actionBtn = ev.target.closest("[data-scan-action]");
      if (actionBtn) {
        ev.preventDefault();
        runScanAction(actionBtn.getAttribute("data-scan-action"), actionBtn.getAttribute("data-scan-id"));
        return;
      }
      const btn = ev.target.closest("[data-delete-scan]");
      if (!btn) return;
      ev.preventDefault();
      deleteScan(btn.getAttribute("data-delete-scan"));
    });
  }

  const paint = (status, engagements) => {
    const run = loadRunFromStorage();
    const list = Array.isArray(engagements) ? engagements : (status?.history || []);
    let card = null;
    if (status?.active) {
      card = {
        ...status,
        name: status.name || run?.name || "",
        objective: status.objective || run?.objective || "",
        engagement_dir: resolveEngagementId(status, list),
      };
      saveRunToStorage({
        name: card.name,
        objective: card.objective,
        target: status.target,
        scope: status.scope || status.target,
        model: sessionStorage.getItem(MODEL_KEY) || run?.model || "",
        useAi: run?.useAi,
        endpoint: OLLAMA_CHAT_ENDPOINT,
        startedAt: run?.startedAt || Date.now(),
        engagementDir: card.engagement_dir,
      });
      if (card.engagement_dir) sessionStorage.setItem(ENGAGEMENT_ID_KEY, card.engagement_dir);
    } else {
      card = cardFromRun(run, status);
      if (card && !card.engagement_dir) {
        card.engagement_dir = resolveEngagementId({ ...status, target: card.target }, list);
      }
      if (!card) {
        const activeRow = list.find((e) => e.active);
        if (activeRow) {
          card = {
            active: true,
            name: activeRow.name || "",
            target: activeRow.target,
            scope: activeRow.scope,
            phase: activeRow.phase || 1,
            progress_pct: 10,
            elapsed_seconds: 0,
            findings_accepted: activeRow.findings_accepted || 0,
            findings_pending: activeRow.findings_pending || 0,
            step_count: activeRow.step_count || 0,
            status_badge: "Scanning",
            engagement_dir: activeRow.engagement_dir || activeRow.id || "",
          };
        }
      }
    }

    renderHistory(list);
    if (card) {
      empty.hidden = true;
      live.hidden = false;
      cards.innerHTML = renderCard(card);
    } else if (list.length) {
      empty.hidden = true;
      live.hidden = false;
      cards.innerHTML = "";
    } else {
      empty.hidden = false;
      live.hidden = true;
      const lead = empty.querySelector("[data-i18n='empty.lead']");
      if (lead) lead.textContent = t("scans.emptyLead", lead.textContent);
    }
    if (window.lucide) lucide.createIcons();
  };

  const poll = async () => {
    let status = { active: false };
    let engagements = [];
    try {
      if (api) status = await api.bridge.getStatus();
    } catch { /* */ }
    try {
      if (api && typeof api.bridge.listEngagements === "function") {
        const data = await api.bridge.listEngagements();
        engagements = (data && data.engagements) || status.history || [];
      } else {
        engagements = status.history || [];
      }
    } catch {
      engagements = status.history || [];
    }
    paint(status, engagements);
  };

  try {
    api = await loadEngine();
    await ensureSession(api);
  } catch {
    paint({ active: false }, []);
    return;
  }

  await poll();
  setInterval(poll, 4000);
}

const page = pageName();
if (page === "start-engagement.html") bootStart();
else if (page === "engagement.html") bootEngagement();
else if (page === "active-scans.html") bootActiveScans();
