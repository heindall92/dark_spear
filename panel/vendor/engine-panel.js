const ENGINE_DEFAULT = "http://127.0.0.1:8420";
const TOKEN_KEY = "ds-engine-token";
const URL_KEY = "ds-engine-url";
const RUN_KEY = "ds-engine-run";

function engineBase() {
  return sessionStorage.getItem(URL_KEY) || ENGINE_DEFAULT;
}

function pageName() {
  return (location.pathname.split("/").pop() || "").toLowerCase();
}

function banner(el, msg, isError) {
  if (!el) return;
  el.hidden = false;
  el.textContent = msg;
  el.classList.toggle("border-error", !!isError);
}

async function loadEngine(base) {
  const [bridge, agent, db] = await Promise.all([
    import(`${base}/js/bridge_client.js`),
    import(`${base}/js/agent.js`),
    import(`${base}/js/db.js`),
  ]);
  return { bridge, agent, db };
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
  if (verdict === "rejected" || verdict === "scope_violation" || verdict === "phase_locked") {
    return "bg-error-container text-error border-error/20";
  }
  return "bg-surface-variant text-on-surface-variant border-outline-variant/30";
}

function renderPhaseBar(phase) {
  const fill = document.getElementById("phase-fill");
  if (fill) fill.style.width = `${Math.max(0, (phase - 1) / 3) * 100}%`;
  document.querySelectorAll("[data-phase-step]").forEach((el) => {
    const n = Number(el.getAttribute("data-phase-step"));
    const iconWrap = el.querySelector("[data-phase-icon]");
    const label = el.querySelector("[data-phase-label]");
    if (n < phase) {
      iconWrap.className = "w-8 h-8 rounded-full bg-tertiary-container text-on-tertiary-container flex items-center justify-center border-2 border-white shadow-sm";
      iconWrap.innerHTML = '<i data-lucide="check" class="icon-sm"></i>';
      if (label) label.className = "font-label-md text-label-md text-on-surface";
    } else if (n === phase) {
      iconWrap.className = "w-8 h-8 rounded-full bg-primary-container text-on-primary-container flex items-center justify-center border-2 border-primary-fixed shadow-md ring-4 ring-primary-container/20";
      iconWrap.innerHTML = n === 1
        ? '<i data-lucide="radar" class="icon-sm"></i>'
        : n === 2
          ? '<i data-lucide="search" class="icon-sm"></i>'
          : `<span class="font-label-md text-label-md">${n}</span>`;
      if (label) label.className = "font-label-md text-label-md text-primary-container font-bold";
    } else {
      iconWrap.className = "w-8 h-8 rounded-full bg-surface-variant text-outline flex items-center justify-center border-2 border-white";
      iconWrap.innerHTML = `<span class="font-label-md text-label-md">${n}</span>`;
      if (label) label.className = "font-label-md text-label-md text-outline";
    }
  });
  if (window.lucide) lucide.createIcons();
}

function appendStep(step) {
  if (step.tool === "(finding)") return;
  if (step.verdict === "agent_error") {
    const msg = String(step.stderr || "");
    if (msg.length > 180 || /ollama_|invalid_json|empty_content|missing_tool|bridge_error/.test(msg)) return;
  }
  if (step.tool === "(agent)" && step.verdict !== "waiting_for_quota" && step.verdict !== "agent_error") return;
  const feed = document.getElementById("engine-feed");
  if (!feed) return;
  const card = document.createElement("div");
  card.className = "glass-panel rounded-lg overflow-hidden flex flex-col hover:shadow-md transition-shadow";
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

function showConfirmModal(decision, onApprove, onReject) {
  const modal = document.getElementById("engine-confirm");
  const text = document.getElementById("engine-confirm-text");
  text.textContent = `${decision.tool} ${JSON.stringify(decision.args)} — ${decision.reasoning || ""}`;
  modal.hidden = false;
  const approve = document.getElementById("engine-confirm-approve");
  const reject = document.getElementById("engine-confirm-reject");
  const cleanup = () => {
    modal.hidden = true;
    approve.onclick = null;
    reject.onclick = null;
  };
  approve.onclick = () => { cleanup(); onApprove(); };
  reject.onclick = () => { cleanup(); onReject(); };
  if (window.lucide) lucide.createIcons();
}

async function bootStart() {
  const params = new URLSearchParams(location.search);
  const tokenInput = document.getElementById("engine-token");
  const targetInput = document.getElementById("target");
  const scopeInput = document.getElementById("scope");
  const modelInput = document.getElementById("model");
  const endpointInput = document.getElementById("endpoint");
  const keyList = document.getElementById("key-list");
  const cta = document.getElementById("primary-cta");
  const form = document.getElementById("start-form");
  const note = document.getElementById("engine-banner");
  const selected = new Set();

  const tokenFromUrl = params.get("token");
  if (tokenFromUrl) sessionStorage.setItem(TOKEN_KEY, tokenFromUrl);
  tokenInput.value = sessionStorage.getItem(TOKEN_KEY) || tokenFromUrl || "";
  if (params.get("target")) targetInput.value = params.get("target");
  if (params.get("scope")) scopeInput.value = params.get("scope");
  modelInput.value = modelInput.value || "gpt-oss:20b";
  if (!endpointInput.value) endpointInput.value = "https://ollama.com/v1/chat/completions";

  const syncCta = () => {
    const ok = tokenInput.value.trim() && targetInput.value.trim() && scopeInput.value.trim()
      && modelInput.value.trim() && selected.size > 0;
    if (ok) cta.removeAttribute("disabled");
    else cta.setAttribute("disabled", "true");
  };

  const renderKeys = (keys) => {
    keyList.innerHTML = "";
    if (!keys.length) {
      const empty = document.createElement("p");
      empty.className = "font-body-sm text-body-sm text-on-surface-variant";
      empty.setAttribute("data-i18n", "engine.noKeys");
      empty.textContent = "No hay keys en el motor. Agregá una de Ollama Cloud.";
      keyList.appendChild(empty);
      return;
    }
    for (const k of keys) {
      const row = document.createElement("label");
      row.className = "glass-panel rounded-lg p-md flex items-center justify-between cursor-pointer hover:bg-white/80 transition-colors";
      row.innerHTML = `
<div class="flex items-center gap-md min-w-0">
  <div class="bg-secondary-container text-on-secondary-container p-sm rounded flex items-center justify-center">
    <i data-lucide="key-round"></i>
  </div>
  <div class="flex flex-col min-w-0">
    <span class="font-label-md text-label-md text-on-surface">${k.label}</span>
    <span class="font-mono-md text-mono-md text-on-surface-variant">****${k.last4} · ${k.window_hours}h</span>
  </div>
</div>
<input class="w-5 h-5 text-primary-container border-outline-variant focus:ring-primary-container cursor-pointer key-checkbox" type="checkbox" value="${k.label}"/>`;
      const cb = row.querySelector("input");
      cb.checked = selected.has(k.label);
      cb.addEventListener("change", () => {
        if (cb.checked) selected.add(k.label);
        else selected.delete(k.label);
        syncCta();
      });
      keyList.appendChild(row);
    }
    if (window.lucide) lucide.createIcons();
  };

  let api;
  try {
    api = await loadEngine(engineBase());
  } catch (err) {
    banner(note, "No se pudo cargar el motor. Arrancá python3 bridge.py y recargá. " + err.message, true);
    return;
  }

  const refreshKeys = async () => {
    const token = tokenInput.value.trim();
    if (!token) {
      banner(note, "Falta el token. Usá la URL Panel que imprime bridge.py (incluye ?token=).", true);
      return;
    }
    sessionStorage.setItem(TOKEN_KEY, token);
    api.bridge.setSessionToken(token);
    try {
      const keys = await api.bridge.listKeys();
      banner(note, "Motor conectado. Seleccioná al menos una key y arrancá.", false);
      renderKeys(Array.isArray(keys) ? keys : []);
      syncCta();
    } catch (err) {
      banner(note, "El motor rechazó el token o no está en 127.0.0.1:8420. " + err.message, true);
    }
  };

  tokenInput.addEventListener("change", refreshKeys);
  tokenInput.addEventListener("blur", refreshKeys);
  ["target", "scope", "model"].forEach((id) => {
    document.getElementById(id).addEventListener("input", syncCta);
  });

  document.getElementById("add-key-btn").addEventListener("click", async () => {
    const label = document.getElementById("key-label").value.trim();
    const value = document.getElementById("key-value").value.trim();
    const windowHours = parseFloat(document.getElementById("key-window").value) || 24;
    if (!label || !value) return;
    api.bridge.setSessionToken(tokenInput.value.trim());
    try {
      await api.bridge.addKey(label, value, windowHours);
      document.getElementById("key-label").value = "";
      document.getElementById("key-value").value = "";
      selected.add(label);
      await refreshKeys();
    } catch (err) {
      banner(note, err.message, true);
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = tokenInput.value.trim();
    const target = targetInput.value.trim();
    const scope = scopeInput.value.trim();
    const model = modelInput.value.trim();
    const endpoint = endpointInput.value.trim();
    if (!token || !target || !scope || !model || selected.size === 0) return;
    api.bridge.setSessionToken(token);
    sessionStorage.setItem(TOKEN_KEY, token);
    try {
      await api.bridge.selectKeys([...selected]);
      await api.bridge.startEngagement(target, scope);
      sessionStorage.setItem(RUN_KEY, JSON.stringify({ target, scope, model, endpoint }));
      location.href = "engagement.html";
    } catch (err) {
      banner(note, err.message, true);
    }
  });

  if (tokenInput.value.trim()) await refreshKeys();
  else banner(note, "Arrancá el motor y abrí la URL Panel con ?token=…, o pegá el token aquí.", false);
  if (window.lucide) lucide.createIcons();
  syncCta();
}

async function bootEngagement() {
  const note = document.getElementById("engine-banner");
  const token = sessionStorage.getItem(TOKEN_KEY);
  const run = JSON.parse(sessionStorage.getItem(RUN_KEY) || "null");
  if (!token || !run) {
    banner(note, "No hay engagement activo. Iniciá uno desde New Scan con el token del motor.", true);
    return;
  }

  document.getElementById("engine-target-crumb").textContent = run.target;
  document.getElementById("engine-target-lead").textContent = run.target;

  let api;
  try {
    api = await loadEngine(engineBase());
  } catch (err) {
    banner(note, "No se pudo cargar el motor. " + err.message, true);
    return;
  }
  api.bridge.setSessionToken(token);
  banner(note, `Motor en vivo · ${run.target}`, false);

  const phaseState = { current: 1 };
  renderPhaseBar(1);

  document.getElementById("advance-phase-btn").addEventListener("click", async () => {
    try {
      const result = await api.bridge.advancePhase();
      phaseState.current = result.phase;
      renderPhaseBar(phaseState.current);
    } catch (err) {
      banner(note, err.message, true);
    }
  });

  const db = await api.db.initDB();
  const engagementId = await api.db.createEngagement(db, { target: run.target, scope: run.scope });

  document.getElementById("engine-export-btn")?.addEventListener("click", async () => {
    const data = await api.db.exportEngagementJSON(db, engagementId);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dark-spear-${run.target}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  const findingsBtn = document.getElementById("engine-findings-btn");
  const findingsPanel = document.getElementById("engine-findings");
  const findingsList = document.getElementById("engine-findings-list");

  async function refreshFindings() {
    if (!findingsBtn || !findingsList) return;
    try {
      const raw = await api.bridge.listFindings();
      const findings = Array.isArray(raw) ? raw : [];
      const pending = findings.filter((f) => f.status === "proposed").length;
      findingsBtn.textContent = `Hallazgos (${pending})`;
      findingsList.innerHTML = "";
      for (const f of findings) {
        if (window.DarkSpearFindings) DarkSpearFindings.push(f);
        const card = document.createElement("div");
        card.className = "glass-panel rounded-lg p-md flex flex-col gap-sm";
        card.innerHTML = `<span class="font-label-md">${f.severity} — ${f.status}</span>
          <strong class="font-headline-md">${f.title}</strong>
          <p class="font-body-sm text-on-surface-variant">${f.description || ""}</p>`;
        if (f.status === "proposed" || f.status === "edited") {
          const row = document.createElement("div");
          row.className = "flex gap-sm";
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
    } catch {
      /* no engagement yet */
    }
  }

  findingsBtn.addEventListener("click", async () => {
    await refreshFindings();
    findingsPanel.hidden = false;
  });
  document.getElementById("engine-findings-close").addEventListener("click", () => {
    findingsPanel.hidden = true;
  });

  const systemPrompt = `Eres un agente de pentest autorizado. Target en scope: ${run.target}. Laboratorio local (p.ej. DVWA). Trabaja paso a paso, una herramienta a la vez. Si el historial ya muestra un servidor HTTP, no repitas nmap: usa curl y propone hallazgos con evidencia. Responde solo JSON.`;

  api.agent.runAgentLoop({
    db,
    engagementId,
    model: run.model,
    target: run.target,
    systemPrompt,
    endpoint: run.endpoint || undefined,
    phaseState,
    onStep: appendStep,
    onPauseForConfirmation: (decision, resolve) => {
      showConfirmModal(decision, () => resolve(true), () => resolve(false));
    },
    onWaitingForQuota: () => {
      appendStep({ tool: "(agent)", args: [], verdict: "waiting_for_quota", stderr: "Keys agotadas, esperando cuota." });
    },
    onFindingProposed: async (finding) => {
      if (window.DarkSpearFindings) DarkSpearFindings.push(finding);
      await refreshFindings();
      findingsPanel.hidden = false;
    },
  }).catch((err) => {
    appendStep({ tool: "(agent)", args: [], verdict: "agent_error", stderr: err.message });
  });
}

const page = pageName();
if (page === "start-engagement.html") bootStart();
else if (page === "engagement.html") bootEngagement();
