function resolveBridgeUrl() {
  if (typeof window !== "undefined") {
    const port = window.location.port;
    if (port === "8080" || port === "8081") {
      return `${window.location.protocol}//${window.location.hostname}:${port}/bridge`;
    }
  }
  return "http://127.0.0.1:8420";
}

let BRIDGE_URL = resolveBridgeUrl();
let sessionToken = null;
let activeEngagementDir = null;

export function setActiveEngagementDir(dir) {
  activeEngagementDir = dir || null;
}

export function getActiveEngagementDir() {
  return activeEngagementDir;
}

function withEngagementDir(body) {
  const out = { ...(body || {}) };
  if (activeEngagementDir && out.engagement_dir == null) {
    out.engagement_dir = activeEngagementDir;
  }
  return out;
}

export function setBridgeUrl(url) {
  if (url) BRIDGE_URL = url.replace(/\/$/, "");
}

export function getBridgeUrl() {
  return BRIDGE_URL;
}

export function setSessionToken(token) {
  sessionToken = token;
}

export async function fetchSession() {
  const res = await fetch(`${BRIDGE_URL}/session`, { cache: "no-store" });
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (res.ok && data.token) {
    setSessionToken(data.token);
    return data;
  }
  throw new Error(data.error || data.hint || "bridge_session_unavailable");
}

export async function verifyOllamaKey(apiKey) {
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const res = await fetch(`${origin}/api/verify-ollama-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error === "invalid_api_key"
      ? "invalid_api_key"
      : `verify_error_${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

export class QuotaExhaustedError extends Error {
  constructor(retryAfterHint) {
    super("all_keys_exhausted");
    this.retryAfterHint = retryAfterHint;
  }
}

async function postJSON(path, body, _retrying = false) {
  if (!sessionToken) {
    // Sin token en memoria (primera carga de página o se perdió por
    // recarga): intentar obtenerlo antes de fallar directamente.
    try {
      await fetchSession();
    } catch {
      throw new Error("missing_session_token");
    }
  }
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Auditor-Token": sessionToken },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  const meta = Array.isArray(data) ? null : data;
  if (res.status === 503 && meta?.error === "all_keys_exhausted") {
    throw new QuotaExhaustedError(meta.retry_after_hint);
  }
  // 401 = token inválido: el motor se reinició (rota AUTH_TOKEN en cada
  // arranque) y esta pestaña se quedó con el token viejo. Sin este
  // reintento, TODA llamada posterior (status, findings, exec) fallaría en
  // silencio para siempre — es la causa típica de "dejó de detectar
  // hallazgos y el panel no reacciona" en un engagement que lleva rato
  // abierto. Refrescar el token una vez y reintentar la misma petición.
  if (res.status === 401 && !_retrying) {
    try {
      await fetchSession();
      return postJSON(path, body, true);
    } catch {
      throw new Error(`bridge_error_401: ${JSON.stringify(data)}`);
    }
  }
  if (!res.ok && res.status !== 403 && res.status !== 409) {
    throw new Error(`bridge_error_${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

export async function listKeys() {
  const data = await postJSON("/keys/list", {});
  return Array.isArray(data) ? data : [];
}

export function startEngagement(target, scope, opts = {}) {
  const body = { target, scope };
  if (opts.name != null) body.name = opts.name;
  if (opts.objective != null) body.objective = opts.objective;
  if (opts.useAi != null) body.use_ai = !!opts.useAi;
  return postJSON("/engagement/start", body).then((data) => {
    if (data && data.engagement_dir) setActiveEngagementDir(data.engagement_dir);
    return data;
  });
}

export async function execTool(tool, args, target) {
  const data = await postJSON("/exec", withEngagementDir({ tool, args, target }));
  if (data.verdict && data.stdout === undefined) {
    return {
      stdout: "",
      stderr: data.error || data.verdict,
      exit_code: data.exit_code ?? -1,
      verdict: data.verdict,
    };
  }
  return data;
}

export async function scanSource(tool, filename, content, target) {
  const data = await postJSON("/tools/scan-source", withEngagementDir({ tool, filename, content, target }));
  if (data.verdict && data.stdout === undefined) {
    return { stdout: "", stderr: data.error || data.verdict, exit_code: data.exit_code ?? -1, verdict: data.verdict };
  }
  return data;
}

export function llmChat(endpoint, payload) {
  return postJSON("/llm/chat", { endpoint, payload });
}

export function listModels(endpoint) {
  return postJSON("/llm/models", { endpoint });
}

export function deleteKey(label) {
  return postJSON("/keys/delete", { label });
}

export function updateKey(label, windowHours, newLabel) {
  const body = { label };
  if (windowHours != null) body.window_hours = windowHours;
  if (newLabel) body.new_label = newLabel;
  return postJSON("/keys/update", body);
}

export function addKey(label, apiKey, windowHours, verify = true) {
  return postJSON("/keys/add", {
    label: label || undefined,
    api_key: apiKey,
    window_hours: windowHours,
    verify,
  });
}

export function selectKeys(labels) {
  return postJSON("/keys/select", { labels });
}

export function advancePhase() {
  return postJSON("/phase/advance", withEngagementDir({}));
}

export function getStatus() {
  return postJSON("/status", {});
}

export function listEngagements() {
  return postJSON("/engagements/list", {});
}

export function deleteEngagement(engagementDir, related = true) {
  return postJSON("/engagements/delete", {
    engagement_dir: engagementDir,
    related: !!related,
  });
}

export function pauseEngagement(engagementDir = "") {
  return postJSON("/engagements/pause", engagementDir ? { engagement_dir: engagementDir } : {});
}

export function resumeEngagement(engagementDir = "") {
  return postJSON("/engagements/resume", engagementDir ? { engagement_dir: engagementDir } : {});
}

export function finishEngagement(engagementDir = "") {
  return postJSON("/engagements/finish", engagementDir ? { engagement_dir: engagementDir } : {});
}

export function proposeFinding(finding) {
  return postJSON("/findings/propose", withEngagementDir(finding));
}

export function listFindings(engagementDir) {
  const dir = engagementDir || activeEngagementDir;
  return postJSON("/findings/list", dir ? { engagement_dir: dir } : {});
}

export function listEngagementFindings(engagementDir) {
  return postJSON("/engagements/findings", { engagement_dir: engagementDir });
}

export function reviewFinding(findingId, action, extra = {}) {
  return postJSON("/findings/review", withEngagementDir({ finding_id: findingId, action, ...extra }));
}
