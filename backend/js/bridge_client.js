const BRIDGE_URL = "http://127.0.0.1:8420";

let sessionToken = null;

export function setSessionToken(token) {
  sessionToken = token;
}

export class QuotaExhaustedError extends Error {
  constructor(retryAfterHint) {
    super("all_keys_exhausted");
    this.retryAfterHint = retryAfterHint;
  }
}

async function postJSON(path, body) {
  if (!sessionToken) {
    throw new Error("missing_session_token");
  }
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Auditor-Token": sessionToken },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (res.status === 503 && data.error === "all_keys_exhausted") {
    throw new QuotaExhaustedError(data.retry_after_hint);
  }
  if (!res.ok && res.status !== 403) {
    throw new Error(`bridge_error_${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

export function startEngagement(target, scope) {
  return postJSON("/engagement/start", { target, scope });
}

export function execTool(tool, args, target) {
  return postJSON("/exec", { tool, args, target });
}

export function llmChat(endpoint, payload) {
  return postJSON("/llm/chat", { endpoint, payload });
}

export function listKeys() {
  return postJSON("/keys/list", {});
}

export function addKey(label, apiKey, windowHours) {
  return postJSON("/keys/add", { label, api_key: apiKey, window_hours: windowHours });
}

export function selectKeys(labels) {
  return postJSON("/keys/select", { labels });
}

export function advancePhase() {
  return postJSON("/phase/advance", {});
}

export function proposeFinding(finding) {
  return postJSON("/findings/propose", finding);
}

export function listFindings() {
  return postJSON("/findings/list", {});
}

export function reviewFinding(findingId, action, extra = {}) {
  return postJSON("/findings/review", { finding_id: findingId, action, ...extra });
}
