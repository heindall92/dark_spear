import { getAxisEntry, upsertAxisEntry } from "./db.js";

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return h.toString(16);
}

const CURL_COSMETIC_FLAGS = new Set([
  "-s", "-S", "-v", "-i", "-I", "-L", "-k", "--silent", "--verbose", "--include", "--head",
  "--location", "--insecure",
]);

function normalizeUrl(raw) {
  const url = String(raw || "").trim().replace(/;$/, "");
  if (!url) return "";
  try {
    const u = new URL(url);
    const params = [...u.searchParams.entries()].sort((a, b) =>
      a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
    u.search = "";
    for (const [k, v] of params) u.searchParams.append(k, v);
    let out = u.toString();
    if (out.endsWith("?")) out = out.slice(0, -1);
    return out.toLowerCase();
  } catch {
    return url.toLowerCase().replace(/\?$/, "");
  }
}

function normalizeFormBody(body) {
  const raw = String(body || "").trim();
  if (!raw) return "";
  if (!raw.includes("&") && !raw.includes("=")) return raw.toLowerCase();
  return raw.split("&").map((p) => p.trim()).filter(Boolean).sort().join("&").toLowerCase();
}

function normalizeCookieFingerprint(raw) {
  return String(raw || "")
    .split(";")
    .map((part) => part.trim().split("=")[0])
    .filter(Boolean)
    .sort()
    .join(";");
}

function normalizeCurlArgs(args) {
  const arr = Array.isArray(args) ? [...args] : [];
  let method = "GET";
  let url = "";
  let data = "";
  let cookies = "";
  const headers = [];

  for (let i = 0; i < arr.length; i++) {
    const a = String(arr[i]);
    if (a === "-X" && arr[i + 1]) {
      method = String(arr[++i]).toUpperCase();
      continue;
    }
    if ((a === "-d" || a === "--data" || a === "--data-raw" || a === "--data-binary") && arr[i + 1]) {
      data = String(arr[++i]);
      continue;
    }
    if ((a === "-b" || a === "--cookie") && arr[i + 1]) {
      cookies = normalizeCookieFingerprint(arr[++i]);
      continue;
    }
    if ((a === "-H" || a === "--header") && arr[i + 1]) {
      headers.push(String(arr[++i]).toLowerCase());
      continue;
    }
    if (a.startsWith("-")) {
      if (CURL_COSMETIC_FLAGS.has(a)) continue;
      continue;
    }
    if (/^https?:\/\//i.test(a)) url = a;
  }

  headers.sort();
  return {
    method,
    url: normalizeUrl(url),
    data: normalizeFormBody(data),
    cookies,
    headers,
  };
}

function normalizeGenericArgs(args) {
  return (Array.isArray(args) ? args : [])
    .map((a) => String(a).trim())
    .filter((a) => a.length > 0);
}

export function normalizeArgsForAxis(tool, args) {
  const t = String(tool || "").toLowerCase();
  if (t === "curl") return normalizeCurlArgs(args);
  return { argv: normalizeGenericArgs(args) };
}

export function paramsHash(tool, args) {
  const normalized = normalizeArgsForAxis(tool, args);
  return simpleHash(`${tool}:${JSON.stringify(normalized)}`);
}

export function resultHash(output) {
  const text = String(output || "");
  const compact = text
    .replace(/\x1b\[[0-9;]*m/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 500);
  return simpleHash(compact);
}

export async function peekAxis(db, engagementId, tool, args) {
  const pHash = paramsHash(tool, args);
  return getAxisEntry(db, engagementId, tool, pHash);
}

export async function peekAxisAgent(db, engagementId, tool, args) {
  const existing = await peekAxis(db, engagementId, tool, args);
  if (!existing) return null;
  return {
    agentAttemptCount: existing.agentAttemptCount ?? 0,
    lastResultHash: existing.lastResultHash,
  };
}

export async function checkAndRecordAxis(db, engagementId, tool, args, output, opts = {}) {
  const agent = opts.agent !== false;
  const pHash = paramsHash(tool, args);
  const rHash = resultHash(output);
  const existing = await getAxisEntry(db, engagementId, tool, pHash);
  const sameAsLast = existing && existing.lastResultHash === rHash;
  const agentAttemptCount = (existing?.agentAttemptCount ?? 0) + (agent ? 1 : 0);
  const playbookAttemptCount = (existing?.playbookAttemptCount ?? 0) + (agent ? 0 : 1);
  const attemptCount = (existing?.attemptCount ?? 0) + 1;
  await upsertAxisEntry(db, {
    engagementId,
    tool,
    paramsHash: pHash,
    attemptCount,
    agentAttemptCount,
    playbookAttemptCount,
    lastResultHash: rHash,
  });
  const agentCount = agent ? agentAttemptCount : (existing?.agentAttemptCount ?? 0);
  // Same paramsHash means same tool+target+payload, regardless of output —
  // DVWA-style pages embed a changing CSRF/session token per response, so
  // gating on identical output silently defeated this on repeated brute
  // attempts with fixed credentials.
  const warn = agent && agentCount >= 3;
  const blocked = agent && agentCount >= 6;
  return { attemptCount, agentAttemptCount: agentCount, warn, blocked, sameAsLast };
}
