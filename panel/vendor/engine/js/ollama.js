import { llmChat, QuotaExhaustedError } from "./bridge_client.js";

const DEFAULT_URL = "https://ollama.com/v1/chat/completions";

const ALLOWED_TOOLS_HINT = [
  "nmap", "gobuster", "ffuf", "feroxbuster", "nikto", "whatweb", "wpscan", "hydra", "sqlmap",
  "hashcat", "john", "curl", "dig", "nslookup", "smbclient", "rpcclient",
  "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py", "wmiexec.py",
  "psexec.py", "certipy", "bloodhound-python", "ldapsearch", "enum4linux",
  "crackmapexec", "netexec", "echo",
  "ntlmrelayx.py", "smbexec.py", "atexec.py", "lookupsid.py",
  "samrdump.py", "mssqlclient.py", "ticketer.py", "getST.py",
  "raiseChild.py", "dcomexec.py", "adscan",
  "dnsrecon", "searchsploit",
];

const SHELL_WRAPPERS = new Set(["bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"]);

const RESPONSE_CONTRACT = `You must respond with ONLY a JSON object, no prose, no markdown fences, no <think> blocks.
Either:
{"tool": "<binary name>", "args": ["<arg1>", "<arg2>", ...], "reasoning": "<why>"}
or, if the engagement objective is complete:
{"done": true, "reasoning": "<why>"}
or, if you have gathered enough evidence to report a real vulnerability finding:
{"finding": {"title": "<short title>", "asset": "<host/url/target this applies to>",
  "severity": "Critical"|"High"|"Medium"|"Low"|"Info",
  "description": "<what it is and why it matters>",
  "remediation": "<how to fix it>",
  "evidence_step_ids": [<the #N ids shown before each step in Recent history that prove this>]},
 "reasoning": "<why you're reporting this now>"}

"tool" must be exactly one binary name from this list — never a shell like
bash/sh/zsh/cmd/powershell, never a full command string:
${ALLOWED_TOOLS_HINT.join(", ")}
"args" is that binary's own argv, each element a SEPARATE argument (the way
you'd pass them to subprocess.run(["tool", "arg1", "arg2"]), never one
combined command string. Split flags: use ["-p","8888"] not ["-p 8888"].
Always pass -s (silent) as curl's first arg — otherwise its progress meter
pollutes the captured output.
Read the Recent history outputs before repeating a scan. Do not re-run the same nmap/whatweb/curl if you already have the result.
If history already identified DVWA (login.php, cookie security=low), propose a finding with that evidence instead of scanning again. Skip nikto unless the operator is in phase 2 and you still lack HTTP info.
Reporting a finding does NOT end the engagement — keep working after it.`;

const JSON_RETRY_HINT = `

CRITICAL: Your previous reply was not valid JSON or omitted "tool"/"done"/"finding". Reply with ONE JSON object only.
Example: {"tool":"curl","args":["-s","-i","http://127.0.0.1:8888/login.php"],"reasoning":"read login page"}`;

function flattenContent(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((part) => {
      if (typeof part === "string") return part;
      if (!part || typeof part !== "object") return "";
      return part.text || part.content || part.output_text || part.reasoning || part.thinking || "";
    }).join("\n");
  }
  if (typeof value === "object") {
    return value.text || value.content || JSON.stringify(value);
  }
  return String(value);
}

function collectMessageText(data) {
  const msg = data.choices?.[0]?.message ?? data.message ?? {};
  const toolArgs = (msg.tool_calls || [])
    .map((c) => c.function?.arguments || c.arguments || "")
    .filter(Boolean)
    .join("\n");
  const harvested = harvestStrings(data).filter((s) => s.includes("{") && /tool|done|finding/.test(s));
  const parts = [
    flattenContent(msg.content),
    flattenContent(msg.reasoning),
    flattenContent(msg.reasoning_content),
    flattenContent(msg.thinking),
    flattenContent(msg.parsed),
    flattenContent(data.response),
    flattenContent(data.choices?.[0]?.text),
    toolArgs,
    ...harvested,
  ].filter((x) => typeof x === "string" && x.trim());
  return [...new Set(parts)].join("\n");
}

function harvestStrings(value, acc = []) {
  if (typeof value === "string") {
    if (value.trim()) acc.push(value);
    return acc;
  }
  if (Array.isArray(value)) {
    for (const item of value) harvestStrings(item, acc);
    return acc;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) harvestStrings(item, acc);
  }
  return acc;
}

function apiSnapshot(data) {
  const msg = data.choices?.[0]?.message ?? data.message ?? {};
  return JSON.stringify({
    keys: Object.keys(msg),
    finish: data.choices?.[0]?.finish_reason,
    contentType: typeof msg.content,
    error: data.error || undefined,
  }).slice(0, 400);
}

function stripReasoning(text) {
  return String(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .replace(/<\|channel\|>analysis[\s\S]*?<\|channel\|>final/gi, "")
    .replace(/<\|[^|>]+\|>/g, "\n")
    .replace(/```(?:json)?/gi, "")
    .trim();
}

function tryParseJson(text) {
  const repaired = text
    .replace(/,\s*}/g, "}")
    .replace(/,\s*]/g, "]");
  try {
    return JSON.parse(text);
  } catch {
    return JSON.parse(repaired);
  }
}

function parseAgentJson(raw) {
  const cleaned = stripReasoning(raw);
  const candidates = [cleaned];
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start >= 0 && end > start) {
    candidates.push(cleaned.slice(start, end + 1));
  }
  const keyed = cleaned.match(/\{[\s\S]*?"(?:tool|done|finding|command|binary)"[\s\S]*\}/);
  if (keyed) candidates.push(keyed[0]);

  let lastErr;
  for (const candidate of candidates) {
    try {
      return tryParseJson(candidate);
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(`ollama_invalid_json: ${String(raw).slice(0, 240)}${lastErr ? ` (${lastErr.message})` : ""}`);
}

function normalizeArgs(args) {
  let list;
  if (Array.isArray(args)) list = args.map(String);
  else if (typeof args === "string" && args.trim()) {
    list = args.match(/(?:[^\s"]+|"[^"]*")+/g)?.map((a) => a.replace(/^"|"$/g, "")) || [args];
  } else if (args && typeof args === "object") {
    list = Object.values(args).map(String);
  } else {
    list = [];
  }
  const out = [];
  for (const item of list) {
    if (/^-[A-Za-z]+\s+\S/.test(item)) out.push(...item.split(/\s+/));
    else out.push(item);
  }
  return out;
}

function splitToolAndArgs(tool, args) {
  const argv = normalizeArgs(args);
  if (typeof tool === "string" && tool.includes(" ")) {
    const parts = tool.trim().split(/\s+/);
    return { tool: parts[0], args: [...parts.slice(1), ...argv] };
  }
  return { tool, args: argv };
}

function coerceFinding(finding) {
  const sevMap = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const severity = sevMap[String(finding.severity || "info").toLowerCase()] || "Info";
  let ids = finding.evidence_step_ids;
  if (!Array.isArray(ids)) ids = [];
  ids = ids.map((id) => {
    if (typeof id === "number" && Number.isFinite(id)) return id;
    const n = parseInt(String(id).replace(/^#/, ""), 10);
    return Number.isFinite(n) ? n : id;
  });
  return {
    title: String(finding.title || "Untitled finding").trim() || "Untitled finding",
    asset: String(finding.asset || "").trim() || "unknown",
    severity,
    description: String(finding.description || finding.impact || "").trim() || "(sin descripción)",
    remediation: String(finding.remediation || finding.fix || "").trim() || "(sin remediación)",
    evidence_step_ids: ids,
  };
}

function decisionFromParsed(parsed, raw) {
  if (parsed.done === true || parsed.action === "done") {
    return { done: true, reasoning: parsed.reasoning ?? "" };
  }
  if (parsed.finding) {
    return { finding: coerceFinding(parsed.finding), reasoning: parsed.reasoning ?? "" };
  }
  const nested = parsed.action && typeof parsed.action === "object" ? parsed.action : parsed;
  const tool = nested.tool || nested.command || nested.binary || nested.name;
  if (!tool) {
    throw new Error("ollama_missing_tool_field: el JSON no trae tool, done ni finding");
  }
  const { tool: splitTool, args } = splitToolAndArgs(
    tool,
    nested.args ?? nested.argv ?? nested.parameters ?? nested.arguments ?? [],
  );
  if (SHELL_WRAPPERS.has(splitTool)) {
    throw new Error(`ollama_shell_wrapper_rejected: model proposed "${splitTool}" instead of a real tool`);
  }
  return { tool: splitTool, args, reasoning: parsed.reasoning ?? nested.reasoning ?? "" };
}

async function chatOnce(url, model, messages, { think } = { think: false }) {
  const base = { model, stream: false, temperature: 0, messages };
  if (think === false) base.think = false;
  let data;
  try {
    data = await llmChat(url, base);
  } catch (err) {
    if (think === false && /think|unknown.?field/i.test(err.message)) {
      return chatOnce(url, model, messages, { think: true });
    }
    throw err;
  }
  if (data.error && !data.choices && !data.message) {
    const msg = typeof data.error === "string" ? data.error : JSON.stringify(data.error);
    if (think === false && /think|unknown.?field/i.test(msg)) {
      return chatOnce(url, model, messages, { think: true });
    }
    throw new Error(`llm_error: ${msg}`);
  }
  const raw = collectMessageText(data);
  if (!raw.trim()) {
    throw new Error(`ollama_empty_content: ${apiSnapshot(data)}`);
  }
  return decisionFromParsed(parseAgentJson(raw), raw);
}

export async function askAgent({ model, systemPrompt, userPrompt, endpoint }) {
  const url = endpoint || DEFAULT_URL;
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const hint = attempt === 0 ? "" : JSON_RETRY_HINT;
    try {
      return await chatOnce(url, model, [
        { role: "system", content: `${systemPrompt}\n\n${RESPONSE_CONTRACT}` },
        { role: "user", content: userPrompt + hint },
      ]);
    } catch (err) {
      if (err instanceof QuotaExhaustedError) throw err;
      lastErr = err;
    }
  }
  throw lastErr;
}
