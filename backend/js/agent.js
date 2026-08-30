import { askAgent } from "./ollama.js";
import { execTool, QuotaExhaustedError, proposeFinding } from "./bridge_client.js";
import { checkAndRecordAxis } from "./axis.js";
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
  1: ["nmap", "whatweb", "dig", "nslookup", "dnsrecon", "ldapsearch",
      "enum4linux", "rpcclient", "echo", "curl"],
  2: ["gobuster", "ffuf", "nikto", "smbclient", "GetNPUsers.py",
      "GetUserSPNs.py", "bloodhound-python", "lookupsid.py", "samrdump.py",
      "searchsploit", "adscan", "certipy"],
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
  return blob.replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/)
    .filter((w) => w.length > 3)
    .sort()
    .slice(0, 6)
    .join("-");
}

function stepOutput(step) {
  if (step.verdict === "agent_error" || step.tool === "(agent)") return "";
  const out = step.output ?? step.stdout ?? "";
  return String(out).slice(0, 800);
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
    prompt += `\n\nWARNING: you already tried this exact (tool, args) 3 times with no new information. Change a parameter or try a different vector.`;
  }
  return prompt;
}

const MAX_CONSECUTIVE_AGENT_ERRORS = 5;

export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {}, onFindingProposed = () => {}, phaseState }) {
  let steps = await getSteps(db, engagementId);
  let axisWarning = false;
  let agentErrorHint = "";
  let reportedTitles = [];
  let consecutiveErrors = 0;
  let duplicateStreak = 0;
  const seenFindings = new Set();
  const JSON_ONLY_HINT = "\n\nJSON only: {\"tool\":\"...\",\"args\":[...]} or {\"finding\":{...}} or {\"done\":true}. No prose.";

  while (true) {
    let decision;
    try {
      decision = await askAgent({
        model,
        systemPrompt,
        userPrompt: buildUserPrompt(target, steps, axisWarning, phaseState.current, reportedTitles) + agentErrorHint,
        endpoint,
      });
    } catch (err) {
      if (err instanceof QuotaExhaustedError) {
        const stepId = await addStep(db, {
          engagementId, tool: "(agent)", args: [],
          output: "", stderr: `all API keys exhausted, retry in ~${Math.ceil(err.retryAfterHint / 60)}min`,
          exitCode: -1, verdict: "waiting_for_quota",
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: "(agent)", args: [],
          stderr: `all API keys exhausted, retry in ~${Math.ceil(err.retryAfterHint / 60)}min`,
          verdict: "waiting_for_quota",
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
          stderr: "El modelo no devolvió JSON válido. Revisá el modelo y reiniciá el engagement.",
          verdict: "agent_error",
        }));
        return;
      }
      continue;
    }
    consecutiveErrors = 0;
    agentErrorHint = "";

    if (decision.done) {
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
      try {
        const finding = await proposeFinding(decision.finding);
        if (finding.duplicate) {
          seenFindings.add(fp);
          reportedTitles.push(finding.title);
          duplicateStreak += 1;
          agentErrorHint = `\n\nFinding already logged (${finding.title}). Do not repeat. Next: a different issue, a tool, or {"done":true}.`;
          if (duplicateStreak >= 12) return;
          continue;
        }
        seenFindings.add(fp);
        reportedTitles.push(finding.title);
        duplicateStreak = 0;
        const summary = `${finding.title} [${finding.severity}] ${finding.asset}`;
        const stepId = await addStep(db, {
          engagementId, tool: "(finding)", args: [finding.id],
          output: summary, stderr: "", exitCode: 0, verdict: "ok",
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: "(finding)", args: [finding.id],
          output: summary, verdict: "ok",
        });
        steps = [...steps, step];
        onFindingProposed(finding);
      } catch (err) {
        consecutiveErrors += 1;
        agentErrorHint = JSON_ONLY_HINT;
        if (consecutiveErrors >= MAX_CONSECUTIVE_AGENT_ERRORS) return;
        continue;
      }
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
        });
        const step = normalizeStep(stepId, engagementId, {
          tool: decision.tool, args: decision.args,
          stderr: "rejected by operator", verdict: "rejected",
        });
        steps = [...steps, step];
        onStep(step);
        continue;
      }
    }

    try {
      const result = await execTool(decision.tool, decision.args, target);
      const stepId = await addStep(db, {
        engagementId, tool: decision.tool, args: decision.args,
        output: result.stdout, stderr: result.stderr,
        exitCode: result.exit_code, verdict: result.verdict,
      });
      const step = normalizeStep(stepId, engagementId, {
        tool: decision.tool, args: decision.args,
        output: result.stdout, stderr: result.stderr,
        exitCode: result.exit_code, verdict: result.verdict,
      });
      steps = [...steps, step];
      onStep(step);

      const axisResult = await checkAndRecordAxis(db, engagementId, decision.tool, decision.args, result.stdout ?? "");
      axisWarning = axisResult.warn;
      duplicateStreak = 0;
    } catch (err) {
      if (err instanceof QuotaExhaustedError) throw err;
      const stepId = await addStep(db, {
        engagementId, tool: decision.tool, args: decision.args,
        output: "", stderr: err.message, exitCode: -1, verdict: "error",
      });
      const step = normalizeStep(stepId, engagementId, {
        tool: decision.tool, args: decision.args,
        stderr: err.message, verdict: "error",
      });
      steps = [...steps, step];
      onStep(step);
    }
  }
}
