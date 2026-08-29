import { llmChat } from "./bridge_client.js";

const DEFAULT_URL = "https://ollama.com/v1/chat/completions";

// Kept in sync by hand with bridge.py's ALLOWED_TOOLS — this is what the
// model is told exists, the bridge is what actually enforces it.
const ALLOWED_TOOLS_HINT = [
  "nmap", "gobuster", "ffuf", "nikto", "whatweb", "hydra", "sqlmap",
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

const RESPONSE_CONTRACT = `You must respond with ONLY a JSON object, no prose, no markdown fences.
Either:
{"tool": "<binary name>", "args": ["<arg1>", "<arg2>", ...], "reasoning": "<why>"}
or, if the engagement objective is complete:
{"done": true, "reasoning": "<why>"}

"tool" must be exactly one binary name from this list — never a shell like
bash/sh/zsh/cmd/powershell, never a full command string:
${ALLOWED_TOOLS_HINT.join(", ")}
"args" is that binary's own argv, each element a SEPARATE argument (the way
you'd pass them to subprocess.run(["tool", "arg1", "arg2"]), never one
combined command string.`;

export async function askAgent({ model, systemPrompt, userPrompt, endpoint }) {
  const url = endpoint || DEFAULT_URL;

  const data = await llmChat(url, {
    model,
    stream: false,
    messages: [
      { role: "system", content: `${systemPrompt}\n\n${RESPONSE_CONTRACT}` },
      { role: "user", content: userPrompt },
    ],
  });
  // OpenAI-compatible shape (cloud): data.choices[0].message.content
  // Native ollama shape (local): data.message.content
  const raw = data.choices?.[0]?.message?.content ?? data.message?.content ?? "";
  let parsed;
  try {
    parsed = JSON.parse(raw.trim());
  } catch (e) {
    throw new Error(`ollama_invalid_json: ${raw.slice(0, 200)}`);
  }
  if (parsed.done) return { done: true, reasoning: parsed.reasoning ?? "" };
  if (!parsed.tool) throw new Error(`ollama_missing_tool_field: ${raw.slice(0, 200)}`);
  if (SHELL_WRAPPERS.has(parsed.tool)) {
    throw new Error(`ollama_shell_wrapper_rejected: model proposed "${parsed.tool}" instead of a real tool`);
  }
  return { tool: parsed.tool, args: parsed.args ?? [], reasoning: parsed.reasoning ?? "" };
}
