#!/usr/bin/env node
/**
 * Wiring JS de HTTP Request Smuggling (CL.TE/TE.CL): step builder que
 * invoca la pseudo-herramienta "http-smuggle-probe" del bridge (conexión
 * TCP cruda, ver backend/bridge.py) y el heurístico que clasifica el
 * resultado. Vive en Fase 3 (mismo gate humano de avance de fase que
 * wmiexec/secretsdump): un desync real en un front-end compartido puede
 * afectar peticiones de otros usuarios, no solo del que prueba.
 */
import { smugglingProbeSteps, smugglingFinding } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const steps = smugglingProbeSteps((id, tool, args, verify, opts) => ({ id, tool, args, opts }), "p3-smuggle", "https://target.local:8443/app");
check("genera 2 steps (clte y tecl)", steps.length === 2);
check("usa la pseudo-herramienta http-smuggle-probe", steps.every((s) => s.tool === "http-smuggle-probe"));
check("step clte manda kind/host/port/path correctos", steps[0].args[0] === "clte" && steps[0].args[1] === "target.local" && steps[0].args[2] === "8443" && steps[0].args[3] === "/app");
check("step tecl manda kind tecl", steps[1].args[0] === "tecl");
check("puerto por defecto 443 para https sin puerto explícito", smugglingProbeSteps((id, tool, args) => ({ id, tool, args }), "p3-smuggle", "https://target.local/")[0].args[2] === "443");
check("puerto por defecto 80 para http sin puerto explícito", smugglingProbeSteps((id, tool, args) => ({ id, tool, args }), "p3-smuggle", "http://target.local/")[0].args[2] === "80");

// --- smugglingFinding: clasifica el JSON que devuelve send_raw_probe ---

check("timed_out true -> candidato (severidad alta, requiere confirmación manual)",
  smugglingFinding(JSON.stringify({ kind: "clte", timed_out: true, elapsed_ms: 8000 }), "/app").severity === "High");
check("timed_out false -> null (respuesta normal, no candidato)",
  smugglingFinding(JSON.stringify({ kind: "clte", timed_out: false, elapsed_ms: 120 }), "/app") === null);
check("JSON inválido -> null (no revienta)", smugglingFinding("no-es-json", "/app") === null);
check("vacío -> null", smugglingFinding("", "/app") === null);
check("finding menciona el tipo de sonda (CL.TE/TE.CL) en el título", /CL\.TE|TE\.CL/.test(smugglingFinding(JSON.stringify({ kind: "tecl", timed_out: true, elapsed_ms: 8000 }), "/app").title));

const ctx = buildPlaybookContext([], { host: "target.local", scope: "https://target.local", hasWebStack: true });
const stepsFase3 = stepsForPhase(3, "https://target.local", ctx);
check("Fase 3 incluye los steps p3-smuggle-*", stepsFase3.some((s) => s.id === "p3-smuggle-clte") && stepsFase3.some((s) => s.id === "p3-smuggle-tecl"));
const stepsFase2 = stepsForPhase(2, "https://target.local", ctx);
check("NO aparece en Fase 2 (gate: solo tras avanzar a Explotación)", !stepsFase2.some((s) => s.id === "p3-smuggle-clte"));

if (!ok) process.exit(1);
console.log("\nOK http-smuggling: sondas CL.TE/TE.CL en Fase 3 con gate humano de avance de fase");
