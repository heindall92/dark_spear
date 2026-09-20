#!/usr/bin/env node
/**
 * stallExceeded(): session watchdog. The freeform agent decision loop
 * calls askAgent() in a Promise.race against phase-change; if the model
 * endpoint hangs (Ollama down, network stall) with no phase change either,
 * nothing today ever cuts the wait — the run hangs forever with no
 * user-visible signal. This pure helper decides when that has happened,
 * so the loop can end the run cleanly instead of hanging.
 */
import { stallExceeded, STALL_TIMEOUT_MS } from "../backend/js/agent.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check("STALL_TIMEOUT_MS es un numero positivo razonable (entre 1 y 30 min)", STALL_TIMEOUT_MS >= 60000 && STALL_TIMEOUT_MS <= 30 * 60 * 1000);

const t0 = 1000000;
check("justo antes del timeout -> false", stallExceeded(t0, t0 + STALL_TIMEOUT_MS - 1, STALL_TIMEOUT_MS) === false);
check("exactamente en el timeout -> true", stallExceeded(t0, t0 + STALL_TIMEOUT_MS, STALL_TIMEOUT_MS) === true);
check("mucho despues del timeout -> true", stallExceeded(t0, t0 + STALL_TIMEOUT_MS * 10, STALL_TIMEOUT_MS) === true);
check("sin tiempo transcurrido -> false", stallExceeded(t0, t0, STALL_TIMEOUT_MS) === false);
check("usa STALL_TIMEOUT_MS como default si no se pasa timeoutMs", stallExceeded(t0, t0 + STALL_TIMEOUT_MS + 1) === true);

process.exit(ok ? 0 : 1);
