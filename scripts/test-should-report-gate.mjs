#!/usr/bin/env node
/**
 * shouldReport(): silence-over-false-positive gate. Critical/High findings
 * without any evidence signal must be silently dropped before they ever
 * reach proposeFinding() — never surfaced to the user as a maybe-wrong
 * high-severity claim.
 */
import { shouldReport } from "../backend/js/finding-heuristics.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check(
  "Critical sin evidence_step_ids ni marcador EVIDENCE en description -> false",
  shouldReport({ title: "X", severity: "Critical", description: "sin nada raro aqui", evidence_step_ids: [] }) === false,
);

check(
  "High con evidence_step_ids no vacío -> true",
  shouldReport({ title: "X", severity: "High", description: "sin marcador", evidence_step_ids: ["p1-curl-x"] }) === true,
);

check(
  "Critical con descripcion que contiene EVIDENCE: -> true",
  shouldReport({ title: "X", severity: "Critical", description: "EVIDENCE: HTTP 200 en /admin", evidence_step_ids: [] }) === true,
);

check(
  "Critical con HTTP 2xx en la descripcion (sin la palabra EVIDENCE) -> true",
  shouldReport({ title: "X", severity: "Critical", description: "respondio HTTP 200 en vez de 401/403", evidence_step_ids: [] }) === true,
);

check(
  "Medium sin evidencia -> true (severidad baja siempre pasa)",
  shouldReport({ title: "X", severity: "Medium", description: "nada", evidence_step_ids: [] }) === true,
);

check(
  "Info sin evidencia -> true",
  shouldReport({ title: "X", severity: "Info", description: "nada", evidence_step_ids: [] }) === true,
);

check(
  "payload malformado (severity ausente) -> false (fail closed)",
  shouldReport({ title: "X", description: "nada" }) === false,
);

check(
  "payload null -> false (fail closed, nunca revienta)",
  shouldReport(null) === false,
);

check(
  "Critical con proofLevel proven pero sin evidence_step_ids ni marcador en description -> true (proofLevel proven es evidencia suficiente por si sola)",
  shouldReport({ title: "X", severity: "Critical", description: "HTTP 2xx en vez de 401/403", evidence_step_ids: [], proofLevel: "proven" }) === true,
);

process.exit(ok ? 0 : 1);
