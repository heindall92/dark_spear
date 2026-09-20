#!/usr/bin/env node
/**
 * Integration regression for the Critical finding from the final
 * whole-branch review: the JWT alg=none finding (proofLevel "proven")
 * must survive collectHeuristicFindings() -> shouldReport() end to end,
 * not just pass each function's isolated unit test.
 */
import { collectHeuristicFindings, shouldReport } from "../backend/js/finding-heuristics.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const stepRecords = [{ id: "p1-jwt-algnone-1", text: "DS_HTTP:200\n{\"role\":\"admin\"}" }];
const findings = collectHeuristicFindings("", "https://x.example.com", {}, stepRecords)
  .filter((f) => /alg=none/i.test(f.title));

check("collectHeuristicFindings produce el finding JWT alg=none", findings.length > 0);
check("el finding JWT alg=none sobrevive shouldReport() end-to-end (no se descarta)", findings.length > 0 && findings.every((f) => shouldReport(f) === true));

process.exit(ok ? 0 : 1);
