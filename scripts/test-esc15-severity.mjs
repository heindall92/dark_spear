#!/usr/bin/env node
/**
 * ESC15 (EKUwu, CVE-2024-49019) debe clasificarse Critical igual que
 * ESC1/ESC4/ESC8 — certipyFindFindings ya captura ESC1-15 por regex pero
 * la severidad solo promovía ESC1/4/8 a Critical.
 */
import { certipyFindFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const esc15Stdout = [
  "Certificate Template: WeakBinding",
  "    [!] Vulnerable to ESC15 - Arbitrary Application Policy Injection (EKUwu)",
].join("\n");

const findings = certipyFindFindings(esc15Stdout);
check("ESC15 genera finding", findings.length === 1);
check("ESC15 -> Critical", findings[0].severity === "Critical");
check("título menciona ESC15", /ESC15/.test(findings[0].title));
check("descripción menciona EKUwu", /EKUwu/i.test(findings[0].description));

// Regresión: ESC1 sigue Critical, ESC2 (no crítico) sigue High.
const esc1 = certipyFindFindings("Certificate Template: X\n[!] Vulnerable to ESC1");
check("ESC1 sigue Critical (regresión)", esc1[0].severity === "Critical");
const esc2 = certipyFindFindings("Certificate Template: Y\n[!] Vulnerable to ESC2");
check("ESC2 sigue High (regresión, no se sobre-promueve)", esc2[0].severity === "High");

if (!ok) process.exit(1);
console.log("\nOK esc15-severity: ESC15/EKUwu clasificado Critical");
