#!/usr/bin/env node
/**
 * Verifica testsslDeprecatedProtocols()/testsslVulnerabilities()/
 * testsslFindings() contra fixtures con el formato real de testssl.sh.
 */
import { testsslDeprecatedProtocols, testsslVulnerabilities, testsslFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

// Fixture real, capturado de una corrida de testssl.sh (--fast --color 0).
const realOutput = `
 Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final

 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experimental not vulnerable (OK)
`;

const deprecated = testsslDeprecatedProtocols(realOutput);
check("detecta TLS 1 y TLS 1.1 como obsoletos y ofrecidos", deprecated.includes("TLS 1") && deprecated.includes("TLS 1.1"));
check("no marca SSLv2/SSLv3 (dicen 'not offered')", !deprecated.includes("SSLv2") && !deprecated.includes("SSLv3"));

const noVulns = testsslVulnerabilities(realOutput);
check("sin 'VULNERABLE (NOT ok)' en el fixture -> []", noVulns.length === 0);

const findingsFromReal = testsslFindings(realOutput, "target.local");
check("genera 1 finding (protocolos obsoletos), sin vulnerabilidades reales", findingsFromReal.length === 1);
check("severidad Medium (solo TLS 1.x, no SSLv2/v3)", findingsFromReal[0].severity === "Medium");

// Fixture con vulnerabilidad real confirmada (formato exacto de testssl.sh).
const vulnOutput = `
 Heartbleed (CVE-2014-0160)                VULNERABLE (NOT ok), timed out
 SSLv3      offered (deprecated)
`;
const vulns = testsslVulnerabilities(vulnOutput);
check("detecta 1 vulnerabilidad real (Heartbleed)", vulns.length === 1 && vulns[0].includes("Heartbleed"));

const findingsFromVuln = testsslFindings(vulnOutput, "target.local");
check("genera 2 findings: vulnerabilidad + SSLv3 obsoleto", findingsFromVuln.length === 2);
check("SSLv3 ofrecido -> severidad Critical", findingsFromVuln.some((f) => f.severity === "Critical" && f.title.includes("Protocolo")));
check("Heartbleed real -> severidad Critical", findingsFromVuln.some((f) => f.title.includes("Heartbleed")));

process.exit(ok ? 0 : 1);
