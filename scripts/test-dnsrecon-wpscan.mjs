#!/usr/bin/env node
/** Parsers dnsrecon / WPScan + cableado playbook/heurística/dossier. */
import {
  dnsreconArgs,
  dnsreconFindings,
  wpscanFindings,
} from "../backend/js/vuln-kb.js";
import { stepsForPhase } from "../backend/js/playbook.js";
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";
import { readFileSync } from "node:fs";
import vm from "node:vm";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const args = dnsreconArgs("example.com");
check("dnsreconArgs es -d root -t std", args.join(" ") === "-d example.com -t std");
check("dnsreconArgs no usa -t brt", !args.includes("brt"));

const axfr = `
[*] Performing General Enumeration of Domain: zonetransfer.me
[*] Checking for Zone Transfer for zonetransfer.me
[+] Zone Transfer was successful
[*] 	 SOA nsztm1.digi.ninja 81.4.108.41
[*] 	 NS nsztm1.digi.ninja 81.4.108.41
[*] 	 NS nsztm2.digi.ninja 167.88.42.94
[*] 	 A zonetransfer.me 81.4.108.41
[*] 	 A www.zonetransfer.me 81.4.108.41
[*] 	 A staging.zonetransfer.me 81.4.108.41
[*] 	 MX zonetransfer.me ASPMX.L.GOOGLE.COM 10
`;
const axfrHits = dnsreconFindings(axfr, "zonetransfer.me");
check("AXFR → High", axfrHits.some((f) => /Transferencia de zona DNS exitosa/.test(f.title) && f.severity === "High"));
check("inventario Info con extras (no el ápice)", axfrHits.some((f) => /^dnsrecon:/.test(f.title) && f.severity === "Info" && /www\.zonetransfer\.me/.test(f.description) && !/A zonetransfer\.me;/.test(f.description)));
check("sin salida → []", dnsreconFindings("", "example.com").length === 0);
check("AXFR fallido sin extras → []", dnsreconFindings("[-]     Zone Transfer Failed\n", "example.com").length === 0);

const wpscanOut = `
[+] URL: http://blog.local/
[+] WordPress version 6.4.2 identified (Insecure, released on 2023-12-06).
[i] The latest WordPress version is 6.5.3.

[+] http://blog.local/xmlrpc.php
 | Found:
 | * http://blog.local/xmlrpc.php
 | The XML-RPC is enabled. This can be used to perform a brute force attack.

[!] Title: Contact Form 7 < 5.8.4 - XSS
 | Fixed in: 5.8.4
 | References:
 |  - https://wpscan.com/vulnerability/cf7
 |  - CVE-2023-6449

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
[+] editor
 | Found By: Login Error Messages (Aggressive Detection)
`;
const wp = wpscanFindings(wpscanOut);
check("versión Insecure → Medium", wp.some((f) => /WordPress 6\.4\.2 \(Insecure\)/.test(f.title) && f.severity === "Medium"));
check("CVE [!] Title → High", wp.some((f) => /Contact Form 7/.test(f.title) && /CVE-2023-6449/.test(f.description) && f.severity === "High"));
check("xmlrpc → Low", wp.some((f) => /xmlrpc\.php/.test(f.title) && f.severity === "Low"));
check("usuarios → Info", wp.some((f) => /usuario/.test(f.title) && /admin/.test(f.description) && f.severity === "Info"));
check("tope ≤8", wp.length <= 8 && wp.length >= 4);
check("Latest no es Insecure", wpscanFindings("[+] WordPress version 6.5.3 identified (Latest, released on 2024-01-01).\n").length === 0);
check("sin salida → []", wpscanFindings("").length === 0);

const domainSteps = stepsForPhase(1, "https://example.com", { host: "example.com", scope: "example.com" });
const dnsStep = domainSteps.find((s) => s.id === "p1-osint-dnsrecon");
check("playbook dominio incluye p1-osint-dnsrecon", !!dnsStep);
check("paso dnsrecon usa -t std", Array.isArray(dnsStep?.args) && dnsStep.args.includes("std"));

const heur = collectHeuristicFindings(
  axfr,
  "https://zonetransfer.me",
  { host: "zonetransfer.me", scope: "zonetransfer.me" },
  [{ id: "p1-osint-dnsrecon", text: axfr }],
);
check("heurística emite AXFR desde probeIdx", heur.some((f) => /Transferencia de zona DNS/.test(f.title)));

const heurWp = collectHeuristicFindings(
  wpscanOut,
  "http://blog.local",
  { host: "blog.local", isWordpress: true },
  [{ id: "p2-wpscan", text: wpscanOut }],
);
check("heurística emite WPScan desde probeIdx", heurWp.some((f) => /^WPScan:/.test(f.title)));

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const code = readFileSync(`${root}/panel/vendor/finding-dossier.js`, "utf8");
const sandbox = { window: {}, console, localStorage: { getItem: () => "es" } };
sandbox.window = sandbox;
sandbox.global = sandbox;
vm.runInNewContext(code.replace("(window);", "(this);"), sandbox);

const dAxfr = sandbox.DarkSpearDossier.enrich({
  title: axfrHits[0].title,
  severity: axfrHits[0].severity,
  description: axfrHits[0].description,
  remediation: axfrHits[0].remediation,
  asset: "https://zonetransfer.me",
});
check("dossier AXFR no cae al genérico CWE-1035", !(dAxfr.cwe || []).includes("CWE-1035"));
check("dossier AXFR cita AXFR/plano", /AXFR|plano DNS|transferencia de zona/i.test(dAxfr.exec));

const wpHit = wp.find((f) => /Contact Form 7/.test(f.title));
const dWp = sandbox.DarkSpearDossier.enrich({
  title: wpHit.title,
  severity: wpHit.severity,
  description: wpHit.description,
  remediation: wpHit.remediation,
  asset: "http://blog.local",
});
check("dossier WPScan cita WPScan", /WPScan/.test(dWp.exec));

process.exit(ok ? 0 : 1);
