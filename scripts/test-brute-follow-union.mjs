#!/usr/bin/env node
/** gobuster + ffuf + feroxbuster alimentan brute-follow (tope 3, SPA >25 → []). */
import { extractBruteDiscoveredPaths, buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const gobuster = `
/admin                (Status: 200) [Size: 1234]
/secret               (Status: 301) [Size: 178]
/internal             (Status: 403) [Size: 19]
/backup               (Status: 200) [Size: 10]
`;
check("gobuster path+Status (descarta /backup de API_SURFACE)", extractBruteDiscoveredPaths(gobuster).join(",") === "/admin,/secret,/internal");

const gobusterE = `
http://127.0.0.1/hidden (Status: 200) [Size: 12]
http://127.0.0.1/old (Status: 301) [Size: 178]
`;
check("gobuster -e URL+Status", extractBruteDiscoveredPaths(gobusterE).join(",") === "/hidden,/old");

const ffufSilent = `
http://127.0.0.1/ffufdir
http://127.0.0.1/ffuf2
`;
check("ffuf -s URLs", extractBruteDiscoveredPaths(ffufSilent).join(",") === "/ffufdir,/ffuf2");

const ffufStatus = `
console                 [Status: 200, Size: 99, Words: 1, Lines: 2]
private                 [Status: 403, Size: 19, Words: 1, Lines: 1]
`;
check("ffuf [Status: nnn]", extractBruteDiscoveredPaths(ffufStatus).join(",") === "/console,/private");

const ferox = `
200      GET        45l       80w     1234c http://127.0.0.1/ferox
301      GET         7l       12w      178c http://127.0.0.1/old => http://127.0.0.1/old/
403      GET         1l        2w        19c http://127.0.0.1/cgi-bin
`;
check("ferox -q 200/301/403 GET", extractBruteDiscoveredPaths(ferox).join(",") === "/ferox,/old,/cgi-bin");

const mixed = [gobuster, ffufSilent, ferox].join("\n");
const mixedPaths = extractBruteDiscoveredPaths(mixed);
check("unión tope 3 (gobuster primero)", mixedPaths.length === 3 && mixedPaths[0] === "/admin");

const spa = Array.from({ length: 30 }, (_, i) => `/page${i}                (Status: 200) [Size: 10]`).join("\n");
check("SPA catch-all >25 → []", extractBruteDiscoveredPaths(spa).length === 0);

check("vacío → []", extractBruteDiscoveredPaths("").length === 0);
check("ruido sin formato → []", extractBruteDiscoveredPaths("nikto found /admin interesting\n").length === 0);

const ctx = buildPlaybookContext([ffufSilent], { host: "127.0.0.1" });
check("buildPlaybookContext.bruteDiscovered lee ffuf", ctx.bruteDiscovered.includes("/ffufdir"));

const p2 = stepsForPhase(2, "http://127.0.0.1", {
  host: "127.0.0.1",
  bruteDiscovered: ["/ffufdir", "/ferox"],
  hasWebStack: true,
});
const follow1 = p2.find((s) => s.id === "p2-brute-follow-1");
const args1 = typeof follow1?.args === "function"
  ? follow1.args({ bruteDiscovered: ["/ffufdir", "/ferox"], hasWebStack: true })
  : follow1?.args;
check("brute-follow-1 usa path de ffuf/ferox", Array.isArray(args1) && args1.some((a) => String(a).endsWith("/ffufdir")));
check("textos brute-follow mencionan ffuf/ferox", /ffuf|ferox/i.test(follow1?.desc || ""));

process.exit(ok ? 0 : 1);
