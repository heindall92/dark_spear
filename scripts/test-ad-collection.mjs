#!/usr/bin/env node
/** Active Directory: DC + Fase 1 null session + Fase 2 AS-REP/SPN/Certipy + WinRM check. */
import {
  detectAdSignals,
  detectDomainController,
  classifyAdSurface,
  domainControllerFindings,
  netexecSmbFindings,
  netexecSharesFindings,
  rpcclientUsersFindings,
  getNpUsersFindings,
  getUserSpnsFindings,
  certipyFindFindings,
  netexecWinrmFindings,
  extractAdUsersFromBlob,
  extractAdDomain,
  lookupsidFindings,
  samrdumpFindings,
  PERIMETER_PORTS,
  AD_SURFACE_PORTS,
} from "../backend/js/vuln-kb.js";
import { stepsForPhase, buildPlaybookContext } from "../backend/js/playbook.js";
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";
import { readFileSync } from "node:fs";
import vm from "node:vm";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && !!cond;
}

check("perímetro incluye 88/135/389/3268/5985", ["88", "135", "389", "3268", "5985"].every((p) => PERIMETER_PORTS.includes(p)));
check("AD_SURFACE_PORTS incluye mindmap OCD", [88, 389, 445, 135, 3268, 5985].every((p) => AD_SURFACE_PORTS.includes(p)));

const dcNmap = `
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
5985/tcp open  wsman
`;
const surf = classifyAdSurface(dcNmap);
check("88+389 → likelyDc", surf.likelyDc === true);
check("detectDomainController", detectDomainController(dcNmap) === true);
check("detectAdSignals por DC", detectAdSignals(dcNmap) === true);
const dcHits = domainControllerFindings(dcNmap);
check("hallazgo Domain Controller High", dcHits.length === 1 && dcHits[0].severity === "High" && /Domain Controller/.test(dcHits[0].title));
check("solo 445 no es DC", classifyAdSurface("445/tcp open  microsoft-ds\n").likelyDc === false);
check("NO dispara por html ldap", !detectAdSignals("<p>configure ldap authentication</p>"));

const rpc = "user:[Administrator] rid:[0x1f4]\nuser:[alice] rid:[0x457]\n";
const nxc = "SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:CORP) (signing:False)\n";
const ctx = buildPlaybookContext([dcNmap, nxc, rpc], { host: "dc.corp.local" });
check("ctx.isAdTarget", ctx.isAdTarget === true);
check("ctx.isDomainController", ctx.isDomainController === true);
check("ctx.adDomain desde netexec", ctx.adDomain === "CORP");
check("ctx.adUsers desde rpc", ctx.adUsers.includes("alice") && ctx.adUsers.includes("Administrator"));
check("extractAdUsers", extractAdUsersFromBlob(rpc).length === 2);
check("extractAdDomain CORP", extractAdDomain(nxc) === "CORP");

const stepsAd = stepsForPhase(1, "http://dc.corp.local", { host: "dc.corp.local", isAdTarget: true });
const ids = stepsAd.map((s) => s.id);
check("netexec fingerprint", ids.includes("p1-ad-netexec-smb"));
check("netexec guest shares", ids.includes("p1-ad-netexec-guest-shares"));
check("rpcclient users", ids.includes("p1-ad-rpcclient-users"));
check("enum4linux", ids.includes("p1-ad-enum4linux"));

const stepsP2 = stepsForPhase(2, "http://dc.corp.local", {
  host: "dc.corp.local",
  isAdTarget: true,
  adDomain: "CORP.LOCAL",
  adUsers: ["alice", "bob"],
  adUser: "alice",
  adPassword: "Passw0rd!",
});
const ids2 = stepsP2.map((s) => s.id);
check("AS-REP paso 1", ids2.includes("p2-ad-asrep-1"));
check("GetUserSPNs", ids2.includes("p2-ad-getuserspns"));
check("certipy find", ids2.includes("p2-ad-certipy-find"));
check("lookupsid null", ids2.includes("p2-ad-lookupsid-null"));
check("samrdump null", ids2.includes("p2-ad-samrdump-null"));
const asrepSpec = stepsP2.find((s) => s.id === "p2-ad-asrep-1");
const asrepArgs = typeof asrepSpec.args === "function"
  ? asrepSpec.args({ adDomain: "CORP.LOCAL", adUsers: ["alice"], isAdTarget: true })
  : asrepSpec.args;
check("GetNPUsers -no-pass", Array.isArray(asrepArgs) && asrepArgs.includes("-no-pass") && asrepArgs[0] === "CORP.LOCAL/alice");

const stepsP3 = stepsForPhase(3, "http://dc.corp.local", {
  host: "dc.corp.local",
  isAdTarget: true,
  adDomain: "CORP",
  adUser: "alice",
  adPassword: "Passw0rd!",
});
check("WinRM check fase 3", stepsP3.some((s) => s.id === "p3-ad-netexec-winrm"));

const nxcHits = netexecSmbFindings(nxc);
check("netexec dominio", nxcHits.some((f) => /dominio CORP/.test(f.title)));
check("hosts tip", nxcHits.some((f) => /\/etc\/hosts/.test(f.remediation + f.description)));

const sharesOut = `
SMB  10.10.10.10  445  DC01  [*] Enumerating shares
SMB  10.10.10.10  445  DC01  SHARE           Permissions     Remark
SMB  10.10.10.10  445  DC01  ADMIN$          READ
SMB  10.10.10.10  445  DC01  C$              READ,WRITE
SMB  10.10.10.10  445  DC01  SYSVOL          READ
`;
check("WRITE C$ → Critical", netexecSharesFindings(sharesOut).some((f) => /escritura en C\$/.test(f.title) && f.severity === "Critical"));
check("rpcclient users Medium", rpcclientUsersFindings(rpc).some((f) => /RPC null/.test(f.title) && f.severity === "Medium"));

const asrepOut = "[*] Getting TGT for alice\n$krb5asrep$23$alice@CORP.LOCAL:deadbeefcafebabe\n";
check("AS-REP High", getNpUsersFindings(asrepOut).some((f) => /AS-REP roastable/.test(f.title) && f.severity === "High"));

const spnOut = "ServicePrincipalName  Name\nHTTP/web.corp.local  svc_web\nMSSQLSvc/db.corp.local:1433  sqlsvc\n";
check("SPN Medium", getUserSpnsFindings(spnOut).some((f) => /SPN/.test(f.title) && f.severity === "Medium"));

const certOut = "[!] Vulnerable Certificate Template Found\nTemplate Name: ESC1-Template\nESC1\n";
check("Certipy Critical/High", certipyFindFindings(certOut).some((f) => /ADCS/.test(f.title) && (f.severity === "Critical" || f.severity === "High")));

const winrmOut = "WINRM  10.10.10.10  5985  DC01  [+] CORP\\alice:Pass (Pwn3d!)\n";
check("WinRM Critical", netexecWinrmFindings(winrmOut).some((f) => /WinRM/.test(f.title) && f.severity === "Critical"));

const sidOut = "500: CORP\\Administrator (SidTypeUser)\n1105: CORP\\alice (SidTypeUser)\n";
check("lookupsid Medium", lookupsidFindings(sidOut).some((f) => /RID cycling/.test(f.title)));
const samrOut = "Found domain: CORP\nUser : bob\nUser : alice\n";
check("samrdump users", samrdumpFindings(samrOut).some((f) => /SAMR/.test(f.title)));
check("extract users lookupsid", extractAdUsersFromBlob(sidOut).includes("alice"));

const heur = collectHeuristicFindings(
  dcNmap + nxc + asrepOut,
  "http://dc.corp.local",
  { host: "dc.corp.local", isAdTarget: true, isDomainController: true },
  [
    { id: "p1-nmap-perimeter", text: dcNmap },
    { id: "p1-ad-netexec-smb", text: nxc },
    { id: "p1-ad-netexec-guest-shares", text: sharesOut },
    { id: "p1-ad-rpcclient-users", text: rpc },
    { id: "p2-ad-asrep-1", text: asrepOut },
    { id: "p2-ad-getuserspns", text: spnOut },
    { id: "p2-ad-certipy-find", text: certOut },
    { id: "p3-ad-netexec-winrm", text: winrmOut },
    { id: "p2-ad-lookupsid-null", text: sidOut },
    { id: "p2-ad-samrdump-null", text: samrOut },
  ],
);
check("heurística DC", heur.some((f) => /Domain Controller probable/.test(f.title)));
check("heurística C$ Critical", heur.some((f) => /escritura en C\$/.test(f.title)));
check("heurística rpc users", heur.some((f) => /RPC null/.test(f.title)));
check("heurística AS-REP", heur.some((f) => /AS-REP roastable/.test(f.title)));
check("heurística SPN", heur.some((f) => /SPN/.test(f.title)));
check("heurística Certipy", heur.some((f) => /ADCS/.test(f.title)));
check("heurística WinRM", heur.some((f) => /WinRM/.test(f.title)));
check("heurística lookupsid", heur.some((f) => /RID cycling/.test(f.title)));
check("heurística samrdump", heur.some((f) => /SAMR/.test(f.title)));

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const code = readFileSync(`${root}/panel/vendor/finding-dossier.js`, "utf8");
const sandbox = { window: {}, console, localStorage: { getItem: () => "es" } };
sandbox.window = sandbox;
sandbox.global = sandbox;
vm.runInNewContext(code.replace("(window);", "(this);"), sandbox);
const d = sandbox.DarkSpearDossier.enrich({
  title: dcHits[0].title,
  severity: dcHits[0].severity,
  description: dcHits[0].description,
  remediation: dcHits[0].remediation,
  asset: "dc.corp.local",
});
check("dossier DC no CWE-1035", !(d.cwe || []).includes("CWE-1035"));
check("dossier cita Kerberos/LDAP", /Kerberos|LDAP|Domain Controller/i.test(d.exec));

const dAsrep = sandbox.DarkSpearDossier.enrich({
  title: "AD: 1 cuenta(s) AS-REP roastable(s)",
  severity: "High",
  description: "test",
  remediation: "test",
  asset: "dc.corp.local",
});
check("dossier AS-REP CWE-308", (dAsrep.cwe || []).includes("CWE-308"));

process.exit(ok ? 0 : 1);
