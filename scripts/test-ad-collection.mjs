#!/usr/bin/env node
/** Active Directory collection: gate + parsers + playbook wiring. */
import {
  detectAdSignals,
  netexecSmbFindings,
  enum4linuxFindings,
  smbclientNullFindings,
  ldapAnonymousFindings,
  PERIMETER_PORTS,
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

check("perímetro incluye 88/389/636", ["88", "389", "636"].every((p) => PERIMETER_PORTS.includes(p)));
check("detecta 445/tcp open", detectAdSignals("445/tcp open  microsoft-ds\n"));
check("detecta banner microsoft-ds", detectAdSignals("Service Info: microsoft-ds"));
check("NO dispara por html con palabra ldap", !detectAdSignals('<p>configure ldap authentication</p>'));
check("flag ctx.isAdTarget", detectAdSignals("", { isAdTarget: true }));

const nmapish = "PORT   STATE SERVICE\n445/tcp open  microsoft-ds\n389/tcp open  ldap\n";
const ctx = buildPlaybookContext([nmapish], { host: "dc.corp.local" });
check("buildPlaybookContext.isAdTarget tras nmap", ctx.isAdTarget === true);

const webOnly = buildPlaybookContext(["HTTP/1.1 200 OK\nServer: nginx\n"], { host: "shop.example.com" });
check("web sin AD → isAdTarget false", webOnly.isAdTarget === false);

const stepsAd = stepsForPhase(1, "http://dc.corp.local", { host: "dc.corp.local", isAdTarget: true });
const ids = stepsAd.map((s) => s.id);
check("paso netexec", ids.includes("p1-ad-netexec-smb"));
check("paso enum4linux", ids.includes("p1-ad-enum4linux"));
check("paso smbclient", ids.includes("p1-ad-smbclient"));
check("paso ldapsearch", ids.includes("p1-ad-ldapsearch-rootdse"));

const stepsWeb = stepsForPhase(1, "http://127.0.0.1:8888", { host: "127.0.0.1" });
const adIdsWeb = stepsWeb.filter((s) => String(s.id).startsWith("p1-ad-"));
check("pasos AD existen en lista (skipIf en runtime)", adIdsWeb.length === 4);
check("skipIf sin isAdTarget", typeof adIdsWeb[0].skipIf === "function" && adIdsWeb[0].skipIf({ isAdTarget: false }) === true);
check("skipIf con isAdTarget", adIdsWeb[0].skipIf({ isAdTarget: true }) === false);

const nxc = `
SMB         10.10.10.10  445    DC01    [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP) (signing:False) (SMBv1:False)
`;
const nxcHits = netexecSmbFindings(nxc);
check("netexec dominio Info", nxcHits.some((f) => /dominio CORP/.test(f.title) && f.severity === "Info"));
check("netexec signing High", nxcHits.some((f) => /SMB signing deshabilitado/.test(f.title) && f.severity === "High"));

const e4l = `
Domain Name: CORP
user:[Administrator] rid:[0x1f4]
user:[alice] rid:[0x457]
user:[bob] rid:[0x458]
Sharename       Type
--------        ----
ADMIN$          Disk
C$              Disk
SYSVOL          Disk
Minimum password length: 6
`;
const eHits = enum4linuxFindings(e4l);
check("enum4linux usuarios Medium", eHits.some((f) => /usuario/.test(f.title) && f.severity === "Medium"));
check("enum4linux política débil", eHits.some((f) => /longitud mínima/.test(f.title)));
check("enum4linux dominio", eHits.some((f) => /dominio CORP/.test(f.title)));

const smb = "ADMIN$|Disk\nC$|Disk\npublic|Disk\n";
check("smbclient null High (ADMIN$)", smbclientNullFindings(smb).some((f) => /sesión nula/.test(f.title) && f.severity === "High"));

const ldap = `
# extended LDIF
dn:
defaultNamingContext: DC=corp,DC=local
namingContexts: DC=corp,DC=local
dnsHostName: dc01.corp.local
`;
check("ldap anónimo Medium", ldapAnonymousFindings(ldap).some((f) => /bind LDAP anónimo/.test(f.title) && f.severity === "Medium"));
check("ldap vacío → []", ldapAnonymousFindings("Can't contact LDAP server").length === 0);

const heur = collectHeuristicFindings(
  nxc + e4l,
  "http://dc.corp.local",
  { host: "dc.corp.local", isAdTarget: true },
  [
    { id: "p1-ad-netexec-smb", text: nxc },
    { id: "p1-ad-enum4linux", text: e4l },
    { id: "p1-ad-smbclient", text: smb },
    { id: "p1-ad-ldapsearch-rootdse", text: ldap },
  ],
);
check("heurística emite AD:", heur.some((f) => /^AD:/.test(f.title)));
check("heurística signing", heur.some((f) => /SMB signing/.test(f.title)));

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const code = readFileSync(`${root}/panel/vendor/finding-dossier.js`, "utf8");
const sandbox = { window: {}, console, localStorage: { getItem: () => "es" } };
sandbox.window = sandbox;
sandbox.global = sandbox;
vm.runInNewContext(code.replace("(window);", "(this);"), sandbox);
const d = sandbox.DarkSpearDossier.enrich({
  title: "AD: SMB signing deshabilitado (relay factible)",
  severity: "High",
  description: "signing False",
  remediation: "GPO",
  asset: "dc.corp.local",
});
check("dossier AD signing no CWE-1035 genérico", !(d.cwe || []).includes("CWE-1035"));
check("dossier cita Active Directory / signing", /Active Directory|SMB signing|signing/i.test(d.exec));

const page = readFileSync(`${root}/panel/ad-assessment.html`, "utf8");
check("página ad-assessment existe", /panel-ad-body/.test(page) && /nav\.ad/.test(page));
const idx = readFileSync(`${root}/panel/index.html`, "utf8");
check("Dashboard enlaza AD", /ad-assessment\.html/.test(idx));

process.exit(ok ? 0 : 1);
