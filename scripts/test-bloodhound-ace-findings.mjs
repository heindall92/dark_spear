#!/usr/bin/env node
/**
 * Parsea las líneas sintéticas DS_ACE|... que bridge.py anexa al stdout de
 * bloodhound-python (aristas de ACL peligrosas ya extraídas de los JSON en
 * evidence/bloodhound: GenericAll, WriteDacl, AddKeyCredentialLink -> Shadow
 * Credentials, DCSync) a findings del motor.
 */
import { bloodhoundAceFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const stdout = [
  "DS_ACE|ALICE@CORP.LOCAL|user|GenericAll|SRV01.CORP.LOCAL|computer",
  "DS_ACE|ALICE@CORP.LOCAL|user|AddKeyCredentialLink|SRV01.CORP.LOCAL|computer",
  "DS_ACE|BOB@CORP.LOCAL|user|DCSync|CORP.LOCAL|domain",
  "DS_ACE|EVE@CORP.LOCAL|user|ForceChangePassword|CARLA@CORP.LOCAL|user",
].join("\n");

const findings = bloodhoundAceFindings(stdout);
check("genera un finding por arista", findings.length === 4);
check("GenericAll -> Critical", findings.find((f) => /GenericAll/.test(f.title)).severity === "Critical");
check("AddKeyCredentialLink -> título menciona Shadow Credentials", /Shadow Credentials/i.test(findings.find((f) => /AddKeyCredentialLink/.test(f.title)).title));
check("AddKeyCredentialLink -> Critical", findings.find((f) => /AddKeyCredentialLink/.test(f.title)).severity === "Critical");
check("DCSync -> Critical y menciona ambos derechos (GetChanges + GetChangesAll)", findings.find((f) => /DCSync/.test(f.title)).severity === "Critical" && /GetChanges/.test(findings.find((f) => /DCSync/.test(f.title)).description));
check("ForceChangePassword -> High", findings.find((f) => /ForceChangePassword/.test(f.title)).severity === "High");
check("cada finding nombra principal y target", findings.every((f) => /ALICE|BOB|EVE/.test(f.title) && /SRV01|CORP\.LOCAL|CARLA/.test(f.title)));

check("sin líneas DS_ACE -> []", bloodhoundAceFindings("Done in 0:01:23").length === 0);
check("vacío -> []", bloodhoundAceFindings("").length === 0);
check("línea malformada no revienta", bloodhoundAceFindings("DS_ACE|solo|tres|campos").length === 0);

if (!ok) process.exit(1);
console.log("\nOK bloodhound-ace-findings: ACL peligrosas de BloodHound -> findings del motor");
