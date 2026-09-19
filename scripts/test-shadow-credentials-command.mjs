#!/usr/bin/env node
/**
 * Cuando BloodHound confirma AddKeyCredentialLink, el finding debe incluir
 * el comando exacto de certipy para ejecutar el ataque Shadow Credentials
 * manualmente (guía, no auto-ejecución — dark_spear no escribe estado AD
 * por su cuenta).
 */
import { bloodhoundAceFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const stdout = "DS_ACE|ALICE@CORP.LOCAL|user|AddKeyCredentialLink|SRV01.CORP.LOCAL|computer";
const finding = bloodhoundAceFindings(stdout).find((f) => /AddKeyCredentialLink/.test(f.title));

check("finding existe", Boolean(finding));
check("incluye comando certipy shadow auto", /certipy shadow auto/.test(finding.description));
check("comando referencia el principal", finding.description.includes("ALICE@CORP.LOCAL"));
check("comando referencia el target", finding.description.includes("SRV01.CORP.LOCAL"));
check("incluye segundo paso certipy auth -pfx", /certipy auth -pfx/.test(finding.description));
check("sigue marcado como no ejecutado por el motor", /no se ejecut/i.test(finding.description));
check("severity sigue Critical (regresión)", finding.severity === "Critical");

if (!ok) process.exit(1);
console.log("\nOK shadow-credentials-command: guía de comando certipy shadow en finding AddKeyCredentialLink");
