#!/usr/bin/env node
/**
 * cloud_enum (github.com/initstring/cloud_enum): enumeración ACTIVA por
 * permutación de nombre contra AWS/Azure/GCP — a diferencia de las
 * detecciones pasivas ya existentes (extractS3BucketHost/etc, que solo
 * confirman recursos que la app YA referencia), esto adivina nombres a
 * partir del dominio del cliente.
 *
 * OJO de atribución: un bucket "acme" puede pertenecer a CUALQUIER
 * empresa que se llame así, no necesariamente al cliente auditado (a
 * diferencia de subdomain takeover, que ancla a un host que sí resuelve
 * bajo el dominio del cliente). Por eso NUNCA se reporta como severidad
 * alta automática — todo es candidato a confirmar manualmente.
 */
import { cloudEnumKeyword, cloudEnumArgs, cloudEnumFindings } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- cloudEnumKeyword ---------------------------- */

check("subdominio.dominio.tld -> usa el label del dominio, no el subdominio", cloudEnumKeyword("app.acme.com") === "acme");
check("dominio.tld simple -> usa el primer label", cloudEnumKeyword("testfire.net") === "testfire");
check("multi-subdominio -> sigue tomando el penúltimo label real", cloudEnumKeyword("api.v2.acme.com") === "acme");
check("vacío -> string vacío (no crashea)", cloudEnumKeyword("") === "");

/* ---------------------------- cloudEnumArgs ---------------------------- */

const args = cloudEnumArgs("acme");
check("incluye -k con el keyword", args.includes("-k") && args.includes("acme"));
check("modo quickscan (rápido, sin mutations pesadas)", args.includes("-qs"));
check("salida JSON a stdout (bridge.py la redirige a tempfile real)", args.includes("-f") && args.includes("json") && args.includes("/dev/stdout"));

/* ---------------------------- cloudEnumFindings ---------------------------- */

// Fixture real capturada: cloud_enum -k acme -qs -f json
const realCapture = [
  JSON.stringify({ platform: "aws", msg: "Protected S3 Bucket", target: "http://acme.s3.amazonaws.com/", access: "protected" }),
  JSON.stringify({ platform: "azure", msg: "Disabled Account", target: "http://acme.blob.core.windows.net/", access: "disabled" }),
  JSON.stringify({ platform: "azure", msg: "Registered Azure Website DNS Name", target: "acme.azurewebsites.net", access: "public" }),
  JSON.stringify({ platform: "gcp", msg: "Protected Google Bucket", target: "http://storage.googleapis.com/acme", access: "protected" }),
].join("\n");

const realFindings = cloudEnumFindings(realCapture);
check("'disabled' no genera finding (recurso no existe/desactivado)", !realFindings.some((f) => /blob\.core\.windows\.net/.test(f.description)));
check("'protected' (bucket existe, requiere auth) -> Info, no alarmante", realFindings.some((f) => /s3\.amazonaws\.com/.test(f.description) && f.severity === "Info"));
check("DNS registrado (no es exposición de datos) -> Info", realFindings.some((f) => /azurewebsites\.net/.test(f.description) && f.severity === "Info"));
check("ningún finding pasa de Medium (atribución no confirmada, nunca High automático)", realFindings.every((f) => f.severity !== "High" && f.severity !== "Critical"));
check("toda descripción advierte que requiere confirmar pertenencia al cliente", realFindings.every((f) => /confirmar|pertenece/i.test(f.description)));

// Bucket S3 PÚBLICO (listado sin auth) -> el caso más serio, pero sigue como
// candidato (Medium), nunca High/Critical automático por el problema de
// atribución de nombre.
const publicBucket = JSON.stringify({ platform: "aws", msg: "Open S3 Bucket", target: "http://acme-backup.s3.amazonaws.com/", access: "public" });
const publicFindings = cloudEnumFindings(publicBucket);
check("bucket público sin auth -> severidad Medium (no High/Critical automático)", publicFindings.length === 1 && publicFindings[0].severity === "Medium");
check("título distingue 'público sin auth' del resto", /públic/i.test(publicFindings[0].title));

check("stdout vacío -> cero findings", cloudEnumFindings("").length === 0);
check("línea no-JSON no crashea", cloudEnumFindings("#### CLOUD_ENUM header ####\nno es json").length === 0);
check("dedupe por target repetido", cloudEnumFindings([publicBucket, publicBucket].join("\n")).length === 1);

/* ------------------------- wiring Fase 1 ------------------------- */

const ctx = buildPlaybookContext([], { host: "acme.com", scope: "https://app.acme.com" });
const stepsFase1 = stepsForPhase(1, "https://app.acme.com", ctx);
const cloudEnumStep = stepsFase1.find((s) => s.id === "p1-cloud-enum");
check("Fase 1 incluye el step p1-cloud-enum", !!cloudEnumStep);
check("usa el keyword derivado del host, no la URL completa", cloudEnumStep?.args.includes("acme"));

const ctxIp = buildPlaybookContext([], { host: "10.0.0.5", scope: "http://10.0.0.5", isIpTarget: true });
const stepsFase1Ip = stepsForPhase(1, "http://10.0.0.5", ctxIp);
const cloudEnumStepIp = stepsFase1Ip.find((s) => s.id === "p1-cloud-enum");
check("se salta contra un target IP (sin dominio, no hay keyword útil)", !cloudEnumStepIp || cloudEnumStepIp.skipIf?.(ctxIp));

const ctxDvwa = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", isDvwa: true });
const stepsFase1Dvwa = stepsForPhase(1, "https://x.com", ctxDvwa);
const cloudEnumStepDvwa = stepsFase1Dvwa.find((s) => s.id === "p1-cloud-enum");
check("se salta en DVWA (skipHeavy, mismo criterio que nikto/wapiti/katana)", !cloudEnumStepDvwa || cloudEnumStepDvwa.skipIf?.(ctxDvwa));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
