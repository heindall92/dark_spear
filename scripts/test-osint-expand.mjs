#!/usr/bin/env node
/**
 * Smoke del paquete OSINT ampliado (Claude-OSINT → Dark Spear):
 * catálogo de secretos, account ID AWS, validadores, IdP, riesgo, delta.
 */
import {
  jsSecretFindings,
  jsSecretSignatureCount,
  extractCapturedSecrets,
  secretValidateFindings,
  accountIdFromAccessKey,
  cloudIdentityFindings,
  domainSecurityFindings,
  idpDiscoveryFindings,
  orgAsnSiblingFindings,
  computeExposureRisk,
  exposureDeltaFindings,
  secretValidateCurlSteps,
  missingWafFinding,
  wafTriggerFindings,
  wafw00fFindings,
  dropContradictoryWafFindings,
} from "../backend/js/vuln-kb.js";
import { stepsForPhase, buildPlaybookContext, scopeRoot } from "../backend/js/playbook.js";
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function step(id, tool, args) {
  return { id, tool, args };
}

const n = jsSecretSignatureCount();
assert(n >= 55, `catálogo de secretos demasiado corto: ${n}`);
console.log("firmas de secretos:", n);

const acct = accountIdFromAccessKey("ASIAY34FZKBOKMUTVV7A");
assert(acct === "609629065308", `account ID decode: got ${acct}`);
console.log("AWS account ID decode OK:", acct);

const jsHits = jsSecretFindings("const k = 'sk-ant-api03-" + "A".repeat(95) + "';", "/app.js");
assert(jsHits.some((f) => /Anthropic/.test(f.title)), "Anthropic no detectada");
const ghp = jsSecretFindings("tok = 'ghp_" + "A".repeat(36) + "';", "/main.js");
assert(ghp.some((f) => /GitHub Personal/.test(f.title)), "GitHub PAT no detectada");

const secrets = extractCapturedSecrets("Bearer ghp_" + "B".repeat(36));
assert(secrets.length >= 1 && secrets[0].kind === "github", "extractCapturedSecrets github");
const valSteps = secretValidateCurlSteps(step, secrets);
assert(valSteps.length === 1 && valSteps[0].args.includes("https://api.github.com/user"), "validador github");
const live = secretValidateFindings('{"login":"x"}\nDS_HTTP:200\n', "github", "GitHub PAT");
assert(live[0] && /viva confirmada/.test(live[0].title), "validador live");
const dead = secretValidateFindings("DS_HTTP:401\n", "github", "GitHub PAT");
assert(dead[0] && /revocada/.test(dead[0].title), "validador 401");

const cloud = cloudIdentityFindings('arn:aws:s3:::bucket:111111111111:obj AKIAIOSFODNN7EXAMPLE');
assert(cloud.length >= 1, "cloud identity debería emitir al menos ARN o account (example key may skip)");

const spf = domainSecurityFindings("", "", "example.com");
assert(spf.some((f) => /sin registro SPF/.test(f.title)), "SPF ausente");

const idp = idpDiscoveryFindings("", "", "acme.com", {
  mxText: "1 aspmx.l.google.com.",
  entraOidcText: '{"issuer":"https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0"}',
  samlHttpCode: "200",
});
assert(idp.some((f) => /Google Workspace/.test(f.title)), "GWS MX");
assert(idp.some((f) => /tenant Entra ID/.test(f.title)), "Entra GUID");
assert(idp.some((f) => /SAML/.test(f.title)), "SAML metadata");

const sib = orgAsnSiblingFindings("{}", JSON.stringify({
  data: { prefixes: [{ prefix: "203.0.113.0/24" }, { prefix: "198.51.100.0/24" }] },
}), "64500", "203.0.113.10", false);
assert(sib.some((f) => /prefijo/.test(f.title)), "ASN siblings");
const hyper = orgAsnSiblingFindings("", "", "16509", "1.1.1.1", true);
assert(hyper.some((f) => /hyperscaler/.test(f.title)), "hyperscaler guard");

const score = computeExposureRisk([
  { title: "X hardcodeada en bundle JS", severity: "Critical" },
  { title: "Bucket S3 referenciado por la app es listable públicamente", severity: "High" },
]);
assert(score.grade && score.risk > 0, "exposure risk");
console.log("exposure risk:", score);

const delta = exposureDeltaFindings(["A", "B"], ["B", "C"]);
assert(delta.length === 2, "delta added+gone");

const domainSteps = stepsForPhase(1, "https://example.com", { host: "example.com", scope: "example.com" });
const ids = domainSteps.map((s) => s.id);
assert(ids.includes("p1-idp-entra-oidc"), "paso entra oidc");
assert(ids.includes("p1-idp-saml-fedmeta"), "paso saml");
assert(ids.includes("p1-osint-dnsrecon"), "paso dnsrecon en dominio");
assert(ids.some((id) => id.startsWith("p1-secretval-")), "pasos validador");
const ipSteps = stepsForPhase(1, "http://127.0.0.1", { host: "127.0.0.1", scope: "127.0.0.1" });
assert(!ipSteps.some((s) => s.id === "p1-osint-dnsrecon"), "dnsrecon no corre contra IP");

assert(scopeRoot("www.cubadebate.cu", "http://www.cubadebate.cu/") === "cubadebate.cu", "apex sin www");
const wwwSteps = stepsForPhase(1, "http://www.example.com", { host: "www.example.com", scope: "http://www.example.com" });
const txtStep = wwwSteps.find((s) => s.id === "p1-osint-dig-txt");
const dmarcStep = wwwSteps.find((s) => s.id === "p1-osint-dig-dmarc");
assert(txtStep && txtStep.args.includes("example.com"), "SPF TXT en apex, no www");
assert(txtStep.args.every((a) => !/www\.example\.com/.test(String(a))), "dig TXT no usa www");
assert(dmarcStep && dmarcStep.args.some((a) => a === "_dmarc.example.com"), "DMARC en _dmarc.apex");

const ctx = buildPlaybookContext(["ghp_" + "C".repeat(36)], { host: "example.com", scope: "example.com" });
assert(ctx.capturedSecrets.length >= 1, "ctx.capturedSecrets");

const findings = collectHeuristicFindings(
  "v=spf1 +all",
  "https://example.com",
  { host: "example.com", scope: "example.com", emitScanDelta: true, previousFindingTitles: ["Viejo"] },
  [{ id: "p1-osint-dig-txt", text: "v=spf1 +all" }, { id: "p1-osint-dig-dmarc", text: "" }],
);
assert(findings.some((f) => /\+all/.test(f.title)), "SPF +all heurística");
assert(findings.some((f) => /Índice de exposición/.test(f.title)), "score finding");
assert(findings.some((f) => /Nuevo desde última/.test(f.title)), "delta finding");

assert(missingWafFinding("HTTP/1.1 200 OK\nServer: nginx", "", true).length === 0, "no concluir sin WAF antes de la sonda");
const blockedProbe = "HTTP/1.1 403 Forbidden\n\nblocked by web application firewall";
assert(wafTriggerFindings(blockedProbe).length === 1, "sonda bloqueada = WAF activo");
assert(wafw00fFindings('[{"detected":true,"firewall":"Cloudflare"}]').length === 1, "wafw00f JSON → hallazgo");
assert(missingWafFinding("HTTP/1.1 200 OK\nServer: nginx", blockedProbe, true).length === 0, "con WAF activo no hay ausencia");
assert(
  dropContradictoryWafFindings([
    { title: "Sin WAF/CDN identificable desde caja negra" },
    { title: "WAF activo: bloqueó una sonda de inyección (caja negra)" },
  ]).length === 1,
  "mutuamente excluyentes",
);

console.log("OK — pipeline OSINT expandido");
