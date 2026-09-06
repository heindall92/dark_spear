#!/usr/bin/env node
/**
 * Cableado panel: dossier CVSS/CWE/MITRE, Kill Chain, RGPD, índice de exposición
 * sobre los títulos nuevos de OSINT + hallazgos típicos de lab.
 */
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { computeExposureRisk } from "../backend/js/vuln-kb.js";

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

function loadDossier() {
  const code = readFileSync(`${root}/panel/vendor/finding-dossier.js`, "utf8");
  const sandbox = {
    window: {},
    console,
    localStorage: { getItem: () => "es" },
  };
  sandbox.window = sandbox;
  sandbox.global = sandbox;
  vm.runInNewContext(code.replace("(window);", "(this);"), sandbox);
  if (!sandbox.DarkSpearDossier) throw new Error("DarkSpearDossier no cargó");
  return sandbox.DarkSpearDossier;
}

function loadKillChainAndMitre() {
  const src = readFileSync(`${root}/panel/vendor/panel-live.js`, "utf8");
  const kc = src.match(/var KILL_CHAIN_STAGES = (\[[\s\S]*?\n  \];)/);
  const mm = src.match(/var MITRE_MATRIX = (\[[\s\S]*?\n  \];)/);
  if (!kc || !mm) throw new Error("no pude extraer KILL_CHAIN_STAGES / MITRE_MATRIX");
  const sandbox = {};
  vm.runInNewContext(
    `KILL_CHAIN_STAGES = ${kc[1]}\nMITRE_MATRIX = ${mm[1]}`,
    sandbox,
  );
  return sandbox;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const NEW_TITLES = [
  { title: "GitHub Personal Access Token hardcodeada en bundle JS (/main.js)", severity: "Critical", wantRe: /hardcodeada en bundle JS/i, wantMitre: /T1552/ },
  { title: "Credencial GitHub Personal Access Token viva confirmada (validador read-only)", severity: "Critical", wantRe: /viva confirmada/i, wantMitre: /T1552/ },
  { title: "AWS Access Key ID decodifica a account 609629065308", severity: "Info", wantRe: /AWS Access Key ID decodifica/i, wantMitre: /T1580|T1590|T1595/ },
  { title: "ARN AWS en el activo referencia account 609629065308", severity: "Info", wantRe: /ARN AWS/i },
  { title: "acme.com usa Google Workspace (MX Google)", severity: "Info", wantRe: /Google Workspace/i, wantMitre: /T1589/ },
  { title: "acme.com resuelve a tenant Entra ID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", severity: "Info", wantRe: /tenant Entra ID/i, wantMitre: /T1589/ },
  { title: "acme.com expone metadata SAML/ADFS (FederationMetadata.xml)", severity: "Info", wantRe: /SAML/i },
  { title: "AS64500 (Acme Net) anuncia 12+ prefijo(s) hermano(s)", severity: "Info", wantRe: /prefijo/i },
  { title: "AS16509 es de un hyperscaler/CDN (AMAZON-02) — sin expansión de prefijos", severity: "Info", wantRe: /hyperscaler/i },
  { title: "Índice de exposición OSINT: 42.5/100 (grado C)", severity: "Info", wantRe: /Índice de exposición OSINT/i },
  { title: "Nuevo desde última auditoría: 3 hallazgo(s)", severity: "Info", wantRe: /Nuevo desde última/i },
  { title: "Dominio acme.com sin registro SPF", severity: "Medium", wantRe: /sin registro SPF/i },
  { title: "Bucket GCS referenciado por la app es listable públicamente", severity: "High", wantRe: /Bucket GCS/i, wantMitre: /T1530/ },
  { title: "Contenedor Azure Blob referenciado por la app es listable públicamente", severity: "High", wantRe: /Azure Blob/i, wantMitre: /T1530/ },
];

const dossier = loadDossier();
const { KILL_CHAIN_STAGES, MITRE_MATRIX } = loadKillChainAndMitre();

let covered = 0;
MITRE_MATRIX.forEach((col) => {
  (col.techniques || []).forEach((t) => {
    if (t.coverage === "high" || t.coverage === "partial") covered += 1;
  });
});
console.log("MITRE técnicas high/partial:", covered);

const genericFallback = /clasificación a confirmar|CWE-1035/;
let fail = 0;
const findings = [];

for (const row of NEW_TITLES) {
  const f = {
    title: row.title,
    severity: row.severity,
    description: row.title,
    remediation: "test",
    asset: "https://acme.com",
    status: "accepted",
  };
  findings.push(f);
  const d = dossier.enrich(f);
  const narrative = (d.narrative && (d.narrative.es || d.narrative)) || "";
  if (genericFallback.test(JSON.stringify(d)) && genericFallback.test(String(narrative))) {
    console.log("FAIL dossier genérico:", row.title);
    fail += 1;
    continue;
  }
  if (!d.cvss || d.cvss.vector == null) {
    console.log("FAIL sin CVSS:", row.title);
    fail += 1;
  }
  if (!(d.nist && d.nist.length) && !(d.gov && d.gov.nist && d.gov.nist.length)) {
    console.log("FAIL sin NIST CSF:", row.title);
    fail += 1;
  }
  if (row.wantMitre) {
    const ids = (d.mitre || []).map((m) => m.id).join(" ");
    if (!row.wantMitre.test(ids + " " + JSON.stringify(d))) {
      const blob = row.title.toLowerCase();
      const hits = [];
      MITRE_MATRIX.forEach((col) => {
        (col.techniques || []).forEach((t) => {
          if (t.re && t.re.test(blob)) hits.push(t.id);
        });
      });
      if (!hits.some((id) => row.wantMitre.test(id))) {
        console.log("FAIL MITRE", row.title, "dossier:", ids, "matrix:", hits.join(","));
        fail += 1;
      }
    }
  }
  const blob = (row.title + " " + (d.narrative?.es || "")).toLowerCase();
  let stage = "Exploitation(default)";
  for (const k of KILL_CHAIN_STAGES) {
    if (k.re.test(blob)) {
      stage = k.stage;
      break;
    }
  }
  console.log(`  OK [${d.cvss?.score}] ${row.title.slice(0, 72)} → KC ${stage}`);
}

const score = computeExposureRisk(findings);
console.log("exposure risk:", score);
assert(score.risk >= 0 && score.grade, "score inválido");

const fairCard = dossier.enrich({
  id: "f-7",
  title: "Índice de exposición OSINT: 2.3/100 (grado A)",
  severity: "Info",
  description: "Cuantificación FAIR-lite sobre los hallazgos de esta auditoría (sin tráfico extra): exposición 0.9, amenaza 5, impacto 40. Motor dominante: business-impact.",
  remediation: "Usar el grado para priorizar remediación ante dirección.",
  asset: "http://www.cubadebate.cu",
});
assert(fairCard.fair && fairCard.fair.risk === 2.3 && fairCard.fair.grade === "A", "FAIR parse 2.3/A");
assert(fairCard.fair.exposure === 0.9 && fairCard.fair.threat === 5 && fairCard.fair.impact === 40, "FAIR E/T/I");
assert(fairCard.gov && /contexto|OSINT|context/i.test(JSON.stringify(fairCard.gov.category)), "GOV.context");
assert(/N\/A/.test(fairCard.gov.sanction.art), "índice no es tramo sancionador");
assert(/Exposición \(E=/.test(fairCard.narrative) && /grado A/i.test(fairCard.exec), "FAIR dossier explica E/T/I y el grado");
assert(/no abras un ticket/i.test(fairCard.exec + " " + (fairCard.steps || []).join(" ")), "FAIR dossier dice que no es un ticket");

const art33re = /hardcodead[oa] en bundle|viva confirmada|access key id|arn aws/i;
assert(art33re.test(NEW_TITLES[0].title), "Art.33 debería cubrir secretos en bundle");
assert(art33re.test(NEW_TITLES[1].title), "Art.33 debería cubrir validador vivo");

if (covered < 30) {
  console.log("WARN: cobertura MITRE high/partial < 30:", covered);
}
const live = readFileSync(`${root}/panel/vendor/panel-live.js`, "utf8");
const titleRe = live.match(/var TECH_MEASURE_TITLE_RE = \/(.+)\/i;/);
const skipRe = live.match(/var TECH_MEASURE_SKIP_RE = \/(.+)\/i;/);
assert(titleRe && skipRe, "regex medidas técnicas en panel-live");
const TECH_TITLE = new RegExp(titleRe[1], "i");
const TECH_SKIP = new RegExp(skipRe[1], "i");
function isMeasure(title) {
  return !TECH_SKIP.test(title) && TECH_TITLE.test(title);
}
assert(isMeasure("WAF activo: bloqueó una sonda de inyección (caja negra)"), "WAF activo es medida");
assert(isMeasure("Perímetro con filtrado de paquetes (21 puerto(s) filtered)"), "perímetro es medida");
assert(!isMeasure("Sin WAF/CDN identificable desde caja negra"), "sin WAF no es medida");
assert(!isMeasure("Índice de exposición OSINT: 2.3/100 (grado A)"), "índice no es medida");
assert(!isMeasure("Dominio www.cubadebate.cu sin registro SPF"), "SPF ausente no es medida");
console.log("OK medidas técnicas (WAF + perímetro, no SPF/índice)");

if (fail) {
  console.log(`FAIL: ${fail} desconexiones dossier/MITRE`);
  process.exit(1);
}
console.log("OK cableado dossier + MITRE + kill chain + exposición");
