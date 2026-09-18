#!/usr/bin/env node
/** Cableado del informe integral: TOC in-document y secciones 00–09 en la misma página. */
import { readFileSync } from "node:fs";

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const html = readFileSync(`${root}/panel/comprehensive-report.html`, "utf8");
const preview = readFileSync(`${root}/panel/report-preview.html`, "utf8");
const live = readFileSync(`${root}/panel/vendor/panel-live.js`, "utf8");
const i18n = readFileSync(`${root}/panel/vendor/i18n.js`, "utf8");

const sections = [
  "sec-00", "sec-01", "sec-02", "sec-03", "sec-04", "sec-05",
  "sec-06", "sec-07", "sec-08", "sec-08-rgpd", "sec-08e", "sec-08f", "sec-09",
];

let fail = 0;
for (const id of sections) {
  try {
    assert(html.includes('id="' + id + '"') || html.includes("id=\"" + id + "\""), "falta #" + id);
    assert(new RegExp('data-go="' + id + '"').test(html), "TOC no apunta a " + id);
  } catch (e) {
    fail += 1;
    console.error("FAIL", e.message);
  }
}

const leaked = html.match(/id="toc-0[1268][^"]*" href="[^#]+"/g) || [];
if (leaked.length) {
  fail += 1;
  console.error("FAIL TOC sigue saliendo a páginas sueltas:", leaked);
}

for (const fn of [
  "renderComprehensiveDocument",
  "renderPreviewPaper",
  "renderReportFindingDossiers",
  "htmlMaturityChapter",
  "htmlMaturityStory",
  "htmlRiskMatrix3x3",
  "htmlGdprDashboard",
  "htmlRgpdChapter",
  "htmlRgpdFindingCard",
  "htmlComplianceRisk",
  "htmlMethodologyAppendix",
  "htmlMitreKillChain",
  "htmlConnectedSurfaces",
  "htmlRemediationPlan",
  "htmlBusinessImpact",
]) {
  if (!live.includes("function " + fn)) {
    fail += 1;
    console.error("FAIL falta", fn);
  }
}

if (!preview.includes('id="preview-paper"')) {
  fail += 1;
  console.error("FAIL report-preview sin #preview-paper");
}

const keys = [
  "comp.sec01Title", "comp.sec08Title", "comp.sec08aTitle", "comp.sec08bTitle",
  "comp.rgpdCardsLead", "comp.methNote", "comp.compRiskLead", "comp.kcPremise",
  "comp.connectedTitle",
  "comp.findingsIndex", "comp.maturityExplain", "comp.maturityMethod",
  "maturity.whyTitle", "maturity.whyScore", "maturity.howUp", "maturity.vsFair",
  "preview.paperTitle", "report.preview",
];
for (const k of keys) {
  const hits = i18n.split('"' + k + '"').length - 1;
  if (hits < 2) {
    fail += 1;
    console.error("FAIL i18n", k, "aparece", hits, "veces (hace falta ES+EN)");
  }
}

if (!html.includes('id="comp-toc-findings"')) {
  fail += 1;
  console.error("FAIL falta #comp-toc-findings en el TOC");
}
if (!html.includes('id="comp-findings"')) {
  fail += 1;
  console.error("FAIL falta #comp-findings");
}
if (!live.includes("function htmlReportFindingCard") || !live.includes("function renderReportFindingDossiers")) {
  fail += 1;
  console.error("FAIL falta htmlReportFindingCard / renderReportFindingDossiers");
}
if (!live.includes('id="preview-dossiers"')) {
  fail += 1;
  console.error("FAIL preview paper sin #preview-dossiers");
}
if (!html.includes('id="comp-paper"')) {
  fail += 1;
  console.error("FAIL comprehensive-report sin #comp-paper");
}
const exportJs = readFileSync(`${root}/panel/vendor/export.js`, "utf8");
if (!exportJs.includes("function printLivePaper") || !exportJs.includes("function findLivePaper")) {
  fail += 1;
  console.error("FAIL export.js no imprime el papel de la vista previa");
}
if (!exportJs.includes("print-color-adjust:exact")) {
  fail += 1;
  console.error("FAIL export.js no fuerza colores en impresión");
}
if (!exportJs.includes("function buildDossierDocumentHTML") || !exportJs.includes("DarkSpearDossier.render")) {
  fail += 1;
  console.error("FAIL export.js no genera fichas DarkSpearDossier al exportar");
}
if (!exportJs.includes(".glass-panel") || !exportJs.includes("#D8E3F0")) {
  fail += 1;
  console.error("FAIL export.js no lleva el CSS de tarjetas glass-panel");
}
const reporting = readFileSync(`${root}/panel/reporting.html`, "utf8");
if (!reporting.includes("vendor/finding-dossier.js")) {
  fail += 1;
  console.error("FAIL reporting.html no carga finding-dossier.js");
}
if (reporting.includes('data-report-export="pdf"')) {
  fail += 1;
  console.error("FAIL reporting.html sigue ofreciendo export PDF");
}
if (!reporting.includes("Abrir informe HTML") && !i18n.includes("Abrir informe HTML")) {
  fail += 1;
  console.error("FAIL falta CTA de informe HTML");
}
if (!live.includes('bindScanExport("btn-export"') || !live.includes(', "html")')) {
  fail += 1;
  console.error("FAIL el informe integral no descarga HTML");
}

if (!live.includes('hideOnListIds: ["comp-toc"]')) {
  fail += 1;
  console.error("FAIL bootComprehensiveReport no oculta el TOC en la lista");
}

for (const token of [
  "SYSTEMIC_PATTERNS",
  "function htmlGlossary",
  "function htmlKpiTiles",
  "function htmlCvssCompactLine",
  "rpt-kpi-row",
  "rpt-pass-badge",
  "rpt-impact",
  "findingPhaseCode",
]) {
  if (!live.includes(token)) {
    fail += 1;
    console.error("FAIL panel-live.js falta", token);
  }
}
if (html.includes("<ul id=\"sec-03-list\"")) {
  fail += 1;
  console.error("FAIL sec-03-list sigue siendo <ul>");
}
if (!html.includes('id="sec-03-list"') || !html.includes('id="sec-05-list"')) {
  fail += 1;
  console.error("FAIL faltan contenedores 03/05");
}
if (!html.includes('id="sec-07-body"') || !html.includes('id="sec-08b"')) {
  fail += 1;
  console.error("FAIL faltan #sec-07-body / #sec-08b");
}
if (!live.includes("htmlMethodologyAppendix(all") || !live.includes("htmlComplianceRisk(all)")) {
  fail += 1;
  console.error("FAIL render no cablea metodología / 08b");
}
if (/G-00[1-9]/.test(live)) {
  fail += 1;
  console.error("FAIL panel-live inventa IDs G-");
}
if (!html.includes("rpt-kpi-row")) {
  fail += 1;
  console.error("FAIL comprehensive-report sin CSS de KPIs");
}
for (const k of ["comp.glossaryTitle", "comp.patternDominant", "comp.passBadge", "comp.colPhase"]) {
  const hits = i18n.split('"' + k + '"').length - 1;
  if (hits < 2) {
    fail += 1;
    console.error("FAIL i18n", k, "aparece", hits, "veces (hace falta ES+EN)");
  }
}

if (fail) {
  console.error("Fallos:", fail);
  process.exit(1);
}
console.log("OK informe integral: TOC 00–09 in-document, preview paper, i18n ES/EN");
