#!/usr/bin/env node
import { katanaArgs, extractKatanaUrls, katanaFindings } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

// katanaArgs
const args = katanaArgs("https://x.com");
check("incluye -u con el target", args.includes("https://x.com"));
check("headless + no-sandbox activados", args.includes("-hl") && args.includes("-no-sandbox"));
check("modo -silent (un URL por línea)", args.includes("-silent"));

// extractKatanaUrls
const stdout = [
  "https://x.com/",
  "https://x.com/rest/products/search?q=",
  "https://x.com/api/admin/config",
  "https://fonts.googleapis.com", // otro host: descartado
  "https://x.com/rest/products/search?q=", // duplicado: descartado
  "no-es-una-url", // línea inválida: descartada
].join("\n");
const urls = extractKatanaUrls(stdout, "https://x.com");
check("extrae solo URLs del mismo host", urls.length === 3);
check("descarta duplicados", urls.filter((u) => u.includes("rest/products/search")).length === 1);
check("descarta el host externo", !urls.some((u) => u.includes("googleapis")));

// stdout vacío: sin URLs
check("stdout vacío -> array vacío", extractKatanaUrls("", "https://x.com").length === 0);

// katanaFindings
const findings = katanaFindings(stdout, "https://x.com");
check("genera 1 finding Info consolidado", findings.length === 1 && findings[0].severity === "Info");
check("el finding lista los endpoints descubiertos", findings[0].description.includes("/rest/products/search"));

check("sin URLs: cero findings", katanaFindings("no-es-una-url", "https://x.com").length === 0);

// Wiring en Fase 2: aparece con args correctos, se salta en DVWA (ya
// cubierto por sondas de módulo específicas, mismo criterio que
// gobuster/ffuf/feroxbuster).
const ctxNormal = buildPlaybookContext([], { host: "x.com", scope: "https://x.com" });
const stepsFase2 = stepsForPhase(2, "https://x.com", ctxNormal);
const katanaStep = stepsFase2.find((s) => s.id === "p2-katana");
check("Fase 2 incluye el step p2-katana", !!katanaStep);
check("p2-katana apunta al baseUrl correcto", katanaStep.args.includes("https://x.com"));

const ctxDvwa = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", isDvwa: true });
const stepsFase2Dvwa = stepsForPhase(2, "https://x.com", ctxDvwa);
const katanaStepDvwa = stepsFase2Dvwa.find((s) => s.id === "p2-katana");
check("p2-katana se salta en DVWA (skipHeavy)", !katanaStepDvwa || katanaStepDvwa.skipIf?.(ctxDvwa));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
