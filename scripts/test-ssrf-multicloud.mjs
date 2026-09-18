#!/usr/bin/env node
/**
 * Mejora cloud: SSRF hacia metadata solo probaba AWS. GCP y Azure exponen
 * el MISMO endpoint (169.254.169.254) con path/query distintos, pero
 * ambos EXIGEN un header propio (Metadata-Flavor: Google / Metadata: true)
 * que un SSRF ciego (la app hace el fetch, nosotros no controlamos sus
 * headers) no puede forjar — por eso, a diferencia de AWS (IMDSv1 sin
 * header), en GCP/Azure lo más que se puede confirmar sin forjar headers
 * es que la petición SÍ llegó al servicio de metadata real (bloqueada por
 * la propia nube, no por la red) — eso ya prueba SSRF real hacia la
 * superficie interna, aunque no filtre credenciales por esta vía exacta.
 */
import {
  SSRF_CLOUD_METADATA,
  ssrfImdsCurlSteps,
  ssrfGcpImdsCurlSteps,
  ssrfAzureImdsCurlSteps,
  SSRF_GCP_BLOCKED_RE,
  SSRF_GCP_STRONG_RE,
  SSRF_AZURE_BLOCKED_RE,
  SSRF_AZURE_STRONG_RE,
} from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- URLs / steps ---------------------------- */

check("AWS sigue apuntando a IMDSv1 (compat con el probe original)", SSRF_CLOUD_METADATA.aws.url.includes("iam/security-credentials"));
check("GCP apunta a computeMetadata en la misma IP 169.254.169.254", SSRF_CLOUD_METADATA.gcp.url.includes("169.254.169.254") && SSRF_CLOUD_METADATA.gcp.url.includes("computeMetadata"));
check("Azure apunta a metadata/instance en la misma IP", SSRF_CLOUD_METADATA.azure.url.includes("169.254.169.254") && SSRF_CLOUD_METADATA.azure.url.includes("metadata/instance"));

const gcpSteps = ssrfGcpImdsCurlSteps((id, tool, args) => ({ id, tool, args }), "p1-ssrf-gcp", "https://x.com", "10");
check("genera 1 step GCP por parámetro típico de SSRF", gcpSteps.length > 0);
check("cada step GCP manda la URL de metadata GCP", gcpSteps.every((s) => s.args.some((a) => String(a).includes(SSRF_CLOUD_METADATA.gcp.url))));

const azureSteps = ssrfAzureImdsCurlSteps((id, tool, args) => ({ id, tool, args }), "p1-ssrf-azure", "https://x.com", "10");
check("genera 1 step Azure por parámetro típico de SSRF", azureSteps.length > 0);
check("cada step Azure manda la URL de metadata Azure", azureSteps.every((s) => s.args.some((a) => String(a).includes(SSRF_CLOUD_METADATA.azure.url))));

// AWS sin cambios de comportamiento (no romper el probe ya validado en producción).
const awsSteps = ssrfImdsCurlSteps((id, tool, args) => ({ id, tool, args }), "p1-ssrf-imds", "https://x.com", "10");
check("AWS conserva su comportamiento original", awsSteps.length === gcpSteps.length && awsSteps.every((s) => s.args.some((a) => String(a).includes(SSRF_CLOUD_METADATA.aws.url))));

/* ---------------------------- detección GCP ---------------------------- */

// Bloqueado por GCP mismo (falta el header Metadata-Flavor) -> confirma que
// la petición SÍ llegó al metadata real, aunque no filtre nada.
const gcpBlocked = `HTTP/1.1 403 Forbidden\n\nMetadata-Flavor header required to access metadata`;
check("GCP: respuesta de bloqueo por header ausente -> señal de SSRF confirmado (débil)", SSRF_GCP_BLOCKED_RE.test(gcpBlocked));

// El caso "fuerte" (la app reenvía el header sin querer, o algún proxy lo agrega).
const gcpLeaked = JSON.stringify({ numericProjectId: 123456789012, serviceAccounts: { default: {} } });
check("GCP: metadata real filtrada -> señal fuerte", SSRF_GCP_STRONG_RE.test(gcpLeaked));

check("GCP: respuesta ajena (eco del parámetro, sin fetch real) -> ninguna señal", !SSRF_GCP_BLOCKED_RE.test("no se pudo cargar la imagen") && !SSRF_GCP_STRONG_RE.test("no se pudo cargar la imagen"));

/* ---------------------------- detección Azure ---------------------------- */

const azureBlocked = `HTTP/1.1 400 Bad Request\n\n{"error":"Required metadata header not specified"}`;
check("Azure: respuesta de bloqueo por header ausente -> señal de SSRF confirmado (débil)", SSRF_AZURE_BLOCKED_RE.test(azureBlocked));

const azureLeaked = JSON.stringify({ compute: { subscriptionId: "abc-123", resourceGroupName: "prod-rg" } });
check("Azure: metadata real filtrada -> señal fuerte", SSRF_AZURE_STRONG_RE.test(azureLeaked));

check("Azure: respuesta ajena -> ninguna señal", !SSRF_AZURE_BLOCKED_RE.test("timeout") && !SSRF_AZURE_STRONG_RE.test("timeout"));

/* ------------------------- wiring Fase 1 ------------------------- */

const ctx = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: true });
const stepsFase1 = stepsForPhase(1, "https://x.com", ctx);
check("Fase 1 incluye steps p1-ssrf-gcp-*", stepsFase1.some((s) => s.id.startsWith("p1-ssrf-gcp-")));
check("Fase 1 incluye steps p1-ssrf-azure-*", stepsFase1.some((s) => s.id.startsWith("p1-ssrf-azure-")));
check("Fase 1 sigue incluyendo p1-ssrf-imds-* (AWS, sin romper lo existente)", stepsFase1.some((s) => s.id.startsWith("p1-ssrf-imds-")));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
