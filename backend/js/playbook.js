/**
 * Playbook por fase PTES — pasos sin LLM (recon predecible).
 * Fase 1: núcleo HTTP → detectar stack → pasos dirigidos (heurística).
 * Probado contra DVWA http://127.0.0.1:8888 (login.php admin/password).
 *
 * Superficie DVWA: GET autenticado por módulo (vuln-kb.js / HackTricks).
 * No envía payloads: solo confirma que el módulo existe (HTTP, no 302 a login).
 */

import {
  CORS_PROBE_ORIGIN,
  DVWA_EXTRA_PROBES,
  API_SURFACE_PROBES,
  dvwaModuleCurlSteps,
  genericExposureCurlSteps,
  apiSurfaceCurlSteps,
  sqliLoginProbeSteps,
  nosqliLoginProbeSteps,
  xssReflectionCurlSteps,
  openRedirectCurlSteps,
  idorCurlSteps,
  hydraDefCredsSteps,
  JWT_TOKEN_RE,
  JWT_ALGNONE_PROBE_PATHS,
  forgeAlgNoneToken,
  waybackOsintSteps,
  jsBundleCurlSteps,
  extractS3BucketHost,
  extractAzureBlobContainer,
  extractGcsBucket,
  azureBlobCheckStep,
  gcsBucketCheckStep,
  ssrfImdsCurlSteps,
  perimeterNmapArgs,
  ipRdapCheckStep,
  idpDiscoveryCurlSteps,
  extractCapturedSecrets,
  extractAsnFromBlob,
  extractAsnHolderFromBlob,
  ripeAsnCurlSteps,
  HYPERSCALER_HOLDER_RE,
  secretValidateCurlSteps,
  extractDangerousCodePatterns,
  codeDangerProbeSteps,
  nucleiTagsForContext,
  nucleiCurlArgs,
  sqlmapCurlArgs,
  subfinderArgs,
  extractSubfinderHosts,
  httpxArgsForHosts,
  testsslArgs,
  dnsreconArgs,
} from "./vuln-kb.js";

const WL = {
  common: "/usr/share/seclists/Discovery/Web-Content/common.txt",
  dirb: "/usr/share/wordlists/dirb/common.txt",
  small: "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
  rockyou: "/usr/share/wordlists/rockyou.txt",
};

const OSINT_SUB_PREFIXES = ["www", "mail", "vpn", "dev", "api", "staging"];

function parseTarget(target) {
  const raw = String(target || "").trim();
  if (!raw) return { host: "", port: "", baseUrl: "" };
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      return {
        host: u.hostname,
        port: u.port || (u.protocol === "https:" ? "443" : "80"),
        baseUrl: u.origin,
      };
    } catch {
      return { host: raw, port: "", baseUrl: raw };
    }
  }
  const [host, port] = raw.split(":");
  const scheme = port === "443" ? "https" : "http";
  const baseUrl = port ? `${scheme}://${host}:${port}` : `${scheme}://${host}`;
  return { host: host || raw, port: port || "", baseUrl };
}

function hostLabel(value) {
  const h = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0];
  return h.startsWith("www.") ? h.slice(4) : h;
}

function scopeRoot(host, scope) {
  return hostLabel(scope) || hostLabel(host);
}

function isIpHost(host) {
  const h = String(host || "").trim();
  if (!h) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(":") && !/^[a-zA-Z]/.test(h)) return true;
  return false;
}

/** El target es el propio motor (caja gris: ufw/iptables/nft SÍ aplican). */
function isLoopbackHost(host) {
  const h = String(host || "").trim().toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "0.0.0.0";
}

/** Salida útil para el feed: descarta vacío, 000, 404 genéricos y ruido OSINT. */
export function isMeaningfulToolOutput(stdout, stderr) {
  const text = [stdout, stderr].map((s) => String(s ?? "").trim()).join("\n").trim();
  if (!text) return false;
  if (/^0+$/.test(text.replace(/\s/g, ""))) return false;
  if (/^404$/m.test(text)) return false;
  if (/404 Not Found/i.test(text) && /Apache\/[\d.]+.*Server at/i.test(text) && text.length < 800) {
    return false;
  }
  if (/502 Bad Gateway/i.test(text) && /nginx/i.test(text) && text.length < 500) {
    return false;
  }
  if (/443\/tcp closed/i.test(text) && !/\bopen\b/i.test(text) && text.length < 500) {
    return false;
  }
  return true;
}

function portSpec(target) {
  const { port } = parseTarget(target);
  if (port) return port;
  return "80,443,8080,8443,8888";
}

function portList(target) {
  return portSpec(target).split(",").map((p) => p.trim()).filter(Boolean);
}

function step(id, tool, args, when, meta = {}) {
  const s = { id, tool, args, ...meta };
  if (when) s.when = when;
  return s;
}

/**
 * Rutas Disallow de robots.txt (máx. 3, sin comodines). robots.txt es una
 * convención para crawlers, no control de acceso: si delata una ruta, vale
 * la pena visitarla — es justo lo que un atacante real haría.
 */
function extractRobotsDisallowed(rawBlob) {
  const seen = new Set();
  const out = [];
  for (const m of String(rawBlob || "").matchAll(/disallow:\s*(\/[^\s#]*)/gi)) {
    const p = m[1].trim().replace(/\/+$/, "") || "/";
    if (p === "/" || p === "*" || seen.has(p)) continue;
    seen.add(p);
    out.push(p);
    if (out.length >= 3) break;
  }
  return out;
}

const API_SURFACE_PATHS = new Set(API_SURFACE_PROBES.map((p) => p.path.replace(/\/+$/, "")));

/**
 * Primer JWT visto en cualquier salida acumulada (login SQLi/NoSQLi, etc.).
 * Se usa para el bypass alg=none: reforjar EL MISMO token capturado, no uno
 * inventado — si el backend confía en alg=none, el claim de rol/usuario
 * original sigue ahí, solo sin verificación de firma.
 */
function extractCapturedJwt(rawBlob) {
  const m = String(rawBlob || "").match(JWT_TOKEN_RE);
  return m ? m[0] : null;
}

/**
 * Rutas que gobuster / ffuf / feroxbuster confirmaron de verdad (no una
 * lista fija de adivinanzas). Cada herramienta imprime un formato distinto;
 * si el blob mezcla más de 25 paths únicos, es ruido de SPA/catch-all.
 */
function normalizeBrutePath(raw) {
  let p = String(raw || "").trim();
  if (/^https?:\/\//i.test(p)) {
    try { p = new URL(p).pathname; } catch { return ""; }
  }
  if (!p.startsWith("/")) p = `/${p}`;
  p = p.replace(/\/+$/, "") || "/";
  if (p.length > 80 || /[<>"\s]/.test(p)) return "";
  return p;
}

export function extractBruteDiscoveredPaths(rawBlob) {
  const seen = new Set();
  const out = [];
  const add = (raw) => {
    const p = normalizeBrutePath(raw);
    if (!p || p === "/" || API_SURFACE_PATHS.has(p) || seen.has(p)) return;
    seen.add(p);
    out.push(p);
  };
  const text = String(rawBlob || "");
  for (const m of text.matchAll(/^(\/\S+)\s+\(Status:\s*\d{3}\)/gm)) add(m[1]);
  for (const m of text.matchAll(/^(https?:\/\/\S+)\s+\(Status:\s*\d{3}\)/gm)) add(m[1]);
  for (const m of text.matchAll(/^\s*(?:200|301|302|403)\s+GET\s+\S+\s+\S+\s+\S+\s+(https?:\/\/\S+)/gim)) add(m[1]);
  for (const m of text.matchAll(/^https?:\/\/[^\s]+\/[A-Za-z0-9._~%-][^\s]*$/gim)) add(m[0]);
  for (const m of text.matchAll(/^([A-Za-z0-9._~%-]{2,40})\s+\[Status:\s*\d{3}/gm)) add(`/${m[1]}`);
  if (out.length > 25) return [];
  return out.slice(0, 3);
}

/** Inferir stack desde salidas del playbook (whatweb, curl, etc.). */
export function buildPlaybookContext(stepOutputs, ctx = {}) {
  const rawBlob = (Array.isArray(stepOutputs) ? stepOutputs : []).join("\n");
  const blob = rawBlob.toLowerCase();
  const root = scopeRoot(ctx.host || "", ctx.scope);
  return {
    cookieFile: ctx.cookieFile || "/tmp/ds-playbook-cookies.txt",
    scope: ctx.scope || "",
    host: ctx.host || "",
    isIpTarget: ctx.isIpTarget ?? isIpHost(root),
    isDvwa: /dvwa|damn vulnerable web application/.test(blob) || ctx.isDvwa === true,
    // Requiere ruta real (con "/") o firma explícita, no la palabra suelta:
    // gobuster/ffuf contra un SPA que responde 200 en todo vuelca su wordlist
    // completa como "coincidencias", y esas listas traen "wordpress",
    // "wp-content", etc. como entradas de diccionario — no como detección real.
    isWordpress: /\/wp-content\/|\/wp-includes\/|wp-login\.php|powered by wordpress|generator" content="wordpress/.test(blob) || ctx.isWordpress === true,
    isApache: /apache/.test(blob),
    hasLogin: /login\.php|name="password"|sign in|type="password"/.test(blob) || ctx.hasLogin === true,
    hasWebStack: /apache|nginx|php|dvwa|wordpress|http\//.test(blob) || ctx.hasWebStack === true,
    robotsDisallowed: ctx.robotsDisallowed && ctx.robotsDisallowed.length
      ? ctx.robotsDisallowed
      : extractRobotsDisallowed(rawBlob),
    bruteDiscovered: ctx.bruteDiscovered && ctx.bruteDiscovered.length
      ? ctx.bruteDiscovered
      : extractBruteDiscoveredPaths(rawBlob),
    capturedJwt: ctx.capturedJwt || extractCapturedJwt(rawBlob),
    capturedSecrets: (ctx.capturedSecrets && ctx.capturedSecrets.length)
      ? ctx.capturedSecrets
      : extractCapturedSecrets(rawBlob),
    dangerousCodeHits: (ctx.dangerousCodeHits && ctx.dangerousCodeHits.length)
      ? ctx.dangerousCodeHits
      : extractDangerousCodePatterns(rawBlob),
    subfinderHosts: (ctx.subfinderHosts && ctx.subfinderHosts.length)
      ? ctx.subfinderHosts
      : extractSubfinderHosts(rawBlob, root),
    extractedAsn: ctx.extractedAsn || extractAsnFromBlob(rawBlob),
    asnHolder: ctx.asnHolder || extractAsnHolderFromBlob(rawBlob),
    asnIsHyperscaler: ctx.asnIsHyperscaler === true
      || HYPERSCALER_HOLDER_RE.test(ctx.asnHolder || extractAsnHolderFromBlob(rawBlob) || ""),
    previousFindingTitles: ctx.previousFindingTitles || [],
    emitScanDelta: ctx.emitScanDelta === true,
    s3BucketHost: ctx.s3BucketHost || extractS3BucketHost(rawBlob),
    azureBlobContainer: ctx.azureBlobContainer || extractAzureBlobContainer(rawBlob),
    gcsBucketName: ctx.gcsBucketName || extractGcsBucket(rawBlob),
  };
}

/** OSINT DNS/CT/subdominios — solo dominios reales (no IPs ni www.127.0.0.1). */
function domainOsintSteps(root, host) {
  if (isIpHost(root) || isIpHost(host) || !root.includes(".")) return [];
  const ctHost = encodeURIComponent(`%.${root}`);
  const steps = [
    step("p1-osint-dig-a", "dig", ["+short", "A", root], null, {
      desc: "Registros DNS A del dominio raíz en scope",
    }),
    step("p1-osint-dig-aaaa", "dig", ["+short", "AAAA", root], null, {
      desc: "Registros DNS AAAA (IPv6)",
    }),
    step("p1-osint-dig-mx", "dig", ["+short", "MX", root], null, {
      desc: "Registros MX — infraestructura de correo",
    }),
    step("p1-osint-dig-ns", "dig", ["+short", "NS", root], null, {
      desc: "Servidores DNS autoritativos",
    }),
    step("p1-osint-dig-txt", "dig", ["+short", "TXT", root], null, {
      desc: "Registros TXT (SPF, DKIM, verificación)",
    }),
    step("p1-osint-dig-dmarc", "dig", ["+short", "TXT", `_dmarc.${root}`], null, {
      desc: "Registro DMARC (política anti-spoofing del dominio)",
    }),
    step("p1-osint-nslookup-a", "nslookup", [root], null, {
      desc: "Resolución A alternativa (nslookup)",
    }),
    step("p1-osint-whois-rdap", "curl", ["-s", "--max-time", "20", `https://rdap.org/domain/${root}`], null, {
      desc: "WHOIS/RDAP pasivo vía HTTPS",
    }),
    step("p1-osint-crtsh-ct", "curl", [
      "-s", "--max-time", "25",
      `https://crt.sh/?q=${ctHost}&output=json`,
    ], null, {
      desc: "Certificate Transparency pasivo (crt.sh JSON)",
    }),
    step("p1-osint-subfinder", "subfinder", subfinderArgs(root), null, {
      desc: "Enumeración pasiva de subdominios (subfinder, sin tocar el target)",
    }),
    step("p1-osint-dnsrecon", "dnsrecon", dnsreconArgs(root), null, {
      desc: "Enumeración DNS estándar (SOA/NS/MX/A + intento de transferencia de zona)",
    }),
    step("p1-osint-httpx", "httpx", (c) => (
      c.subfinderHosts && c.subfinderHosts.length ? httpxArgsForHosts(c.subfinderHosts) : null
    ), null, {
      desc: "Fingerprint HTTP de los subdominios hallados por subfinder",
      skipIf: (c) => !c.subfinderHosts || !c.subfinderHosts.length,
    }),
    ...idpDiscoveryCurlSteps(step, root),
  ];

  for (const prefix of OSINT_SUB_PREFIXES) {
    const subHost = `${prefix}.${root}`;
    if (subHost === host || subHost === root) continue;
    steps.push(
      step(`p1-osint-sub-${prefix}`, "curl", [
        "-s", "-I", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10",
        `https://${subHost}/`,
      ], null, {
        desc: `Sonda HEAD a subdominio ${prefix}.${root}`,
      }),
    );
  }
  return steps;
}

function phase1Steps(baseUrl, host, target, cookie, ctx = {}) {
  const root = scopeRoot(host, ctx.scope);
  const ipTarget = isIpHost(root) || isIpHost(host);
  const ports = portList(target);
  const needsAuthProbe = (c) => c.isDvwa || c.hasLogin;

  const steps = [
    step("p1-nmap-sV", "nmap", ["-sV", "-p", portSpec(target), host], null, {
      desc: "Detección de servicios en puertos del target",
    }),
    // Caja negra: open vs filtered en un set curado de puertos de gestión/BD.
    // Se omite en loopback: nmap 127.0.0.1 listaría ssh/cups de Kali, no del
    // cliente. En local la capa equivalente es ufw/iptables/nft (abajo).
    step("p1-nmap-perimeter", "nmap", perimeterNmapArgs(host, portSpec(target).split(",")[0]), null, {
      desc: "Perímetro: puertos de gestión/BD open vs filtered (caja negra)",
      skipIf: (c) => isLoopbackHost(c.host) || isLoopbackHost(host),
    }),
    ...(ipTarget && !isLoopbackHost(host) ? ipRdapCheckStep(step, root) : []),
    ...(ipTarget && !isLoopbackHost(host) ? ripeAsnCurlSteps(step, root) : []),
    step("p1-osint-curl-head-root", "curl", ["-s", "-I", "--max-time", "15", baseUrl], null, {
      desc: "Cabeceras HTTP de la raíz",
    }),
    step("p1-wafw00f", "wafw00f", ["--no-colors", "-f", "json", "-o", "-", "-T", "10", baseUrl], null, {
      desc: "Fingerprint WAF/CDN (wafw00f)",
    }),
    step("p1-waf-trigger", "curl", [
      "-s", "-i", "--max-time", "12", "-w", "\nDS_HTTP:%{http_code}\n",
      "-G", "--data-urlencode", "ds_waf_probe=1' UNION SELECT NULL--",
      baseUrl,
    ], null, {
      desc: "Sonda WAF (caja negra): ¿el perímetro bloquea una UNION SELECT inofensiva?",
    }),
    step("p1-osint-curl-root", "curl", ["-s", "-L", "--max-time", "25", baseUrl], null, {
      desc: "HTTP GET / — contenido público inicial",
    }),
    ...DVWA_EXTRA_PROBES.map((p) =>
      step(
        "p1-curl-" + p.stepId,
        "curl",
        ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p1-curl-" + p.stepId, baseUrl + p.path],
        null,
        { desc: p.desc },
      ),
    ),
    step("p1-whatweb", "whatweb", ["-a", "3", baseUrl], null, {
      desc: "Fingerprint tecnológico (whatweb)",
    }),
    ...domainOsintSteps(root, host),
    ...waybackOsintSteps(step, root),
    step("p1-osint-curl-robots", "curl", ["-s", "--max-time", "15", `${baseUrl}/robots.txt`], null, {
      desc: "robots.txt",
      skipIf: (c) => !c.hasWebStack,
    }),
    // Sigue las rutas que robots.txt intenta ocultar con Disallow: la lista
    // solo se conoce DESPUÉS de leer robots.txt, así que args es una función
    // evaluada contra el contexto ya actualizado (ver execSpec en agent.js).
    step("p1-robots-follow-1", "curl", (c) => (c.robotsDisallowed?.[0]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p1-robots-follow-1", baseUrl + c.robotsDisallowed[0]]
      : null), null, {
      desc: "Sigue la 1ª ruta Disallow de robots.txt",
      skipIf: (c) => !c.robotsDisallowed?.[0],
    }),
    step("p1-robots-follow-2", "curl", (c) => (c.robotsDisallowed?.[1]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p1-robots-follow-2", baseUrl + c.robotsDisallowed[1]]
      : null), null, {
      desc: "Sigue la 2ª ruta Disallow de robots.txt",
      skipIf: (c) => !c.robotsDisallowed?.[1],
    }),
    step("p1-osint-curl-sitemap", "curl", ["-s", "--max-time", "15", `${baseUrl}/sitemap.xml`], null, {
      desc: "sitemap.xml",
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-osint-curl-security-txt", "curl", ["-s", "--max-time", "15", `${baseUrl}/security.txt`], null, {
      desc: "security.txt en raíz",
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-osint-curl-wellknown-security", "curl", ["-s", "--max-time", "15", `${baseUrl}/.well-known/security.txt`], null, {
      desc: "security.txt en .well-known",
      skipIf: (c) => !c.hasWebStack,
    }),
    ...genericExposureCurlSteps(step, "p1-exposure", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...apiSurfaceCurlSteps(step, "p1-api", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...sqliLoginProbeSteps(step, "p1-sqli-login", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...nosqliLoginProbeSteps(step, "p1-nosqli-login", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...xssReflectionCurlSteps(step, "p1-xss", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...openRedirectCurlSteps(step, "p1-redirect", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...idorCurlSteps(step, "p1-idor", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...jsBundleCurlSteps(step, "p1-jssecrets", baseUrl, "12").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    ...ssrfImdsCurlSteps(step, "p1-ssrf-imds", baseUrl, "10").map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    // El JWT solo se conoce tras correr las sondas de login SQLi/NoSQLi de
    // más arriba: args es función evaluada contra el contexto ya
    // actualizado (mismo patrón que robots-follow/brute-follow).
    ...JWT_ALGNONE_PROBE_PATHS.map((path, i) =>
      step(`p1-jwt-algnone-${i + 1}`, "curl", (c) => {
        const forged = c.capturedJwt ? forgeAlgNoneToken(c.capturedJwt) : null;
        return forged
          ? ["-s", "-L", "--max-time", "12", "-H", `Authorization: Bearer ${forged}`, "-w", "\nDS_HTTP:%{http_code}\n", baseUrl + path]
          : null;
      }, null, {
        desc: `JWT alg=none forjado contra ${path}`,
        skipIf: (c) => !c.capturedJwt,
      }),
    ),
    step("p1-s3-bucket-check", "curl", (c) => (c.s3BucketHost
      ? ["-s", "-L", "--max-time", "12", `https://${c.s3BucketHost}/`]
      : null), null, {
      desc: "Bucket S3 referenciado por la app: ¿listado público?",
      skipIf: (c) => !c.s3BucketHost,
    }),
    step("p1-azureblob-check", "curl", (c) => (c.azureBlobContainer?.container
      ? ["-s", "-L", "--max-time", "12", `https://${c.azureBlobContainer.account}.blob.core.windows.net/${c.azureBlobContainer.container}?restype=container&comp=list`]
      : null), null, {
      desc: "Contenedor Azure Blob referenciado por la app: ¿listado público?",
      skipIf: (c) => !c.azureBlobContainer?.container,
    }),
    step("p1-gcs-bucket-check", "curl", (c) => (c.gcsBucketName
      ? ["-s", "-L", "--max-time", "12", `https://storage.googleapis.com/storage/v1/b/${c.gcsBucketName}/o`]
      : null), null, {
      desc: "Bucket GCS referenciado por la app: ¿listado público?",
      skipIf: (c) => !c.gcsBucketName,
    }),
    step("p1-osint-ripe-whois", "curl", (c) => (c.extractedAsn
      ? ["-s", "--max-time", "15", `https://stat.ripe.net/data/whois/data.json?resource=AS${c.extractedAsn}`]
      : null), null, {
      desc: "RIPEstat whois del ASN (titular / hyperscaler guard)",
      skipIf: (c) => !c.extractedAsn,
    }),
    step("p1-osint-ripe-prefixes", "curl", (c) => (c.extractedAsn && !c.asnIsHyperscaler
      ? ["-s", "--max-time", "15", `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${c.extractedAsn}`]
      : null), null, {
      desc: "Prefijos anunciados por el ASN (solo si no es hyperscaler/CDN)",
      skipIf: (c) => !c.extractedAsn || c.asnIsHyperscaler,
    }),
    ...[1, 2, 3, 4, 5].map((i) =>
      step(`p1-secretval-${i}`, "curl", (c) => {
        const hit = (c.capturedSecrets || [])[i - 1];
        if (!hit) return null;
        const built = secretValidateCurlSteps(step, [hit])[0];
        return built ? built.args : null;
      }, null, {
        desc: `Validador read-only de credencial #${i} hallada en el activo`,
        skipIf: (c) => !(c.capturedSecrets || [])[i - 1],
      }),
    ),
    step("p1-curl-cors-probe", "curl", [
      "-s", "-I", "--max-time", "12", "-H", `Origin: ${CORS_PROBE_ORIGIN}`, baseUrl,
    ], null, {
      desc: "Sonda CORS: Origin de prueba no confiable para detectar reflejo/comodín",
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-curl-trace-probe", "curl", ["-s", "-i", "-X", "TRACE", "--max-time", "10", baseUrl], null, {
      desc: "Sonda método HTTP TRACE (posible Cross-Site Tracing)",
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-nmap-scripts", "nmap", ["-sC", "-p", portSpec(target), host], null, {
      desc: "Scripts NSE por defecto",
    }),
    step("p1-curl-login-get", "curl", ["-s", "-I", baseUrl + "/login.php"], null, {
      skipIf: (c) => !needsAuthProbe(c),
    }),
    step("p1-curl-login-body", "curl", ["-s", baseUrl + "/login.php"], null, {
      skipIf: (c) => !needsAuthProbe(c),
    }),
    step("p1-curl-setup", "curl", ["-s", "-I", baseUrl + "/setup.php"], null, {
      skipIf: (c) => !c.isDvwa,
    }),
    step("p1-curl-config", "curl", ["-s", "-L", "--max-time", "12", "-w", "\nDS_HTTP:%{http_code}\n", baseUrl + "/config.inc.php"], null, {
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-curl-phpinfo", "curl", ["-s", "-L", "--max-time", "12", "-w", "\nDS_HTTP:%{http_code}\n", baseUrl + "/phpinfo.php"], null, {
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p1-login-post", "curl", [
      "-s", "-c", cookie, "-b", cookie,
      "-X", "POST",
      "-d", "username=admin&password=password&Login=Login",
      "-o", "/dev/null", "-w", "%{http_code}",
      baseUrl + "/login.php",
    ], null, {
      skipIf: (c) => !needsAuthProbe(c),
    }),
    step("p1-curl-vulns-index", "curl", ["-s", "-L", "-b", cookie, baseUrl + "/vulnerabilities/"], null, {
      skipIf: (c) => !c.isDvwa,
    }),
    step("p1-curl-phpinfo-auth", "curl", [
      "-s", "-L", "--max-time", "12", "-b", cookie, "-w", "\nDS_HTTP:%{http_code}\n",
      baseUrl + "/phpinfo.php",
    ], null, {
      skipIf: (c) => !needsAuthProbe(c),
      desc: "phpinfo.php autenticado",
    }),
    step("p1-curl-index-auth", "curl", ["-s", "-L", "-b", cookie, baseUrl + "/index.php"], null, {
      skipIf: (c) => !needsAuthProbe(c),
    }),
    step("p1-curl-security-cookie", "curl", ["-s", "-I", "-b", cookie, baseUrl + "/index.php"], null, {
      skipIf: (c) => !needsAuthProbe(c),
    }),
    // Caja gris: reglas reales del host donde corre el motor. Solo loopback
    // — contra un target remoto esto leería iptables de Kali, no del cliente.
    step("p1-host-ufw", "ufw", ["status", "verbose"], null, {
      desc: "Host firewall: ufw status (solo si el target es este equipo)",
      skipIf: () => !isLoopbackHost(host),
    }),
    step("p1-host-iptables", "iptables", ["-L", "-n", "-v"], null, {
      desc: "Host firewall: iptables -L (requiere privilegios)",
      skipIf: () => !isLoopbackHost(host),
    }),
    step("p1-host-nft", "nft", ["list", "ruleset"], null, {
      desc: "Host firewall: nft list ruleset (requiere privilegios)",
      skipIf: () => !isLoopbackHost(host),
    }),
  ];

  const sslPort = ports.includes("443") ? "443" : ports.includes("8443") ? "8443" : null;
  if (sslPort && !ipTarget) {
    steps.push(step("p1-osint-nmap-ssl-cert", "nmap", ["--script", "ssl-cert", "-p", sslPort, host], null, {
      desc: "Certificado TLS vía nmap ssl-cert",
    }));
    steps.push(step("p1-testssl", "testssl.sh", testsslArgs(host, sslPort), null, {
      desc: `Protocolos/ciphers/vulnerabilidades TLS conocidas (testssl.sh, puerto ${sslPort})`,
    }));
  }

  return steps;
}

function phase2Steps(baseUrl, host, target, cookie, ctx) {
  // Solo se omiten en DVWA (ya cubierto por sondas de módulo específicas).
  // Antes también se omitían para CUALQUIER target por IP (isIpTarget),
  // lo que dejaba sin brute-force de directorios/nikto a cualquier app de
  // laboratorio que no fuera DVWA (p. ej. Juice Shop en 127.0.0.1:3000):
  // ese fuerza-bruta es precisamente lo que descubre /ftp/, /rest/, /api/.
  const skipHeavy = (c) => c.isDvwa;
  const steps = [];

  if (ctx.isDvwa) {
    steps.push(
      step("p2-curl-vulns-index", "curl", ["-s", "-L", "--max-time", "20", "-b", cookie, baseUrl + "/vulnerabilities/"], null, {
        desc: "Índice de módulos DVWA tras sesión",
      }),
      step("p2-dvwa-security", "curl", ["-s", "-L", "--max-time", "20", "-b", cookie, baseUrl + "/security.php"], null, {
        desc: "Nivel de seguridad DVWA",
      }),
      ...dvwaModuleCurlSteps(step, "p2-dvwa", baseUrl, cookie, "15"),
      ...DVWA_EXTRA_PROBES.map((p) =>
        step(
          "p2-curl-" + p.stepId,
          "curl",
          ["-s", "-L", "--max-time", "15", "-H", "X-DS-Playbook: p2-curl-" + p.stepId, baseUrl + p.path],
          null,
          { desc: p.desc },
        ),
      ),
    );
  }

  steps.push(
    step("p2-nmap-vuln", "nmap", ["--script", "vuln", "-p", portSpec(target), host], null, {
      desc: "Scripts NSE de vulnerabilidades conocidas contra puertos del target",
    }),
    step("p2-nikto", "nikto", ["-h", baseUrl, "-maxtime", "120"], null, {
      desc: "Nikto (máx. 2 min en labs)",
      skipIf: skipHeavy,
    }),
    step("p2-nuclei", "nuclei", nucleiCurlArgs(baseUrl, nucleiTagsForContext(ctx)), null, {
      desc: `Nuclei (tags: ${nucleiTagsForContext(ctx).join(",")})`,
    }),
    // Sin -n: gobuster imprime "(Status: nnn)"; ffuf -s imprime la URL;
    // ferox -q imprime "200 GET … url". extractBruteDiscoveredPaths une los tres.
    step("p2-gobuster-dir", "gobuster", ["dir", "-u", baseUrl, "-w", WL.common, "-q", "-e", "--timeout", "10s"], null, {
      skipIf: skipHeavy,
    }),
    step("p2-gobuster-dir-small", "gobuster", ["dir", "-u", baseUrl, "-w", WL.dirb, "-q"], null, {
      skipIf: skipHeavy,
    }),
    step("p2-ffuf-dirs", "ffuf", [
      "-u", baseUrl + "/FUZZ", "-w", WL.small,
      "-mc", "200,301,302,403", "-fs", "0", "-s", "-maxtime", "60",
    ], null, { skipIf: skipHeavy }),
    step("p2-ffuf-common", "ffuf", [
      "-u", baseUrl + "/FUZZ", "-w", WL.common,
      "-mc", "200,301,302,403", "-fs", "0", "-s", "-maxtime", "60",
    ], null, { skipIf: skipHeavy }),
    step("p2-feroxbuster", "feroxbuster", ["-u", baseUrl, "-w", WL.common, "-q", "--no-state", "-t", "10", "--timeout", "10"], null, {
      skipIf: skipHeavy,
    }),
    // Sigue hasta 3 rutas que gobuster/ffuf/ferox confirmaron de verdad.
    step("p2-brute-follow-1", "curl", (c) => (c.bruteDiscovered?.[0]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-1", baseUrl + c.bruteDiscovered[0]]
      : null), null, {
      desc: "Sigue el 1er path real de enumeración (gobuster/ffuf/ferox)",
      skipIf: (c) => !c.bruteDiscovered?.[0],
    }),
    step("p2-brute-follow-2", "curl", (c) => (c.bruteDiscovered?.[1]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-2", baseUrl + c.bruteDiscovered[1]]
      : null), null, {
      desc: "Sigue el 2º path real de enumeración (gobuster/ffuf/ferox)",
      skipIf: (c) => !c.bruteDiscovered?.[1],
    }),
    step("p2-brute-follow-3", "curl", (c) => (c.bruteDiscovered?.[2]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-3", baseUrl + c.bruteDiscovered[2]]
      : null), null, {
      desc: "Sigue el 3er path real de enumeración (gobuster/ffuf/ferox)",
      skipIf: (c) => !c.bruteDiscovered?.[2],
    }),
    ...[1, 2, 3].map((i) =>
      step(`p2-codeguided-${i}`, "curl", (c) => {
        const hit = (c.dangerousCodeHits || [])[i - 1];
        if (!hit) return null;
        const built = codeDangerProbeSteps(step, [hit], baseUrl)[0];
        return built ? built.args : null;
      }, null, {
        desc: `Sonda dirigida por código fuente filtrado #${i}`,
        skipIf: (c) => !(c.dangerousCodeHits || [])[i - 1],
      }),
    ),
  );

  if (ctx.isWordpress) {
    steps.push(
      step("p2-wpscan-update", "wpscan", ["--update"], () => ctx.isWordpress),
      step("p2-wpscan", "wpscan", ["--url", baseUrl, "--enumerate", "p,t,u", "--disable-tls-checks"], () => ctx.isWordpress),
      step("p2-wpscan-plugins", "wpscan", ["--url", baseUrl, "--enumerate", "ap", "--plugins-detection", "aggressive"], () => ctx.isWordpress),
    );
  }
  return steps;
}

function phase3Steps(baseUrl, cookie, ctx) {
  const needsAuth = (c) => c.isDvwa || c.hasLogin;
  const steps = [
    // hydra vive en PHASE_TOOLS[3] del lado del bridge (exploitation): un
    // login por defecto encontrado aquí ya no es "recon", es una cuenta
    // tomada de verdad. Diccionario curado (17 usuarios × 25 contraseñas),
    // no una fuerza bruta con rockyou.txt — corta al primer hit (-f).
    ...hydraDefCredsSteps(step, "p3-hydra-defcreds", baseUrl).map((s) => ({
      ...s,
      skipIf: (c) => !c.hasWebStack,
    })),
    // sqlmap descubre y prueba sus propios formularios (--forms --crawl):
    // más fiable que intentar capturar el formulario a mano en el motor.
    // level=1/risk=1 son los valores más conservadores de la herramienta.
    step("p3-sqlmap-forms", "sqlmap", sqlmapCurlArgs(baseUrl), null, {
      desc: "sqlmap --forms --crawl (descubrimiento + explotación de inyección SQL)",
      skipIf: (c) => !c.hasWebStack,
    }),
    step("p3-curl-config-bak", "curl", ["-s", "-L", "--max-time", "15", "-H", "X-DS-Playbook: p3-curl-config-bak", baseUrl + "/config/config.inc.php.bak"], null, {
      desc: "Contenido de config.inc.php.bak",
      skipIf: (c) => !c.hasWebStack && !c.isDvwa,
    }),
    step("p3-curl-phpini-body", "curl", ["-s", "-L", "--max-time", "15", baseUrl + "/php.ini"], null, {
      desc: "Contenido de php.ini expuesto",
      skipIf: (c) => !c.hasWebStack && !c.isDvwa,
    }),
    ...dvwaModuleCurlSteps(step, "p3-dvwa", baseUrl, cookie, "20").map((s) => ({
      ...s,
      skipIf: (c) => !needsAuth(c),
    })),
    step("p3-dvwa-setup", "curl", ["-s", "-L", "--max-time", "20", "-b", cookie, baseUrl + "/setup.php"], null, {
      skipIf: (c) => !c.isDvwa,
      desc: "setup.php autenticado ( fuga de config )",
    }),
  ];
  return steps;
}

function phase4Steps(baseUrl, cookie, ctx) {
  const needsAuth = (c) => c.isDvwa || c.hasLogin;
  return [
    step("p4-dvwa-about", "curl", ["-s", "-L", "--max-time", "15", "-b", cookie, baseUrl + "/about.php"], null, {
      skipIf: (c) => !needsAuth(c),
    }),
    step("p4-dvwa-phpinfo-auth", "curl", ["-s", "-L", "--max-time", "20", "-b", cookie, "-w", "\nDS_HTTP:%{http_code}\n", baseUrl + "/phpinfo.php"], null, {
      skipIf: (c) => !needsAuth(c),
      desc: "phpinfo autenticado",
    }),
    step("p4-dvwa-security", "curl", ["-s", "-L", "--max-time", "15", "-b", cookie, baseUrl + "/security.php"], null, {
      skipIf: (c) => !c.isDvwa,
    }),
    step("p4-curl-robots", "curl", ["-s", "--max-time", "10", baseUrl + "/robots.txt"], null, {
      skipIf: (c) => !c.hasWebStack && !c.isDvwa,
    }),
  ];
}

export function stepsForPhase(phase, target, ctx = {}) {
  const { host, baseUrl } = parseTarget(target);
  if (!host || !baseUrl) return [];

  const cookie = ctx.cookieFile || "/tmp/ds-playbook-cookies.txt";
  const enriched = { ...ctx, host, scope: ctx.scope || "" };
  let list = [];
  if (phase === 1) list = phase1Steps(baseUrl, host, target, cookie, enriched);
  else if (phase === 2) list = phase2Steps(baseUrl, host, target, cookie, enriched);
  else if (phase === 3) list = phase3Steps(baseUrl, cookie, enriched);
  else if (phase === 4) list = phase4Steps(baseUrl, cookie, enriched);

  return list.filter((s) => {
    if (typeof s.when === "function") return s.when(enriched);
    return true;
  });
}

export function allPlaybookStepIds(phase, target, ctx = {}) {
  return stepsForPhase(phase, target, ctx).map((s) => s.id);
}

export { WL, parseTarget, scopeRoot, isIpHost, isLoopbackHost, OSINT_SUB_PREFIXES };
