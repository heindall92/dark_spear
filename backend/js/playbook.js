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
  ssrfImdsCurlSteps,
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

function scopeRoot(host, scope) {
  const fromScope = String(scope || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0];
  const fromHost = String(host || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0];
  return fromScope || fromHost;
}

function isIpHost(host) {
  const h = String(host || "").trim();
  if (!h) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(":") && !/^[a-zA-Z]/.test(h)) return true;
  return false;
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
 * Rutas que gobuster confirmó de verdad (no una lista fija de adivinanzas):
 * requiere el formato "(Status: nnn)" que gobuster imprime por línea
 * cuando no se le pasa -n, así que este patrón no puede confundirse con
 * texto de cualquier otra herramienta mezclado en el mismo blob acumulado.
 * Descarta las que ya cubre API_SURFACE_PROBES (evita hallazgo duplicado
 * por dos caminos distintos para el mismo path) y se protege contra un
 * volcado masivo (un SPA/catch-all que "encuentra" casi todo el wordlist):
 * si hay más de 25 líneas con ese formato, no es señal real, es ruido.
 */
function extractBruteDiscoveredPaths(rawBlob) {
  const seen = new Set();
  const out = [];
  for (const m of String(rawBlob || "").matchAll(/^(\/\S+)\s+\(Status:\s*\d{3}\)/gm)) {
    const p = m[1].replace(/\/+$/, "") || "/";
    if (p === "/" || API_SURFACE_PATHS.has(p) || seen.has(p)) continue;
    seen.add(p);
    out.push(p);
  }
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
    s3BucketHost: ctx.s3BucketHost || extractS3BucketHost(rawBlob),
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
    step("p1-osint-curl-head-root", "curl", ["-s", "-I", "--max-time", "15", baseUrl], null, {
      desc: "Cabeceras HTTP de la raíz",
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
  ];

  const sslPort = ports.includes("443") ? "443" : ports.includes("8443") ? "8443" : null;
  if (sslPort && !ipTarget) {
    steps.push(step("p1-osint-nmap-ssl-cert", "nmap", ["--script", "ssl-cert", "-p", sslPort, host], null, {
      desc: "Certificado TLS vía nmap ssl-cert",
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
    // Sin -n: gobuster imprime "(Status: nnn)" por línea, formato que
    // extractBruteDiscoveredPaths necesita para distinguir un hallazgo real
    // de cualquier otro texto mezclado en el blob acumulado.
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
    // Sigue hasta 3 rutas que gobuster confirmó de verdad (no una lista fija
    // de adivinanzas): igual que robots-follow en fase 1, args es función
    // porque el resultado solo se conoce tras correr gobuster en esta fase.
    step("p2-brute-follow-1", "curl", (c) => (c.bruteDiscovered?.[0]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-1", baseUrl + c.bruteDiscovered[0]]
      : null), null, {
      desc: "Sigue el 1er hallazgo real de gobuster",
      skipIf: (c) => !c.bruteDiscovered?.[0],
    }),
    step("p2-brute-follow-2", "curl", (c) => (c.bruteDiscovered?.[1]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-2", baseUrl + c.bruteDiscovered[1]]
      : null), null, {
      desc: "Sigue el 2º hallazgo real de gobuster",
      skipIf: (c) => !c.bruteDiscovered?.[1],
    }),
    step("p2-brute-follow-3", "curl", (c) => (c.bruteDiscovered?.[2]
      ? ["-s", "-L", "--max-time", "12", "-H", "X-DS-Playbook: p2-brute-follow-3", baseUrl + c.bruteDiscovered[2]]
      : null), null, {
      desc: "Sigue el 3er hallazgo real de gobuster",
      skipIf: (c) => !c.bruteDiscovered?.[2],
    }),
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

export { WL, parseTarget, scopeRoot, isIpHost, OSINT_SUB_PREFIXES };
