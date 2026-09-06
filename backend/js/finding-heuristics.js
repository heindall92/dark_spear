/**
 * Hallazgos derivados de salidas del playbook (sin LLM).
 * Evidencia = texto acumulado de herramientas (curl, whatweb, nmap, etc.).
 */

import { parseTarget, isIpHost, isLoopbackHost, scopeRoot } from "./playbook.js";
import {
  DVWA_MODULES,
  GENERIC_EXPOSURE_PROBES,
  SURFACE_SIGNALS,
  corsFinding,
  modulePathRe,
  DIRECTORY_LISTING_RE,
  API_SURFACE_PROBES,
  SQLI_LOGIN_PROBES,
  NOSQLI_LOGIN_PROBES,
  XSS_REFLECTION_PAYLOAD,
  OPEN_REDIRECT_TEST_URL,
  IDOR_PROBES,
  IDOR_DATA_MARKER_RE,
  IDOR_DENIED_RE,
  DEFAULT_CREDS_LOGIN_PROBES,
  HYDRA_SUCCESS_RE,
  securityHeaderFindings,
  crackJwtHs256Secret,
  JWT_ALGNONE_PROBE_PATHS,
  JS_BUNDLE_PROBE_PATHS,
  jsSecretFindings,
  wafFindings,
  wafw00fFindings,
  cloudProviderFindings,
  S3_LISTING_RE,
  SSRF_IMDS_PARAMS,
  SSRF_IMDS_STRONG_RE,
  SSRF_IMDS_WEAK_RE,
  perimeterFirewallFindings,
  wafTriggerFindings,
  missingWafFinding,
  dropContradictoryWafFindings,
  hostFirewallFindings,
  domainSecurityFindings,
  orgAttackSurfaceFindings,
  idpDiscoveryFindings,
  AZURE_BLOB_LISTING_RE,
  GCS_LISTING_RE,
  secretValidateFindings,
  codeDangerFinding,
  nucleiFindings,
  sqlmapFindings,
  httpxFindings,
  testsslFindings,
  niktoFindings,
  dnsreconFindings,
  wpscanFindings,
  netexecSmbFindings,
  netexecSharesFindings,
  rpcclientUsersFindings,
  enum4linuxFindings,
  smbclientNullFindings,
  ldapAnonymousFindings,
  getNpUsersFindings,
  getUserSpnsFindings,
  certipyFindFindings,
  netexecWinrmFindings,
  lookupsidFindings,
  samrdumpFindings,
  netexecUsersFindings,
  netexecGroupsFindings,
  netexecPassPolFindings,
  bloodhoundFindings,
  domainControllerFindings,
  cloudIdentityFindings,
  orgAsnSiblingFindings,
  extractAsnFromBlob,
  extractAsnHolderFromBlob,
  HYPERSCALER_HOLDER_RE,
  exposureScoreFindings,
  exposureDeltaFindings,
} from "./vuln-kb.js";

/**
 * Índice { clave -> texto de ESE paso } a partir de stepRecords (spec.id + su
 * propia salida). Las señales atadas a una ruta concreta (módulo DVWA, sonda
 * de exposición, CORS, TRACE) se confirman contra este texto en vez del blob
 * acumulado de la fase, para no dar un falso positivo si el patrón aparece
 * por casualidad en la salida de OTRA petición.
 */
function buildProbeIndex(stepRecords) {
  const idx = {};
  if (!Array.isArray(stepRecords)) return idx;
  const push = (key, text) => {
    idx[key] = idx[key] ? `${idx[key]}\n${text}` : text;
  };
  stepRecords.forEach(function (r) {
    if (!r || !r.id) return;
    const text = String(r.text || "");
    let m = /^p[1-4]-dvwa-(.+)$/.exec(r.id);
    if (m) push(`dvwa:${m[1]}`, text);
    m = /^p[1-4]-exposure-(.+)$/.exec(r.id);
    if (m) push(`exposure:${m[1]}`, text);
    m = /^p1-api-(.+)$/.exec(r.id);
    if (m) push(`api-surface:${m[1]}`, text);
    m = /^p1-sqli-login-(.+)$/.exec(r.id);
    if (m) push(`sqli-login:${m[1]}`, text);
    m = /^p1-nosqli-login-(.+)$/.exec(r.id);
    if (m) push(`nosqli-login:${m[1]}`, text);
    m = /^p1-xss-(.+)$/.exec(r.id);
    if (m) push(`xss-reflect:${m[1]}`, text);
    m = /^p1-redirect-(.+)$/.exec(r.id);
    if (m) push(`open-redirect:${m[1]}`, text);
    m = /^p1-idor-(.+)$/.exec(r.id);
    if (m) push(`idor:${m[1]}`, text);
    m = /^p3-hydra-defcreds-(.+)$/.exec(r.id);
    if (m) push(`hydra-defcreds:${m[1]}`, text);
    m = /^p1-robots-follow-(\d+)$/.exec(r.id);
    if (m) push(`robots-follow:${m[1]}`, text);
    m = /^p2-brute-follow-(\d+)$/.exec(r.id);
    if (m) push(`brute-follow:${m[1]}`, text);
    m = /^p1-jwt-algnone-(\d+)$/.exec(r.id);
    if (m) push(`jwt-algnone:${m[1]}`, text);
    m = /^p1-jssecrets-(\d+)$/.exec(r.id);
    if (m) push(`jssecrets:${m[1]}`, text);
    m = /^p1-ssrf-imds-(.+)$/.exec(r.id);
    if (m) push(`ssrf-imds:${m[1]}`, text);
    if (r.id === "p1-s3-bucket-check") push("s3-bucket", text);
    if (r.id === "p1-azureblob-check") push("azureblob", text);
    if (r.id === "p1-gcs-bucket-check") push("gcs-bucket", text);
    if (r.id === "p1-osint-wayback-cdx") push("wayback", text);
    if (r.id === "p1-osint-curl-head-root") push("head-root", text);
    if (r.id === "p1-osint-dig-txt") push("osint-txt", text);
    if (r.id === "p1-osint-dig-dmarc") push("osint-dmarc", text);
    if (r.id === "p1-osint-rdap-ip") push("osint-rdap-ip", text);
    if (r.id === "p1-osint-ripe-asn") push("osint-ripe-asn", text);
    if (r.id === "p1-osint-ripe-whois") push("osint-ripe-whois", text);
    if (r.id === "p1-osint-ripe-prefixes") push("osint-ripe-prefixes", text);
    if (r.id === "p1-osint-dig-mx") push("osint-mx", text);
    if (r.id === "p1-idp-m365-realm") push("idp-m365", text);
    if (r.id === "p1-idp-entra-oidc") push("idp-entra-oidc", text);
    if (r.id === "p1-idp-okta-wellknown") push("idp-oidc", text);
    if (r.id === "p1-idp-saml-fedmeta") push("idp-saml", text);
    if (r.id === "p1-idp-saml-wellknown") push("idp-saml-wk", text);
    m = /^p1-secretval-(\d+)$/.exec(r.id);
    if (m) push(`secretval:${m[1]}`, text);
    m = /^p2-codeguided-(\d+)$/.exec(r.id);
    if (m) push(`codeguided:${m[1]}`, text);
    if (r.id === "p1-nmap-perimeter") push("nmap-perimeter", text);
    if (r.id === "p1-waf-trigger") push("waf-trigger", text);
    if (r.id === "p1-wafw00f") push("wafw00f", text);
    if (r.id === "p2-nuclei") push("nuclei", text);
    if (r.id === "p3-sqlmap-forms") push("sqlmap-forms", text);
    if (r.id === "p1-osint-httpx") push("httpx-hosts", text);
    if (r.id === "p1-testssl") push("testssl", text);
    if (r.id === "p2-nikto") push("nikto", text);
    if (r.id === "p1-osint-dnsrecon") push("dnsrecon", text);
    if (r.id === "p2-wpscan" || r.id === "p2-wpscan-plugins") push("wpscan", text);
    if (r.id === "p1-ad-netexec-smb") push("ad-netexec", text);
    if (r.id === "p1-ad-netexec-guest-shares") push("ad-netexec-shares", text);
    if (r.id === "p1-ad-enum4linux") push("ad-enum4linux", text);
    if (r.id === "p1-ad-smbclient") push("ad-smbclient", text);
    if (r.id === "p1-ad-rpcclient-users") push("ad-rpcclient", text);
    if (r.id === "p1-ad-ldapsearch-rootdse") push("ad-ldap", text);
    if (/^p2-ad-asrep-/.test(r.id)) push("ad-asrep", text);
    if (r.id === "p2-ad-getuserspns") push("ad-spn", text);
    if (r.id === "p2-ad-certipy-find") push("ad-certipy", text);
    if (r.id === "p3-ad-netexec-winrm") push("ad-winrm", text);
    if (r.id === "p2-ad-lookupsid-null" || r.id === "p2-ad-lookupsid-auth") push("ad-lookupsid", text);
    if (r.id === "p2-ad-samrdump-null" || r.id === "p2-ad-samrdump-auth") push("ad-samrdump", text);
    if (r.id === "p2-ad-nxc-users") push("ad-nxc-users", text);
    if (r.id === "p2-ad-nxc-groups") push("ad-nxc-groups", text);
    if (r.id === "p2-ad-nxc-passpol") push("ad-nxc-passpol", text);
    if (r.id === "p2-ad-bloodhound-dconly") push("ad-bloodhound", text);
    if (r.id === "p1-host-ufw") push("host-ufw", text);
    if (r.id === "p1-host-iptables") push("host-iptables", text);
    if (r.id === "p1-host-nft") push("host-nft", text);
    m = /^p[1-4]-curl-(phpini|config-bak|config-dist)(?:-body)?$/.exec(r.id);
    if (m) push(`extra:${m[1]}`, text);
    if (r.id === "p1-curl-cors-probe") push("cors", text);
    if (r.id === "p1-curl-trace-probe") push("trace", text);
    if (r.id === "p1-login-post") push("login-post", text);
  });
  return idx;
}

/**
 * Páginas "negativas" para confirmar un módulo DVWA por su propio paso:
 * redirección a login (sesión inválida/expirada) o error 40x genérico del
 * servidor. Si el paso propio devuelve esto, NO confirma que el módulo esté
 * accesible aunque su ruta aparezca mencionada en otra parte del blob.
 */
function isDvwaNegativePage(text) {
  return (
    /<title>\s*Login\s*::/i.test(text)
    || /<title>\s*40[134]\b/i.test(text)
    || /<title>[^<]*Not Found<\/title>/i.test(text)
    || /<title>[^<]*Forbidden<\/title>/i.test(text)
  );
}

/**
 * @param {string} blob Texto acumulado de salidas
 * @param {string} asset URL/base del objetivo
 * @param {object} ctx buildPlaybookContext
 * @param {Array<{id:string,text:string}>} [stepRecords] Salida propia de cada paso del playbook
 */
export function collectHeuristicFindings(blob, asset, ctx = {}, stepRecords = []) {
  const findings = [];
  const b = String(blob || "");
  const lower = b.toLowerCase();
  const probeIdx = buildProbeIndex(stepRecords);
  // Con registro por-paso disponible, NUNCA caer al blob completo si el
  // paso propio de una sonda aún no corrió (own === undefined): las
  // heurísticas se reevalúan tras CADA paso del playbook, así que a mitad
  // de fase el blob ya contiene la respuesta de sondas que SÍ corrieron
  // antes. Si dos sondas comparten patrón (p. ej. "listado de directorio"
  // en /ftp/, /backup/, /files/…), caer al blob marca como confirmadas las
  // que todavía ni se han pedido. Solo se usa el blob completo en llamadas
  // legado sin stepRecords en absoluto (ver test "compat hacia atrás").
  const hasRecords = Array.isArray(stepRecords) && stepRecords.length > 0;
  function extraText(id) {
    return String(probeIdx[`extra:${id}`] || "").trim();
  }
  function extraHttpOk(id) {
    const text = extraText(id);
    if (!text) return false;
    if (/^\s*200\s*$/m.test(text) || /^HTTP\/1\.[01]\s+200\b/im.test(text)) return true;
    if (/EVIDENCE:.*HTTP 200/i.test(text)) return true;
    return false;
  }
  function extraHas(id, re) {
    return re.test(extraText(id));
  }

  function add(title, severity, description, remediation) {
    findings.push({
      title,
      asset: asset || "unknown",
      severity,
      description,
      remediation,
      evidence_step_ids: [],
    });
  }

  if (/dvwa|damn vulnerable web application/i.test(b)) {
    add(
      "Aplicación DVWA expuesta en el objetivo",
      "Medium",
      "Fingerprint HTTP (whatweb/curl) identificó Damn Vulnerable Web Application (DVWA). Es una aplicación deliberadamente vulnerable (SQLi, XSS, CSRF, upload, RFI). No debe existir fuera de un lab aislado: equivale a publicar un polígono de ataque contra la propia organización.",
      "No exponer DVWA fuera de laboratorio aislado. En producción, retirar la aplicación y revisar que no queden copias en el perimetro.",
    );
  }

  if (/set-cookie:[^\n]*security=low/i.test(b)) {
    add(
      "DVWA con nivel de seguridad en «low»",
      "High",
      "La cookie «security=low» confirma que los retos de DVWA están en dificultad mínima (SQLi, XSS, CSRF, upload, etc. son triviales de explotar).",
      "Subir el nivel en security.php para pruebas representativas; en entornos reales eliminar DVWA.",
    );
  }

  if (/set-cookie:[^\n]*phpsessid/i.test(b) && !/httponly/i.test(b)) {
    add(
      "Cookie PHPSESSID sin flag HttpOnly",
      "Medium",
      "La sesión PHP se emite sin HttpOnly, facilitando exfiltración del identificador de sesión mediante XSS.",
      "Activar session.cookie_httponly y Secure en producción; regenerar session ID tras autenticación.",
    );
  }

  if (/set-cookie:[^\n]*phpsessid/i.test(b) && !/;\s*secure/i.test(b) && /https:\/\//i.test(asset)) {
    add(
      "Cookie de sesión sin flag Secure en contexto HTTPS",
      "Medium",
      "PHPSESSID no incluye Secure pese a servir sobre HTTPS, permitiendo replay en canal no cifrado si hay mixed content.",
      "Marcar cookies de sesión como Secure y revisar HSTS.",
    );
  }

  const serverLine = b.match(/^server:\s*([^\r\n]+)/im);
  if (serverLine) {
    const banner = serverLine[1].trim();
    const ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(banner);
    const versioned = /\/\d+\.\d+/.test(banner)
      || /\b(?:apache|nginx|microsoft-iis|iis|litespeed|openresty|tomcat|jetty|caddy|lighttpd)[\/\s-]\d/i.test(banner);
    if (ipv4) {
      add(
        "Cabecera Server revela dirección IP",
        "Low",
        `La cabecera Server no identifica un producto: el valor es una IPv4 «${banner}». Si es RFC1918, filtra topología interna (CWE-200). No es divulgación de versión de httpd.`,
        "Emitir un banner genérico (p. ej. un token de producto sin host). No poner la IP del backend ni del origen en Server/X-Powered-By.",
      );
    } else if (versioned) {
      add(
        "Divulgación de versión en cabecera Server",
        "Low",
        `La cabecera Server revela stack y versión: «${banner}».`,
        "Reducir fingerprint (p. ej. ServerTokens Prod, ServerSignature Off en Apache).",
      );
    }
  }

  if (/EVIDENCE: setup\.php HTTP 200/i.test(b)) {
    add(
      "Página setup.php accesible (HTTP 200)",
      "High",
      "setup.php responde 200 OK; en DVWA permite crear/reinicializar la base de datos del laboratorio.",
      "Bloquear setup.php tras instalación o restringir por IP/autenticación.",
    );
  }

  if (/EVIDENCE: login\.php POST admin\/password → HTTP 302(?:\s+index\.php)?/i.test(b)
      && /index\.php/i.test(b)) {
    add(
      "Login exitoso con credenciales por defecto (admin/password)",
      "Critical",
      "El POST a login.php con admin/password devolvió HTTP 302 a index.php: se creó sesión con credenciales de fábrica (CWE-798). En DVWA es el diseño del lab; en cualquier otro activo es compromiso de cuenta. Invalidar sesiones, forzar reset y MFA.",
      "Forzar cambio de contraseña en primer acceso, deshabilitar cuentas por defecto y aplicar MFA.",
    );
  } else if (/DS_HTTP:302/.test(b) && /DS_REDIRECT:\s*\S*index\.php/i.test(b) && !/DS_REDIRECT:\s*\S*login\.php/i.test(b)) {
    add(
      "Login exitoso con credenciales por defecto (admin/password)",
      "Critical",
      "El POST a login.php con admin/password devolvió 302 a index.php, indicando autenticación válida con credenciales por defecto.",
      "Forzar cambio de contraseña en primer acceso, deshabilitar cuentas por defecto y aplicar MFA.",
    );
  }

  if (/EVIDENCE: config\.inc\.php HTTP 200/i.test(b)) {
    add(
      "Archivo config.inc.php accesible",
      "Critical",
      "config.inc.php (o /config/config.inc.php.bak) no debe servirse por HTTP. Un 200 hay que atarlo a ESA URL y a un cuerpo con secretos — no a un 200 de login.php. Si el archivo incluye credenciales de BD, es fuga de secretos (CWE-538, RGPD Art. 32): denegar .inc/.bak/.env, sacar la config del document root y rotar claves.",
      "Denegar acceso web a archivos .inc/.env; mover configuración fuera del document root.",
    );
  }

  if (/EVIDENCE: phpinfo\.php HTTP 200/i.test(b) || extraHttpOk("phpinfo")) {
    add(
      "phpinfo.php accesible",
      "High",
      "phpinfo.php solo es hallazgo si responde 200 con cuerpo de diagnóstico (versión PHP, módulos, rutas). Un 302 a login no cuenta. Facilita exploits por versión y LFI; hay que retirar phpinfo() de cualquier entorno no aislado.",
      "Eliminar phpinfo.php en producción y restringir entornos de debug.",
    );
  }

  if (/EVIDENCE:.*\/vulnerabilities\//i.test(b) || ((ctx.isDvwa || /dvwa/i.test(b)) && /vulnerabilities\//i.test(b))) {
    add(
      "Panel de módulos vulnerables accesible tras login",
      "High",
      "Tras autenticación se alcanzan rutas bajo /vulnerabilities/ (SQLi, XSS, brute-force, upload, CSRF, FI, exec, CSP, etc.). Cada módulo es un hallazgo hijo con su propia ficha.",
      "Corregir cada clase de fallo según OWASP; no desplegar código de demo en producción.",
    );
  }

  if (ctx.isDvwa || /dvwa|damn vulnerable web application/i.test(b)) {
    DVWA_MODULES.forEach(function (m) {
      const own = probeIdx[`dvwa:${m.stepId}`];
      // Con registro por-paso: confirmar contra la respuesta real de ESE
      // módulo (no vacía, no redirigida a login ni un 40x genérico). No
      // exigimos que coincida con `m.detect`: esas cadenas suelen requerir
      // provocar el error (p. ej. inyectar), no aparecen en un GET simple.
      // Sin registro (compat hacia atrás, p. ej. llamadas antiguas sin
      // stepRecords): heurística previa sobre el blob completo.
      const confirmed = hasRecords
        ? own != null && Boolean(own.trim()) && !isDvwaNegativePage(own)
        : modulePathRe(m.path).test(b);
      if (confirmed) add(m.title, m.severity, m.description, m.remediation);
    });
  }

  SURFACE_SIGNALS.forEach(function (sig) {
    const scoped = sig.scopeKey && probeIdx[sig.scopeKey] != null ? probeIdx[sig.scopeKey] : b;
    if (sig.re.test(scoped)) add(sig.title, sig.severity, sig.description, sig.remediation);
  });

  // Cabeceras y cookies de seguridad (genérico, cualquier stack): HSTS,
  // nosniff, clickjacking, CSP, flags de cookie. Solo contra la respuesta
  // real de la cabecera raíz (own), nunca contra el blob completo — de lo
  // contrario un Set-Cookie de OTRO paso confundiría el análisis de flags.
  const headText = probeIdx["head-root"];
  if (headText) {
    securityHeaderFindings(headText, asset).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    // Fingerprint pasivo de WAF/CDN y proveedor cloud: contexto de gobierno,
    // no vulnerabilidad, pero es señal real (firma en cabecera), no adivinada.
    wafFindings(headText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    cloudProviderFindings(headText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    const triggerText = probeIdx["waf-trigger"] || "";
    const wafw00fText = probeIdx["wafw00f"] || "";
    wafTriggerFindings(triggerText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    wafw00fFindings(wafw00fText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    const hostName = ctx.host || "";
    const publicDomain = Boolean(hostName) && !isIpHost(hostName) && !isLoopbackHost(hostName) && hostName.includes(".");
    missingWafFinding(headText, triggerText, publicDomain, wafw00fText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  }

  const periText = probeIdx["nmap-perimeter"];
  if (periText) {
    perimeterFirewallFindings(periText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    domainControllerFindings(periText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  }
  const nmapSvText = (stepRecords.find((r) => r && r.id === "p1-nmap-sV") || {}).text;
  if (nmapSvText && domainControllerFindings(periText || "").length === 0) {
    domainControllerFindings(nmapSvText).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  }

  if (probeIdx["host-ufw"] != null || probeIdx["host-iptables"] != null || probeIdx["host-nft"] != null) {
    hostFirewallFindings(probeIdx["host-ufw"], probeIdx["host-iptables"], probeIdx["host-nft"])
      .forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  }

  // Sondas genéricas de exposición (cualquier stack): git, .env, swagger, actuator…
  GENERIC_EXPOSURE_PROBES.forEach(function (p) {
    const own = probeIdx[`exposure:${p.stepId}`];
    const matched = hasRecords ? own != null && p.bodyRe.test(own) : p.bodyRe.test(b);
    if (matched) add(p.title, p.severity, p.description, p.remediation);
  });

  // Superficie REST/API moderna (Node/Express, SPA, microservicios):
  // directorios estáticos listables, /metrics, source maps.
  API_SURFACE_PROBES.forEach(function (p) {
    const own = probeIdx[`api-surface:${p.stepId}`];
    const matched = hasRecords ? own != null && p.bodyRe.test(own) : p.bodyRe.test(b);
    if (matched) add(p.title, p.severity, p.description, p.remediation);
  });

  // Bypass de login por SQL injection (' OR 1=1--): un login legítimo con
  // ese payload devuelve 401/error; si la app concatena SQL, se autentica
  // sin contraseña real y el servidor emite un token de sesión (JWT).
  const JWT_RE = /eyJ[\w-]+\.[\w-]+\.[\w-]+/;
  Object.keys(probeIdx)
    .filter((k) => k.startsWith("sqli-login:"))
    .forEach(function (key) {
      const text = probeIdx[key];
      if (!JWT_RE.test(text)) return;
      const stepId = key.slice("sqli-login:".length);
      const probe = SQLI_LOGIN_PROBES.find((p) => p.stepId === stepId);
      const path = probe ? probe.path : stepId;
      add(
        "Bypass de autenticación por SQL injection en login",
        "Critical",
        `El endpoint de login (${path}) devolvió un token de sesión válido (JWT) al enviar ' OR 1=1-- en el campo de usuario/email, sin contraseña correcta. La consulta de autenticación concatena la entrada en SQL en vez de parametrizarla (CWE-89), permitiendo tomar cualquier cuenta —incluida la de administrador— sin credenciales.`,
        "Usar consultas parametrizadas/ORM con bind params en la autenticación; nunca concatenar entrada de usuario en SQL; añadir rate-limiting y alertas sobre intentos de login anómalos.",
      );
    });

  // Mismo principio con operadores de MongoDB ($gt: "" siempre verdadero)
  // en vez de sintaxis SQL: bypass de auth si el backend usa Mongo/Mongoose
  // y pasa el objeto del body directo al filtro sin sanear.
  Object.keys(probeIdx)
    .filter((k) => k.startsWith("nosqli-login:"))
    .forEach(function (key) {
      const text = probeIdx[key];
      if (!JWT_RE.test(text)) return;
      const stepId = key.slice("nosqli-login:".length);
      const probe = NOSQLI_LOGIN_PROBES.find((p) => p.stepId === stepId);
      const path = probe ? probe.path : stepId;
      add(
        "Bypass de autenticación por NoSQL injection en login",
        "Critical",
        `El endpoint de login (${path}) devolvió un token de sesión válido (JWT) al enviar el operador MongoDB {"$gt":""} en usuario/contraseña, sin credenciales reales. El backend pasa el objeto de entrada directo al filtro de Mongo/Mongoose sin sanear (CWE-943), y $gt:"" es siempre verdadero contra cualquier valor no vacío, autenticando como el primer usuario que la consulta encuentre.`,
        "Sanear/tipar la entrada antes de pasarla al driver de Mongo (rechazar objetos donde se espera un string); usar un ODM que valide el esquema; nunca reenviar req.body directo a un filtro de base de datos.",
      );
    });

  // XSS reflejado genérico: el marcador vuelve SIN escapar en el cuerpo de
  // la respuesta a su propio parámetro. La explotabilidad exacta (contexto
  // HTML/JS, CSP, WAF) requiere confirmación manual — esto detecta la señal
  // de interpolación sin sanitizar, que es lo automatizable.
  Object.keys(probeIdx)
    .filter((k) => k.startsWith("xss-reflect:"))
    .forEach(function (key) {
      const text = probeIdx[key];
      if (!text || !text.includes(XSS_REFLECTION_PAYLOAD)) return;
      const param = key.slice("xss-reflect:".length);
      add(
        `XSS reflejado en el parámetro ?${param}=`,
        "Medium",
        `El valor enviado en ?${param}= (marcador con caracteres de ruptura HTML) vuelve sin escapar en el cuerpo de la respuesta (CWE-79): la aplicación interpola esta entrada en el HTML sin sanitizar. Confirmar manualmente el contexto exacto (¿dentro de una etiqueta, de un atributo, de un bloque <script>?) para valorar la explotabilidad real y si hay CSP que lo mitigue.`,
        "Codificar la salida según el contexto (HTML entity-encoding, JS string-escaping); aplicar una Content-Security-Policy restrictiva como defensa en profundidad.",
      );
    });

  // Open redirect genérico: Location apunta a la URL externa de prueba sin
  // validar contra una allow-list.
  Object.keys(probeIdx)
    .filter((k) => k.startsWith("open-redirect:"))
    .forEach(function (key) {
      const text = probeIdx[key];
      if (!text) return;
      const locMatch = text.match(/location:\s*([^\r\n]+)/i);
      if (!locMatch || !locMatch[1].trim().startsWith(OPEN_REDIRECT_TEST_URL)) return;
      const tag = key.slice("open-redirect:".length); // "<root|redirect>-<param>"
      const dashIdx = tag.indexOf("-");
      const pathTag = dashIdx >= 0 ? tag.slice(0, dashIdx) : tag;
      const param = dashIdx >= 0 ? tag.slice(dashIdx + 1) : tag;
      const path = pathTag === "root" ? "/" : `/${pathTag}`;
      add(
        `Open redirect en ${path}?${param}=`,
        "Medium",
        `El servidor respondió con Location: ${locMatch[1].trim()} al enviar una URL externa de prueba en ${path}?${param}= (CWE-601): el destino de la redirección no se valida contra una allow-list de orígenes propios, permitiendo blanquear enlaces de phishing con el dominio de confianza de esta aplicación.`,
        "Validar el destino de la redirección contra una allow-list de rutas/orígenes propios; no redirigir a una URL completa controlada por el usuario.",
      );
    });

  // IDOR genérico: recurso por ID accesible SIN NINGUNA sesión, con datos
  // de aspecto real en la respuesta (no un 401/403/404 ni el fallback SPA).
  IDOR_PROBES.forEach(function (p) {
    const text = probeIdx[`idor:${p.stepId}`];
    if (!text) return;
    const is200 = /DS_HTTP:200\b/.test(text);
    const hasData = IDOR_DATA_MARKER_RE.test(text);
    const denied = IDOR_DENIED_RE.test(text);
    if (is200 && hasData && !denied) {
      add(
        `Objeto accedido sin autenticación (posible IDOR): ${p.path}`,
        "High",
        `GET ${p.path} sin cookie ni token de sesión devolvió HTTP 200 con datos de aspecto real (campos tipo email/username/precio/productos) en vez de un 401/403 (CWE-639). El endpoint no verifica que exista una sesión válida antes de servir el objeto por ID — a falta de más pruebas no se confirma IDOR horizontal (otro usuario autenticado accediendo al ID de otro), pero sí que NINGUNA autenticación es necesaria, que es peor.`,
        "Exigir sesión válida en todo endpoint que devuelva datos por ID; además, verificar que el ID pertenezca al usuario autenticado (no solo que exista sesión) antes de responder.",
      );
    }
  });

  // Credenciales por defecto (diccionario curado vía hydra) contra los
  // mismos endpoints de login REST/JSON conocidos — fase 3 (exploitation).
  Object.keys(probeIdx)
    .filter((k) => k.startsWith("hydra-defcreds:"))
    .forEach(function (key) {
      const text = probeIdx[key];
      const m = HYDRA_SUCCESS_RE.exec(text || "");
      if (!m) return;
      const stepId = key.slice("hydra-defcreds:".length);
      const probe = DEFAULT_CREDS_LOGIN_PROBES.find((p) => p.stepId === stepId);
      const path = probe ? probe.path : stepId;
      add(
        `Credenciales por defecto en ${path} (${m[1]} / ${m[2]})`,
        "Critical",
        `Un diccionario curado de usuarios y contraseñas habituales (no una lista de fábrica exhaustiva) encontró una combinación válida contra ${path}: usuario «${m[1]}», contraseña «${m[2]}» (CWE-798, CWE-521). La cuenta nunca cambió una contraseña trivial de adivinar.`,
        "Rotar esta contraseña de inmediato; forzar contraseñas fuertes y cambio obligatorio en primer acceso; añadir rate-limiting/lockout y alertas sobre intentos de login anómalos.",
      );
    });

  // robots.txt no es control de acceso: si Disallow delata una ruta y esa
  // ruta responde sin protección real, es un hallazgo por sí mismo.
  (ctx.robotsDisallowed || []).forEach(function (path, i) {
    const text = probeIdx[`robots-follow:${i + 1}`];
    if (!text) return;
    if (DIRECTORY_LISTING_RE.test(text)) {
      add(
        `Ruta oculta en robots.txt (${path}) expone un listado de directorio`,
        "High",
        `robots.txt intenta ocultar «${path}» con Disallow, pero la ruta responde con un listado de directorio real (autoindex), exponiendo los nombres de archivo internos sin autenticación (CWE-548, CWE-200). Disallow es una convención para crawlers educados, no un control de acceso.`,
        "Desactivar el listado de directorios en el servidor web; retirar del document root cualquier archivo que no deba ser público; no depender de robots.txt para ocultar rutas sensibles.",
      );
    } else if (!/^\s*(404|not found)\b/i.test(text) && text.trim().length > 20) {
      add(
        `Ruta oculta en robots.txt (${path}) responde sin control de acceso real`,
        "Medium",
        `robots.txt declara Disallow para «${path}», pero la ruta responde con contenido (HTTP 200) sin exigir autenticación (CWE-200). Disallow es una convención para crawlers, no un control de seguridad.`,
        "Proteger la ruta con autenticación/autorización si contiene datos sensibles, o retirarla de producción; no depender de robots.txt.",
      );
    }
  });

  // Rutas que gobuster confirmó de verdad en fase 2 (no una lista fija de
  // adivinanzas): mismo chequeo de listado de directorio que robots-follow,
  // pero sobre un hallazgo real de fuerza bruta.
  (ctx.bruteDiscovered || []).forEach(function (path, i) {
    const text = probeIdx[`brute-follow:${i + 1}`];
    if (!text) return;
    if (DIRECTORY_LISTING_RE.test(text)) {
      add(
        `Directorio ${path}/ listable sin autenticación (hallado por fuerza bruta)`,
        "High",
        `La enumeración (gobuster/ffuf/ferox) encontró «${path}» y GET ${path}/ devuelve un listado de directorio real (autoindex/serve-index), exponiendo nombres de archivo internos sin autenticación (CWE-548, CWE-200).`,
        "Desactivar el listado de directorios en el servidor web; retirar del document root cualquier archivo que no deba ser público.",
      );
    }
  });

  // JWT: crackeo offline de secreto débil (HS256) contra el diccionario
  // curado — cómputo local sobre el primer JWT capturado, sin red.
  if (ctx.capturedJwt) {
    const weakSecret = crackJwtHs256Secret(ctx.capturedJwt);
    if (weakSecret) {
      add(
        "Secreto JWT débil/adivinable (HS256)",
        "Critical",
        `El token JWT capturado durante el playbook está firmado con HS256 usando un secreto presente en un diccionario curado de valores habituales (defaults de librería, ejemplos de documentación) — no un dump de contraseñas filtradas (CWE-798, CWE-347). Con el secreto en mano, cualquiera puede firmar tokens arbitrarios (incluido rol/usuario admin) sin conocer ninguna contraseña.`,
        "Generar un secreto HS256 aleatorio de al menos 256 bits (o migrar a RS256/ES256 con clave asimétrica); rotarlo invalida todos los tokens ya emitidos.",
      );
    }
  }

  // JWT: bypass alg=none — el mismo JWT reforjado sin firma, contra
  // endpoints típicamente autenticados. HTTP 2xx en vez de 401/403 confirma
  // que el backend no verifica el algoritmo antes de confiar en el token.
  JWT_ALGNONE_PROBE_PATHS.forEach(function (path, i) {
    const text = probeIdx[`jwt-algnone:${i + 1}`];
    if (!text) return;
    if (/DS_HTTP:20\d\b/.test(text) && !/DS_HTTP:(401|403|404)\b/.test(text)) {
      add(
        `Bypass de autorización con JWT alg=none en ${path}`,
        "Critical",
        `Al reforjar el JWT capturado con header {"alg":"none"} y firma vacía, ${path} respondió HTTP 2xx en vez de 401/403 (CWE-347): el backend no verifica el algoritmo de firma antes de confiar en los claims del token, aceptando un token sin firmar con los mismos datos (rol, usuario) que el original.`,
        "Verificar siempre el algoritmo de firma en servidor con una allow-list explícita (nunca leerlo del propio token); rechazar alg=none de forma explícita; actualizar la librería JWT.",
      );
    }
  });

  // Código fuente: secretos hardcodeados en bundles JS ya servidos.
  JS_BUNDLE_PROBE_PATHS.forEach(function (path, i) {
    const text = probeIdx[`jssecrets:${i + 1}`];
    if (!text || !/DS_HTTP:200\b/.test(text)) return;
    jsSecretFindings(text, path).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  });

  // Identidad cloud observada (AKIA→account ID offline, ARNs, tenant Azure).
  cloudIdentityFindings(b).forEach((f) => add(f.title, f.severity, f.description, f.remediation));

  // Validadores read-only: GET de identidad tras confirmar el secreto.
  const captured = ctx.capturedSecrets || [];
  captured.forEach(function (hit, i) {
    const text = probeIdx[`secretval:${i + 1}`];
    if (!text) return;
    secretValidateFindings(text, hit.kind, hit.label).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  });

  // Sondas dirigidas por código fuente/config filtrado: confirma (o
  // descarta) cada hit contra la respuesta real de su sonda p2-codeguided-N.
  const dangerousCodeHits = ctx.dangerousCodeHits || [];
  dangerousCodeHits.forEach(function (hit, i) {
    const text = probeIdx[`codeguided:${i + 1}`];
    if (!text) return;
    codeDangerFinding(text, hit).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  });

  // Nuclei: cada línea -jsonl ya viene confirmada por el propio template.
  const nucleiText = probeIdx["nuclei"];
  if (nucleiText) {
    nucleiFindings(nucleiText).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  // sqlmap: descubrimiento + explotación propios (--forms --crawl).
  const sqlmapText = probeIdx["sqlmap-forms"];
  if (sqlmapText) {
    sqlmapFindings(sqlmapText).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  // httpx sobre subdominios de subfinder: inventario consolidado (1 finding).
  const httpxText = probeIdx["httpx-hosts"];
  if (httpxText) {
    httpxFindings(httpxText, scopeRoot(ctx.host || "", ctx.scope)).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  // testssl.sh: protocolos obsoletos + vulnerabilidades TLS confirmadas.
  const testsslText = probeIdx["testssl"];
  if (testsslText) {
    testsslFindings(testsslText, ctx.host || asset).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  const niktoText = probeIdx["nikto"];
  if (niktoText) {
    niktoFindings(niktoText).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  const dnsreconText = probeIdx["dnsrecon"];
  if (dnsreconText) {
    dnsreconFindings(dnsreconText, scopeRoot(ctx.host || "", ctx.scope)).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  const wpscanText = probeIdx["wpscan"];
  if (wpscanText) {
    wpscanFindings(wpscanText).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  const adNetexec = probeIdx["ad-netexec"];
  if (adNetexec) {
    netexecSmbFindings(adNetexec).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adShares = probeIdx["ad-netexec-shares"];
  if (adShares) {
    netexecSharesFindings(adShares).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adEnum = probeIdx["ad-enum4linux"];
  if (adEnum) {
    enum4linuxFindings(adEnum).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adSmb = probeIdx["ad-smbclient"];
  if (adSmb) {
    smbclientNullFindings(adSmb).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adRpc = probeIdx["ad-rpcclient"];
  if (adRpc) {
    rpcclientUsersFindings(adRpc).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adLdap = probeIdx["ad-ldap"];
  if (adLdap) {
    ldapAnonymousFindings(adLdap).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adAsrep = probeIdx["ad-asrep"];
  if (adAsrep) {
    getNpUsersFindings(adAsrep).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adSpn = probeIdx["ad-spn"];
  if (adSpn) {
    getUserSpnsFindings(adSpn).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adCertipy = probeIdx["ad-certipy"];
  if (adCertipy) {
    certipyFindFindings(adCertipy).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adWinrm = probeIdx["ad-winrm"];
  if (adWinrm) {
    netexecWinrmFindings(adWinrm).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adLookupsid = probeIdx["ad-lookupsid"];
  if (adLookupsid) {
    lookupsidFindings(adLookupsid).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adSamrdump = probeIdx["ad-samrdump"];
  if (adSamrdump) {
    samrdumpFindings(adSamrdump).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adNxcUsers = probeIdx["ad-nxc-users"];
  if (adNxcUsers) {
    netexecUsersFindings(adNxcUsers).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adNxcGroups = probeIdx["ad-nxc-groups"];
  if (adNxcGroups) {
    netexecGroupsFindings(adNxcGroups).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adNxcPasspol = probeIdx["ad-nxc-passpol"];
  if (adNxcPasspol) {
    netexecPassPolFindings(adNxcPasspol).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }
  const adBloodhound = probeIdx["ad-bloodhound"];
  if (adBloodhound) {
    bloodhoundFindings(adBloodhound).forEach((f) =>
      add(f.title, f.severity, f.description, f.remediation));
  }

  // SSRF genérico → metadata AWS (IMDS): señal fuerte (credencial IAM real
  // en la respuesta) vs. señal débil (solo el listado de categorías IMDS,
  // a confirmar a mano — podría ser un eco del parámetro sin fetch real).
  SSRF_IMDS_PARAMS.forEach(function (param) {
    const text = probeIdx[`ssrf-imds:${param}`];
    if (!text) return;
    if (SSRF_IMDS_STRONG_RE.test(text)) {
      add(
        `SSRF confirmado hacia metadata AWS vía ?${param}= (credenciales IAM filtradas)`,
        "Critical",
        `El parámetro ?${param}= hizo que el servidor solicitara por sí mismo http://169.254.169.254/latest/meta-data/iam/security-credentials/ y la respuesta refleja credenciales IAM temporales reales (AccessKeyId/SecretAccessKey) (CWE-918): un atacante puede tomar el rol IAM de la instancia sin ninguna credencial propia.`,
        "Bloquear que la app haga fetch de URLs arbitrarias del lado servidor (allow-list de hosts); forzar IMDSv2 (token con hop-limit) para que un SSRF simple no baste; revisar permisos del rol IAM (mínimo privilegio).",
      );
    } else if (SSRF_IMDS_WEAK_RE.test(text)) {
      add(
        `Posible SSRF hacia metadata AWS vía ?${param}= (confirmar manualmente)`,
        "High",
        `El parámetro ?${param}= devolvió contenido con forma de listado de categorías IMDS (ami-id/instance-id/security-credentials) al apuntarlo a 169.254.169.254 (CWE-918). No se vio una credencial completa en esta respuesta; confirmar a mano si el servidor reenvía la petición de verdad o si es solo un eco del parámetro.`,
        "Bloquear el fetch de URLs arbitrarias del lado servidor hacia rangos de metadata (169.254.169.254, fd00:ec2::254); forzar IMDSv2.",
      );
    }
  });

  // Bucket S3 referenciado por la app: ¿listado público?
  const s3Text = probeIdx["s3-bucket"];
  if (s3Text && S3_LISTING_RE.test(s3Text)) {
    add(
      "Bucket S3 referenciado por la app es listable públicamente",
      "High",
      "Un bucket S3 referenciado en el código de la app responde con un listado XML (<ListBucketResult>) sin autenticación (CWE-284, CWE-200): cualquiera puede enumerar y potencialmente descargar todos los objetos del bucket.",
      "Configurar la ACL/política del bucket para bloquear listado y lectura públicos (S3 Block Public Access); servir contenido público solo vía CloudFront con OAC, nunca el bucket directo.",
    );
  }

  // Contenedor Azure Blob / bucket GCS referenciado por la app: ¿listado público?
  const azureText = probeIdx["azureblob"];
  if (azureText && AZURE_BLOB_LISTING_RE.test(azureText)) {
    add(
      "Contenedor Azure Blob referenciado por la app es listable públicamente",
      "High",
      "Un contenedor Azure Blob Storage referenciado en el código de la app responde con un listado XML (<EnumerationResults>) sin autenticación (CWE-284, CWE-200): cualquiera puede enumerar y potencialmente descargar todos los blobs del contenedor.",
      "Cambiar el nivel de acceso público del contenedor a Private en Azure Storage; servir contenido público solo vía Azure CDN/Front Door con SAS token, nunca el contenedor directo.",
    );
  }
  const gcsText = probeIdx["gcs-bucket"];
  if (gcsText && GCS_LISTING_RE.test(gcsText)) {
    add(
      "Bucket GCS referenciado por la app es listable públicamente",
      "High",
      "Un bucket de Google Cloud Storage referenciado en el código de la app responde con un listado JSON (storage#objects) sin autenticación (CWE-284, CWE-200): cualquiera puede enumerar y potencialmente descargar todos los objetos del bucket.",
      "Quitar allUsers/allAuthenticatedUsers de la IAM policy del bucket; servir contenido público solo vía Cloud CDN con firma, nunca el bucket directo.",
    );
  }

  // Email/domain security — SPF y DMARC del dominio en scope.
  {
    const root = scopeRoot(ctx.host || "", ctx.scope);
    if (root && root.includes(".") && !isIpHost(root)) {
      const txtText = probeIdx["osint-txt"];
      const dmarcText = probeIdx["osint-dmarc"];
      if (txtText !== undefined || dmarcText !== undefined) {
        domainSecurityFindings(txtText, dmarcText, root).forEach((f) =>
          add(f.title, f.severity, f.description, f.remediation));
      }
    }
  }

  // Org attack surface — ASN/organización de la IP en scope (RDAP pasivo)
  // + prefijos hermanos RIPEstat (con guardia hyperscaler).
  {
    const rdapIpText = probeIdx["osint-rdap-ip"];
    if (rdapIpText) {
      orgAttackSurfaceFindings(rdapIpText, ctx.host, ctx.host).forEach((f) =>
        add(f.title, f.severity, f.description, f.remediation));
    }
    const ripeAsnText = probeIdx["osint-ripe-asn"];
    const ripeWhois = probeIdx["osint-ripe-whois"];
    const ripePfx = probeIdx["osint-ripe-prefixes"];
    if (ripeAsnText || ripeWhois || ripePfx) {
      const asn = ctx.extractedAsn || extractAsnFromBlob(ripeAsnText || "");
      const holder = ctx.asnHolder || extractAsnHolderFromBlob(ripeWhois || "");
      const hyper = ctx.asnIsHyperscaler === true || HYPERSCALER_HOLDER_RE.test(holder);
      if (asn || ripePfx || ripeWhois) {
        orgAsnSiblingFindings(ripeWhois, ripePfx, asn, ctx.host, hyper).forEach((f) =>
          add(f.title, f.severity, f.description, f.remediation));
      }
    }
  }

  // Identity Provider recon — discovery pasivo de tenant (M365/OIDC/SAML/GWS).
  {
    const root = scopeRoot(ctx.host || "", ctx.scope);
    const m365Text = probeIdx["idp-m365"];
    const oidcCode = probeIdx["idp-oidc"];
    const entraText = probeIdx["idp-entra-oidc"];
    const mxText = probeIdx["osint-mx"];
    const samlA = probeIdx["idp-saml"];
    const samlB = probeIdx["idp-saml-wk"];
    if ((m365Text !== undefined || oidcCode !== undefined || entraText !== undefined
        || mxText !== undefined || samlA !== undefined || samlB !== undefined)
        && root && root.includes(".") && !isIpHost(root)) {
      const samlCode = (String(samlA || "").trim() === "200" || String(samlB || "").trim() === "200")
        ? "200" : (samlA || samlB || "");
      idpDiscoveryFindings(m365Text, oidcCode, root, {
        entraOidcText: entraText,
        mxText,
        samlHttpCode: samlCode,
      }).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    }
  }

  // Wayback Machine: rutas históricas con extensión/patrón sensible que ya
  // no están enlazadas pero siguen indexadas — a confirmar manualmente.
  const waybackText = probeIdx["wayback"];
  if (waybackText && waybackText.trim()) {
    const sensitiveLines = waybackText.split("\n").filter((l) => /\.(env|sql|bak|git|zip|log)\b|\/admin\b|\/backup\b/i.test(l));
    if (sensitiveLines.length) {
      add(
        `Wayback Machine indexó ${sensitiveLines.length} ruta(s) históricamente sensible(s)`,
        "Low",
        `archive.org conserva snapshots de rutas que ya no están enlazadas (p. ej. ${sensitiveLines.slice(0, 3).join(", ")}). Aunque hoy puedan devolver 404, documentan superficie histórica (backups, paneles admin, endpoints viejos) que vale la pena verificar manualmente por si sigue accesible o reaparece en un despliegue futuro.`,
        "Revisar manualmente cada ruta listada; si alguna sigue accesible, tratarla como el hallazgo que corresponda; purgar de CDN/caché lo que ya no deba existir.",
      );
    }
  }

  const corsText = probeIdx.cors != null ? probeIdx.cors : b;
  const cors = corsFinding(corsText);
  if (cors) add(cors.title, cors.severity, cors.description, cors.remediation);

  const loginOwn = String(probeIdx["login-post"] || stepRecords.find((r) => r && r.id === "p1-login-post")?.text || "");
  if (/CSRF token is incorrect/i.test(loginOwn) && !/index\.php/i.test(b)) {
    add(
      "Login DVWA rechazado por token CSRF",
      "Medium",
      "El POST de login devolvió «CSRF token is incorrect»; el playbook debe obtener user_token antes del POST.",
      "En apps reales: tokens CSRF en formularios; en pentest repetir flujo completo de login.",
    );
  }

  if (/x-powered-by:/i.test(b) && /php/i.test(b)) {
    add(
      "Divulgación de tecnología (X-Powered-By)",
      "Low",
      "La respuesta HTTP incluye X-Powered-By relacionado con PHP, facilitando fingerprint del stack.",
      "Deshabilitar expose_php y cabeceras que revelen tecnología.",
    );
  }

  if (/robots\.txt/i.test(b) && /disallow:\s*\//i.test(b)) {
    add(
      "robots.txt revela rutas sensibles",
      "Info",
      "robots.txt contiene entradas Disallow que pueden señalar directorios ocultos o administrativos.",
      "Revisar que Disallow no exponga rutas críticas; proteger con auth independientemente de robots.txt.",
    );
  }

  if (/EVIDENCE: php\.ini HTTP 200/i.test(b) || extraHttpOk("phpini") || (/php\.ini/i.test(b) && /\[PHP\]|allow_url_fopen/i.test(b))) {
    add(
      "php.ini accesible desde el document root",
      "High",
      "El servidor entrega php.ini (o un backup) por HTTP; puede filtrar directivas y rutas.",
      "Eliminar php.ini del document root y denegar el acceso a archivos de configuración.",
    );
  }

  if (/EVIDENCE: config\.inc\.php\.bak HTTP 200/i.test(b)
      || extraHttpOk("config-bak")
      || extraHas("config-bak", /\$_DVWA|db_password/i)
      || (/config\.inc\.php\.bak/i.test(b) && /\$_DVWA|db_password/i.test(b))) {
    add(
      "Backup config.inc.php.bak accesible",
      "Critical",
      "config/config.inc.php.bak responde 200; suele contener credenciales de base de datos.",
      "Borrar backups del document root y denegar acceso a /config/.",
    );
  }

  if (/EVIDENCE: config\.inc\.php\.dist HTTP 200/i.test(b) || extraHttpOk("config-dist")) {
    add(
      "Plantilla config.inc.php.dist accesible",
      "Medium",
      "El archivo de ejemplo de configuración está expuesto por HTTP.",
      "No servir .dist/.bak/.inc desde el document root.",
    );
  }

  if (/Index of \/vulnerabilities/i.test(b)) {
    add(
      "Listado de directorio en /vulnerabilities/",
      "Medium",
      "Apache Indexes está activo: se enumeran módulos (sqli, xss, upload, exec, csrf, fi, etc.) sin autenticación.",
      "Desactivar Options Indexes y exigir autenticación en rutas de laboratorio.",
    );
  }

  if (/Writable folder[\s\S]{0,80}hackable\/uploads/i.test(b) || /hackable\/uploads\/:[\s\S]{0,40}Yes/i.test(b)) {
    add(
      "Directorio de upload escribible (hackable/uploads)",
      "High",
      "setup.php confirma que www-data puede escribir en hackable/uploads.",
      "Restringir permisos de upload; validar tipo MIME y no ejecutar lo subido.",
    );
  }

  if (/MySQL username:/i.test(b) && /setup\.php|Database Setup/i.test(b)) {
    add(
      "setup.php filtra usuario y host de MySQL",
      "High",
      "La página de setup muestra usuario MySQL, host y nombre de base de datos.",
      "Proteger setup.php tras la instalación; no exponer detalles de la base de datos.",
    );
  }

  if (ctx.emitScanDelta === true) {
    exposureScoreFindings(findings).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
    exposureDeltaFindings(
      findings.map((f) => f.title),
      ctx.previousFindingTitles || [],
    ).forEach((f) => add(f.title, f.severity, f.description, f.remediation));
  }

  return dropContradictoryWafFindings(findings);
}

export function heuristicAssetFromTarget(target) {
  const { baseUrl } = parseTarget(target);
  return baseUrl || String(target || "").trim() || "unknown";
}
