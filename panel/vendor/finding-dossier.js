/**
 * Dossier de informe por hallazgo: narrativa, CVSS, MITRE, RGPD, remediación y grafo.
 * Se deriva del título/severidad aunque el motor solo haya guardado un párrafo.
 */
(function (global) {
  function lang() {
    try {
      return (localStorage.getItem("ds-lang") || "es").toLowerCase() === "en" ? "en" : "es";
    } catch {
      return "es";
    }
  }

  function L(es, en) {
    return lang() === "en" ? en : es;
  }

  var CVSS = {
    critical: { score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
    high: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" },
    medium: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    low: { score: 3.1, vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    info: { score: 0.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" },
  };

  function parseCvssVector(vector) {
    var m = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" };
    String(vector || "").split("/").forEach(function (p) {
      var kv = p.split(":");
      if (kv.length === 2 && Object.prototype.hasOwnProperty.call(m, kv[0])) m[kv[0]] = kv[1];
    });
    return m;
  }

  function cvssRoundup(n) {
    var intInput = Math.round(n * 100000);
    if (intInput % 10000 === 0) return intInput / 100000;
    return (Math.floor(intInput / 10000) + 1) / 10;
  }

  function scoreCvss31(m) {
    var av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
    var ac = { L: 0.77, H: 0.44 }[m.AC];
    var prTable = m.S === "C"
      ? { N: 0.85, L: 0.68, H: 0.5 }
      : { N: 0.85, L: 0.62, H: 0.27 };
    var pr = prTable[m.PR];
    var ui = { N: 0.85, R: 0.62 }[m.UI];
    var imp = { N: 0, L: 0.22, H: 0.56 };
    var iss = 1 - (1 - (imp[m.C] || 0)) * (1 - (imp[m.I] || 0)) * (1 - (imp[m.A] || 0));
    var impact = m.S === "C"
      ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(Math.max(0, iss - 0.02), 15)
      : 6.42 * iss;
    if (impact <= 0) return 0;
    var expl = 8.22 * (av || 0.85) * (ac || 0.77) * (pr || 0.85) * (ui || 0.85);
    var raw = m.S === "C" ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10);
    return cvssRoundup(raw);
  }

  function ciaFromLetter(letter) {
    var x = String(letter || "N").toUpperCase();
    if (x === "H") return { key: "high", pct: 1, label: "HIGH" };
    if (x === "L") return { key: "low", pct: 0.22, label: "LOW" };
    return { key: "none", pct: 0, label: "NONE" };
  }

  function cvssFromVector(vector) {
    var m = parseCvssVector(vector);
    var c = ciaFromLetter(m.C);
    var i = ciaFromLetter(m.I);
    var a = ciaFromLetter(m.A);
    var avPct = { N: 1, A: 0.73, L: 0.55, P: 0.2 }[m.AV] || 0.55;
    var acPct = { L: 0.22, H: 0.85 }[m.AC] || 0.22;
    var prPct = { N: 0, L: 0.4, H: 0.85 }[m.PR] != null ? { N: 0, L: 0.4, H: 0.85 }[m.PR] : 0;
    return {
      score: scoreCvss31(m),
      vector: vector,
      metrics: m,
      av: avPct,
      ac: acPct,
      pr: prPct,
      c: c.pct,
      i: i.pct,
      a: a.pct,
      impact: {
        confidentiality: c.key,
        integrity: i.key,
        availability: a.key,
      },
    };
  }

  var SLA = { critical: 24, high: 168, medium: 720, low: 2160, info: 4320 };

  var HT = "https://hacktricks.wiki/en/pentesting-web/";

  /**
   * Gobernanza al molde del informe Aurora (Evolve 2026-08-18):
   * obligación legal / hueco / riesgo AEPD / impacto de negocio / coste / 30-60-90.
   * Techos 83.4 y 83.5 son el máximo de la norma, no una multa calculada.
   */
  var GOV = {
    data_breach: {
      category: { es: "Confidencialidad de datos / inyección", en: "Data confidentiality / injection" },
      legalBase: { es: "RGPD Art. 32 · Art. 5.1.f · Arts. 33–34 (72 h) · Art. 30 si no hay RAT que cubra el tratamiento", en: "GDPR Art. 32 · Art. 5.1.f · Arts. 33–34 (72h) · Art. 30 if RoPA is missing" },
      sanction: { art: "Art. 83.4 y, si hay datos personales, Art. 83.5", es: "Hasta 10 M€ o el 2 % (medidas Art. 32, notificación 33). Si el fallo vulnera principios del Art. 5 (confidencialidad de datos personales), techo 20 M€ o el 4 %. La AEPD puede sancionar el hueco sin ataque exitoso.", en: "Up to €10M / 2% (Art. 32, 33). If Art. 5 principles are breached, €20M / 4%." },
      iso: ["A.8.8 Vulnerabilidades técnicas", "A.8.26 Seguridad en aplicaciones", "A.8.28 Codificación segura", "A.8.12 Prevención de fugas"],
      ens: { es: "Alto — dimensión confidencialidad", en: "High — confidentiality" },
      nis2: { es: "Art. 21.2.e — seguridad en adquisición, desarrollo y mantenimiento", en: "Art. 21.2.e — secure development" },
      obligation: { es: "El responsable debe garantizar confidencialidad e integridad permanentes de los sistemas que tratan datos (Art. 32). Una inyección SQL o un backup de config en HTTP demuestra que esa medida no es demostrable.", en: "The controller must ensure ongoing confidentiality and integrity (Art. 32). SQLi or a web-readable config backup shows that measure is not demonstrable." },
      aepd: { es: "Ante un requerimiento, la AEPD pide medidas apropiadas al riesgo, RAT y capacidad de notificar en 72 h. Un SQLi o secretos en claro deja a la organización sin accountability: el incidente técnico se convierte en infracción de gobernanza, acumulable.", en: "A DPA will ask for appropriate measures, RoPA and a 72h notification clock. SQLi or plaintext secrets turn a technical incident into a governance infringement." },
      business: { operational: "Alto", reputational: "Alto", legal: "Alto", economic: "Alto" },
      costFix: { es: "Cerrar el hueco: 8–40 h de ingeniería (parametrizar, rotar secretos, test de regresión). En una pyme, cientos o pocos miles de euros — un orden de magnitud por debajo de un incidente.", en: "Fix: 8–40 engineering hours (parameterize, rotate secrets, regression). Hundreds to a few thousand euros for an SME — far below an incident." },
      costIncident: { es: "Si hay datos personales: forense, notificación AEPD 72 h, Art. 34 a afectados, parada y reputación. El techo legal es 10 M€/2 % o 20 M€/4 %; no es una factura, es el máximo de la norma. En ISO 27001 es no-conformidad mayor (A.8.8 / A.8.26) y puede bloquear certificación o renovación.", en: "Personal data in play: forensics, 72h DPA notice, Art. 34, downtime, reputation. Legal ceiling €10M/2% or €20M/4%. ISO 27001: major nonconformity on A.8.8 / A.8.26." },
      plan30: { es: "Parametrizar o retirar la superficie; rotar credenciales si hubo fuga; evidenciar 403/404 o consulta segura.", en: "Parameterize or remove the surface; rotate secrets if leaked; evidence 403/404 or a safe query." },
      plan60: { es: "Revisión de accesos a BD; WAF como capa extra; actualizar RAT si hay datos personales.", en: "Review DB access; WAF as extra layer; update RoPA if personal data is in scope." },
      plan90: { es: "Regresión en CI; IRP con reloj 72 h; evidencia para auditoría ISO/ENS.", en: "CI regression; IRP with a 72h clock; evidence for ISO/ENS audit." },
    },
    rce: {
      category: { es: "Ejecución / persistencia en el host", en: "Host execution / persistence" },
      legalBase: { es: "RGPD Art. 32 (integridad y disponibilidad del sistema) · Arts. 33–34 · NIS2 Art. 21", en: "GDPR Art. 32 · Arts. 33–34 · NIS2 Art. 21" },
      sanction: { art: "Art. 83.4 (y 83.5 si se accede a datos personales)", es: "RCE o webshell no es «solo un lab»: es compromiso del sistema que trata datos. Techo 10 M€/2 % por medidas inadecuadas; 20 M€/4 % si hay acceso a datos personales.", en: "RCE/webshell is compromise of the system processing data. €10M/2% for inadequate measures; €20M/4% if personal data is reached." },
      iso: ["A.8.26 Seguridad en aplicaciones", "A.8.28 Codificación segura", "A.8.7 Protección contra malware", "A.8.3 Restricción de acceso"],
      ens: { es: "Alto — integridad y disponibilidad", en: "High — integrity and availability" },
      nis2: { es: "Art. 21.2.c — seguridad en la cadena de suministro y en el desarrollo", en: "Art. 21.2.c — supply-chain and development security" },
      obligation: { es: "Art. 32 exige integridad permanente. Command injection, file inclusion o upload ejecutable demuestran que un tercero puede ejecutar código o persistir en el servidor.", en: "Art. 32 requires ongoing integrity. Command injection, file inclusion or executable uploads show a third party can run code or persist on the host." },
      aepd: { es: "Un host comprometido anula copias de seguridad no probadas y el reloj de 72 h: no hay garantía de qué datos salieron. Sin IRP (como en el vacío GRC Aurora) el incidente no tiene dueño.", en: "A compromised host voids untested backups and the 72h clock: you cannot prove what left. Without an IRP the incident has no owner." },
      business: { operational: "Alto", reputational: "Alto", legal: "Alto", economic: "Alto" },
      costFix: { es: "Cerrar: 4–24 h (eliminar shell-out, allow-list, directorio de upload sin ejecución). Barato frente a reconstruir un servidor y rotar todo el perímetro.", en: "Fix: 4–24 h (stop shelling out, allow-list, non-executable upload dir). Cheap versus rebuilding a host and rotating the perimeter." },
      costIncident: { es: "ERIR, posible parada, rotación masiva de secretos, comunicación a clientes. Techos RGPD anteriores. NIS2: las entidades esenciales deben notificar incidentes significativos; un RCE lo es.", en: "IR, possible outage, mass secret rotation, customer notice. Same GDPR ceilings. NIS2: a significant incident for essential entities." },
      plan30: { es: "Inventariar system/exec/include/upload; desactivar ejecución en directorios de subida; allow_url_include=Off.", en: "Inventory system/exec/include/upload; disable execution in upload dirs; allow_url_include=Off." },
      plan60: { es: "Sustituir APIs nativas; WAF; EDR en el host; prueba de restore de backup.", en: "Native APIs; WAF; host EDR; prove a backup restore." },
      plan90: { es: "IRP con árbol AEPD 72 h; simulacro; evidencias ISO A.8.7/A.8.26.", en: "IRP with a 72h DPA tree; tabletop; ISO A.8.7/A.8.26 evidence." },
    },
    session: {
      category: { es: "Sesión, XSS y falsificación de peticiones", en: "Session, XSS and request forgery" },
      legalBase: { es: "RGPD Art. 32 · Art. 25 (privacidad desde el diseño) · Art. 5.1.f", en: "GDPR Art. 32 · Art. 25 · Art. 5.1.f" },
      sanction: { art: "Art. 83.4 (medidas) / 83.5 si hay secuestro de cuentas con datos personales", es: "XSS + cookie sin HttpOnly es robo de sesión. Medidas inadecuadas: 10 M€/2 %. Si se accede a datos de interesados: 20 M€/4 %.", en: "XSS + missing HttpOnly is session theft. Inadequate measures: €10M/2%. Access to data subjects: €20M/4%." },
      iso: ["A.8.5 Autenticación segura", "A.8.24 Criptografía", "A.8.26 Seguridad en aplicaciones", "A.5.15 Control de acceso"],
      ens: { es: "Alto — autenticación y confidencialidad", en: "High — authentication and confidentiality" },
      nis2: { es: "Art. 21.2.d — control de acceso y gestión de activos", en: "Art. 21.2.d — access control" },
      obligation: { es: "La sesión es la llave del tratamiento. Art. 25 y 32 exigen HttpOnly/Secure/SameSite, encoding de salida y tokens anti-CSRF. Sin ellos, un script o una petición forjada opera en nombre del usuario.", en: "The session is the key to processing. Arts. 25 and 32 require HttpOnly/Secure/SameSite, output encoding and anti-CSRF tokens." },
      aepd: { es: "Un secuestro de sesión con datos de clientes es brecha del Art. 4.12. Hay que evaluar notificación 33/34. No tener CSP ni HttpOnly debilita la defensa de «medidas apropiadas».", en: "Session hijack with customer data is a personal-data breach (Art. 4.12). Assess 33/34 notice. Missing CSP/HttpOnly weakens the 'appropriate measures' defence." },
      business: { operational: "Medio", reputational: "Alto", legal: "Alto", economic: "Medio" },
      costFix: { es: "Cerrar: 2–16 h (flags de cookie, encoding, CSP nonce, token CSRF). Coste de ingeniería bajo; el coste está en no hacerlo.", en: "Fix: 2–16 h (cookie flags, encoding, CSP nonce, CSRF token). Low engineering cost; the cost is not doing it." },
      costIncident: { es: "Cuentas tomadas, fraude interno, phishing a clientes con sesión válida. Sanción y reputación superan de largo el parche. ISO: no-conformidad en A.8.5.", en: "Taken-over accounts, internal fraud, phishing with a valid session. Sanction and reputation dwarf the patch. ISO: nonconformity on A.8.5." },
      plan30: { es: "HttpOnly + Secure + SameSite; encoding contextual; token CSRF en POST de estado.", en: "HttpOnly + Secure + SameSite; contextual encoding; CSRF tokens on state-changing POST." },
      plan60: { es: "CSP con nonce/hash; regenerar session id al login; revisar sinks innerHTML.", en: "CSP with nonce/hash; regenerate session id on login; audit innerHTML sinks." },
      plan90: { es: "Tests automáticos de headers; revisión ENS/ISO de autenticación.", en: "Automated header tests; ENS/ISO authentication review." },
    },
    authn: {
      category: { es: "Autenticación y fuerza bruta", en: "Authentication and brute force" },
      legalBase: { es: "RGPD Art. 32.1.b (capacidad de garantizar confidencialidad) · Art. 25 · NIS2 Art. 21.2.d", en: "GDPR Art. 32.1.b · Art. 25 · NIS2 Art. 21.2.d" },
      sanction: { art: "Art. 83.4", es: "Credenciales por defecto, sin lockout o sin MFA en consolas es el hueco que la AEPD considera más barato y esperable (el informe Aurora lo marcó como «el más serio» en GRC). Techo 10 M€ o 2 %.", en: "Default credentials, no lockout or no MFA is the cheapest expected Art. 32 measure. Ceiling €10M or 2%." },
      iso: ["A.8.5 Autenticación segura", "A.5.17 Información de autenticación", "A.8.2 Identidades privilegiadas"],
      ens: { es: "Alto — autenticación", en: "High — authentication" },
      nis2: { es: "Art. 21.2.d — control de acceso a sistemas y datos", en: "Art. 21.2.d — access control to systems and data" },
      obligation: { es: "Art. 32 exige autenticación apropiada al riesgo. Cuentas de fábrica, login sin rate-limit y CAPTCHA solo en cliente no son medidas demostrables.", en: "Art. 32 requires authentication appropriate to the risk. Factory accounts, unlimited login and client-only CAPTCHA are not demonstrable measures." },
      aepd: { es: "Una sola contraseña reutilizada abre el tratamiento. Sin MFA (como F-025/F-026 en Aurora) la posición Art. 32 queda débil aunque el código de negocio esté bien.", en: "One reused password opens processing. Without MFA the Art. 32 position is weak even if business code is sound." },
      business: { operational: "Alto", reputational: "Alto", legal: "Medio", economic: "Alto" },
      costFix: { es: "Cerrar: horas, no semanas (reset de default, lockout, MFA). Es el quick win más barato del plan 30 días.", en: "Fix: hours, not weeks (reset defaults, lockout, MFA). Cheapest 30-day quick win." },
      costIncident: { es: "Compromiso de cuenta admin = el resto de hallazgos se encadenan. Coste de incidente ≈ coste de la cadena (datos, fraude, notificación), no el de este hallazgo aislado.", en: "Admin account takeover chains every other finding. Incident cost ≈ the whole chain, not this item alone." },
      plan30: { es: "Invalidar sesiones default; forzar reset; rate-limit y lockout; MFA en admin y consolas cloud.", en: "Invalidate default sessions; force reset; rate-limit and lockout; MFA on admin and cloud consoles." },
      plan60: { es: "Política de contraseñas; revisión de cuentas privilegiadas; alertas de 401/403.", en: "Password policy; privileged-account review; 401/403 alerts." },
      plan90: { es: "IdP central; evidencia MFA en el RAT; simulacro de cuenta comprometida.", en: "Central IdP; MFA evidence in RoPA; compromised-account tabletop." },
    },
    lab: {
      category: { es: "Software deliberadamente vulnerable / instalador vivo", en: "Deliberately vulnerable software / live installer" },
      legalBase: { es: "RGPD Art. 32 · Art. 25 · NIS2 Art. 21 (no operar sistemas inseguros por diseño en el perímetro de datos reales)", en: "GDPR Art. 32 · Art. 25 · NIS2 Art. 21" },
      sanction: { art: "Art. 83.4 / 83.5 según datos alcanzables", es: "Publicar DVWA o setup.php junto a datos reales es equivalente a un polígono de ataque interno. Si el lab toca datos personales, aplican los techos 83.4/83.5. En lab aislado (localhost, datos sintéticos) la sanción no corre; el hallazgo sigue siendo de gobierno: no replicar esto en producción.", en: "Shipping DVWA or a live installer next to real data is an internal firing range. Isolated lab with synthetic data: no fine, but do not copy this to production." },
      iso: ["A.8.9 Gestión de la configuración", "A.8.19 Instalación de software", "A.8.8 Vulnerabilidades técnicas"],
      ens: { es: "Alto si hay datos reales; lab si está aislado y documentado", en: "High if real data; lab if isolated and documented" },
      nis2: { es: "Art. 21 — medidas apropiadas; no exponer entornos de entrenamiento al perímetro productivo", en: "Art. 21 — do not expose training environments on the production perimeter" },
      obligation: { es: "El Art. 32 se evalúa al riesgo del tratamiento. Un laboratorio OWASP en una VLAN de producción no es «formación»: es superficie de inyección, XSS y RCE con credenciales de fábrica.", en: "Art. 32 is judged against processing risk. An OWASP lab on a production VLAN is injection/XSS/RCE surface with factory credentials." },
      aepd: { es: "Si el lab comparte red o BD con interesados, la AEPD no acepta «era un entorno de pruebas» como medida apropiada. Segmentar, datos sintéticos y no publicar el vhost.", en: "If the lab shares network or DB with data subjects, 'it was a test env' is not an appropriate measure. Segment, synthetic data, do not publish the vhost." },
      business: { operational: "Alto", reputational: "Alto", legal: "Alto", economic: "Medio" },
      costFix: { es: "Apagar el vhost o aislar el lab: minutos. El coste de dejarlo es el de todos los módulos hijos (SQLi, exec, upload).", en: "Shut the vhost or isolate the lab: minutes. Leaving it costs every child module (SQLi, exec, upload)." },
      costIncident: { es: "Cadena completa del playbook contra datos reales. Misma lógica que Aurora: un fallo técnico encuentra a la organización sin IRP ni RAT.", en: "Full playbook chain against real data. Same logic as Aurora: a technical fail meets an org with no IRP or RoPA." },
      plan30: { es: "Confirmar RFC1918/localhost; si no es lab, apagar y rotar secretos; si es lab, VLAN sin datos reales.", en: "Confirm RFC1918/localhost; if not a lab, shut down and rotate secrets; if a lab, VLAN with no real data." },
      plan60: { es: "Inventario de clones Docker/snapshots; prohibir DVWA/setup en CI de producción.", en: "Inventory Docker clones/snapshots; ban DVWA/setup from production CI." },
      plan90: { es: "Política de entornos (dev/lab/prod) en el SGSI; evidencia ENS.", en: "Env policy (dev/lab/prod) in the ISMS; ENS evidence." },
    },
    misconfig: {
      category: { es: "Configuración insegura y fingerprint", en: "Insecure configuration and fingerprint" },
      legalBase: { es: "RGPD Art. 32 · Art. 25 · ISO 27001 A.8.9", en: "GDPR Art. 32 · Art. 25 · ISO 27001 A.8.9" },
      sanction: { art: "Art. 83.4 (habitualmente)", es: "phpinfo, Indexes, CSP débil o validación solo en cliente no suelen ser el 4 % por sí solos; sí demuestran falta de endurecimiento (Art. 32) y abaratan el resto de la cadena. Techo típico 10 M€/2 % si se argumenta medida inadecuada.", en: "phpinfo, Indexes, weak CSP or client-only checks are rarely the 4% tier alone; they prove missing hardening (Art. 32) and cheapen the rest of the chain." },
      iso: ["A.8.9 Gestión de la configuración", "A.8.8 Vulnerabilidades técnicas", "A.8.27 Arquitectura de sistemas segura"],
      ens: { es: "Medio (Alto si filtra rutas o secretos)", en: "Medium (High if paths or secrets leak)" },
      nis2: { es: "Art. 21.2.a — políticas de análisis de riesgos y seguridad de sistemas", en: "Art. 21.2.a — risk-analysis and system-security policies" },
      obligation: { es: "Art. 25 y 32 exigen minimizar lo que el sistema revela y no fiarse del cliente. Un banner con versión o un php.ini descargable no es explotable solo, pero documenta que el endurecimiento no está hecho.", en: "Arts. 25 and 32 require minimising disclosure and not trusting the client. A versioned banner or a downloadable php.ini is not exploitable alone, but it documents missing hardening." },
      aepd: { es: "En inspección, estos hallazgos pintan madurez baja (en Aurora el índice quedó 2.5/10). No son el titular, son la prueba de que no hay SGSI operativo.", en: "In an inspection these findings paint low maturity (Aurora scored 2.5/10). They are not the headline; they prove the ISMS is not operational." },
      business: { operational: "Bajo", reputational: "Medio", legal: "Medio", economic: "Bajo" },
      costFix: { es: "Cerrar: 1–8 h (ServerTokens, denegar .ini, CSP, validación server-side). Quick wins del plan 30 días.", en: "Fix: 1–8 h (ServerTokens, deny .ini, CSP, server-side validation). 30-day quick wins." },
      costIncident: { es: "Por sí solo, bajo. Como eslabón (reconocimiento → módulo vulnerable), multiplica el resto. ISO: observaciones de A.8.9 que se acumulan en la auditoría.", en: "Alone, low. As a link (recon → vulnerable module), it multiplies the rest. ISO: A.8.9 observations that pile up in audit." },
      plan30: { es: "Reducir banner; denegar .ini/.bak; Indexes Off; validación en servidor.", en: "Reduce banner; deny .ini/.bak; Indexes Off; server-side validation." },
      plan60: { es: "Baseline de hardening; CSP en report-only y luego enforce.", en: "Hardening baseline; CSP report-only then enforce." },
      plan90: { es: "Escaneo de configuración periódico; evidencia A.8.9 para ISO/ENS.", en: "Periodic config scanning; A.8.9 evidence for ISO/ENS." },
    },
  };

  function inferGovKey(cat) {
    if (cat && cat.govKey) return cat.govKey;
    var cwe = ((cat && cat.cwe) || []).join(" ");
    if (/CWE-78|CWE-434|CWE-98/.test(cwe)) return "rce";
    if (/CWE-89|CWE-538|CWE-540/.test(cwe)) return "data_breach";
    if (/CWE-79|CWE-352|CWE-330|CWE-1004|CWE-614|CWE-80/.test(cwe)) return "session";
    if (/CWE-307|CWE-798|CWE-521|CWE-804|CWE-799/.test(cwe)) return "authn";
    if (/CWE-489/.test(cwe)) return "lab";
    return "misconfig";
  }

  function loc(obj) {
    if (!obj) return "";
    if (typeof obj === "string") return obj;
    return lang() === "en" ? obj.en : obj.es;
  }

  function pickGov(cat) {
    return GOV[inferGovKey(cat)] || GOV.misconfig;
  }

  function dvwaCard(c) {
    return {
      re: c.re,
      cwe: c.cwe,
      owasp: c.owasp,
      mitre: c.mitre,
      gdpr: c.gdpr || ["Art. 32 seguridad del tratamiento", "Art. 5.1.f"],
      iso: c.iso || ["A.8.8 Gestión de vulnerabilidades", "A.8.26 Seguridad en desarrollo"],
      ens: c.ens || "Alto",
      nis2: c.nis2 || "Art. 21.2.e — seguridad en desarrollo y adquisición",
      kill: c.kill || "Exploitation",
      impact: c.impact || { confidentiality: "high", integrity: "high", availability: "low" },
      narrative: c.narrative,
      exec: c.exec,
      steps: c.steps,
      refs: c.refs || [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
      cvssVector: c.cvssVector || null,
    };
  }

  var CATALOG = [
    dvwaCard({
      re: /sqli_blind|SQL Injection \(Blind\)/i,
      cwe: ["CWE-89"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      refs: [{ label: "HackTricks — SQL Injection", href: HT + "sql-injection/index.html" }],
      narrative: {
        es: "SQLi a ciegas: la aplicación interpreta entrada en SQL pero no refleja filas en la respuesta. El impacto sigue siendo lectura/escritura de BD; cambia la forma de detectar (tiempo o booleanos), no el riesgo. Superficie DVWA: /vulnerabilities/sqli_blind/. Defensa: consultas parametrizadas y cuenta de BD de mínimo privilegio. Referencia de clase: HackTricks SQL Injection (qué es y por qué importa), no un recetario de payloads.",
        en: "Blind SQLi still means user input reaches SQL. Detection differs (boolean/time); impact does not. Parameterize queries; least-privilege DB role.",
      },
      exec: {
        es: "Módulo de SQL injection a ciegas accesible. Misma clase CWE-89 que SQLi clásica. Prioridad alta: parametrizar y no exponer el lab.",
        en: "Blind SQL injection module reachable. Same CWE-89 class. Parameterize; do not expose the lab.",
      },
      steps: {
        es: ["Confirmar que el endpoint autenticado responde (no 302 a login).", "Parametrizar / stored procedures; nada de concatenar SQL.", "Rol de BD sin DROP/FILE.", "WAF como capa extra, no única."],
        en: ["Confirm the authenticated endpoint is not a login 302.", "Parameterize SQL.", "Least-privilege DB role.", "WAF as extra layer only."],
      },
    }),
    dvwaCard({
      re: /SQL Injection \(DVWA\)|vulnerabilities\/sqli(?!_)/i,
      cwe: ["CWE-89"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      refs: [{ label: "HackTricks — SQL Injection", href: HT + "sql-injection/index.html" }],
      narrative: {
        es: "Inyección SQL (HackTricks: interferir con consultas de BD para ver, modificar o borrar datos). En DVWA el módulo /vulnerabilities/sqli/ es la superficie deliberada. El dossier de lab documenta que el endpoint existe y está autenticado; en producción se exige evidencia de que la entrada altera la consulta. Impacto: datos de usuarios, bypass de login, en algunos motores lectura de ficheros. RGPD Art. 32/33 si hay datos personales.",
        en: "SQL injection (HackTricks: interfere with DB queries). DVWA /vulnerabilities/sqli/ is deliberate surface. Production needs query-level evidence.",
      },
      exec: {
        es: "Superficie SQLi en la aplicación (módulo DVWA o equivalente). Riesgo de compromiso de base de datos. Parametrizar ya.",
        en: "SQLi surface. Database compromise risk. Parameterize now.",
      },
      steps: {
        es: ["Inventariar parámetros del módulo.", "Prepared statements / ORM.", "Mínimo privilegio en MySQL.", "Regresión en CI que falle si el módulo reaparece en prod."],
        en: ["Inventory parameters.", "Prepared statements.", "Least privilege on MySQL.", "CI regression if the module reappears in prod."],
      },
    }),
    dvwaCard({
      re: /xss_s|XSS \(Stored\)|XSS almacenad/i,
      cwe: ["CWE-79"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" }, { id: "T1059.007", name: "JavaScript", tactic: "Execution" }],
      kill: "Installation",
      refs: [{ label: "HackTricks — XSS", href: HT + "xss-cross-site-scripting/index.html" }],
      narrative: {
        es: "XSS almacenado: el script persiste en servidor y se sirve a otras sesiones (HackTricks: stored XSS). En DVWA, /vulnerabilities/xss_s/. Encadena con cookies sin HttpOnly (robo de sesión). Defensa: encoding contextual, CSP, sanitizar al guardar y al pintar.",
        en: "Stored XSS persists on the server and hits other sessions. Chain with missing HttpOnly. Encode, CSP, sanitize on store and render.",
      },
      exec: {
        es: "XSS persistente accesible. Un visitante posterior ejecuta script del atacante. Codificar salida y CSP.",
        en: "Stored XSS reachable. Later visitors run attacker script. Encode output and CSP.",
      },
      steps: {
        es: ["Encoding HTML/attr/JS al renderizar.", "CSP sin unsafe-inline.", "HttpOnly + SameSite en sesión.", "Revisar sinks (innerHTML, document.write)."],
        en: ["Contextual encoding.", "CSP without unsafe-inline.", "HttpOnly + SameSite.", "Audit sinks."],
      },
    }),
    dvwaCard({
      re: /xss_d|XSS \(DOM\)/i,
      cwe: ["CWE-79", "CWE-80"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1059.007", name: "JavaScript", tactic: "Execution" }],
      refs: [{ label: "HackTricks — XSS", href: HT + "xss-cross-site-scripting/index.html" }],
      narrative: {
        es: "XSS DOM: el script se arma en el navegador desde location/hash/query sin pasar por el HTML del servidor (HackTricks: DOM XSS). Mitigación: no usar innerHTML con datos de URL; textContent; CSP.",
        en: "DOM XSS is built in the browser from location/hash. Avoid innerHTML with URL data; use textContent; CSP.",
      },
      exec: {
        es: "XSS basado en DOM. Revisar JavaScript que lee la URL y escribe en el DOM.",
        en: "DOM-based XSS. Audit JS that reads the URL into the DOM.",
      },
      steps: {
        es: ["Eliminar innerHTML/document.write con input de URL.", "textContent / APIs seguras.", "CSP estricta."],
        en: ["Remove innerHTML from URL data.", "Use textContent.", "Strict CSP."],
      },
    }),
    dvwaCard({
      re: /xss_r|XSS \(Reflected\)|Módulo XSS \(DVWA\)/i,
      cwe: ["CWE-79"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" }],
      refs: [{ label: "HackTricks — XSS", href: HT + "xss-cross-site-scripting/index.html" }],
      narrative: {
        es: "XSS reflejado: la entrada vuelve en la misma respuesta HTML sin encoding (HackTricks). DVWA /vulnerabilities/xss_r/. Requiere que la víctima abra un enlace; con HttpOnly ausente, la sesión viaja al atacante.",
        en: "Reflected XSS echoes input in the HTML response. Victim must open a link; missing HttpOnly leaks the session.",
      },
      exec: {
        es: "XSS reflejado en módulo DVWA. Codificar, CSP y cookies HttpOnly.",
        en: "Reflected XSS on the DVWA module. Encode, CSP, HttpOnly.",
      },
      steps: {
        es: ["Output encoding.", "CSP.", "HttpOnly + SameSite.", "No concatenar input en HTML."],
        en: ["Output encoding.", "CSP.", "HttpOnly + SameSite.", "Do not concatenate input into HTML."],
      },
    }),
    dvwaCard({
      re: /Command Injection|vulnerabilities\/exec/i,
      cwe: ["CWE-78"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
      impact: { confidentiality: "high", integrity: "high", availability: "high" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      refs: [{ label: "HackTricks — Command injection", href: HT + "command-injection/index.html" }],
      narrative: {
        es: "Command injection: la entrada llega a una shell del SO (distinto de SQLi, que se queda en la BD). Impacto: RCE en el host del servidor web. DVWA /vulnerabilities/exec/. Defensa: no invocar shell; APIs nativas; listas blancas de argumentos; nunca interpolar input en system()/exec().",
        en: "Command injection reaches the OS shell (unlike SQLi). Impact is host RCE. Do not shell out; use native APIs; allow-list arguments.",
      },
      exec: {
        es: "Módulo de command injection accesible. Riesgo de ejecución en el servidor. Eliminar llamadas a shell con input de usuario.",
        en: "Command-injection module reachable. Stop shelling out on user input.",
      },
      steps: {
        es: ["Inventariar system/exec/passthru/backticks.", "Sustituir por APIs sin shell.", "Allow-list de valores.", "Usuario del servicio sin sudo."],
        en: ["Inventory system/exec/passthru.", "Replace with non-shell APIs.", "Allow-list values.", "Unprivileged service user."],
      },
    }),
    dvwaCard({
      re: /File Inclusion|vulnerabilities\/fi/i,
      cwe: ["CWE-98", "CWE-22"],
      owasp: "A03:2021 / A01:2021",
      mitre: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }, { id: "T1505.003", name: "Web Shell", tactic: "Persistence" }],
      refs: [{ label: "HackTricks — File inclusion", href: HT + "file-inclusion/index.html" }],
      narrative: {
        es: "File inclusion (LFI/RFI): include/require con path controlado. LFI lee ficheros locales; RFI carga código remoto si allow_url_include está On (DVWA setup lo muestra). Defensa: allow-list de páginas, no pasar path de usuario, allow_url_include=Off.",
        en: "File inclusion: user-controlled include/require. Disable allow_url_include; allow-list pages; never pass raw paths.",
      },
      exec: {
        es: "Módulo de file inclusion accesible. Riesgo de lectura de ficheros y, si RFI está habilitado, de código remoto.",
        en: "File-inclusion module reachable. File read and possible remote code if RFI is on.",
      },
      steps: {
        es: ["allow_url_include=Off y allow_url_fopen revisado.", "Mapa id→fichero en servidor, nunca path crudo.", "open_basedir.", "No exponer php.ini."],
        en: ["allow_url_include=Off.", "Server-side id-to-file map.", "open_basedir.", "Do not expose php.ini."],
      },
    }),
    dvwaCard({
      re: /File Upload|vulnerabilities\/upload|hackable\/uploads/i,
      cwe: ["CWE-434"],
      owasp: "A04:2021 Insecure Design",
      mitre: [{ id: "T1505.003", name: "Web Shell", tactic: "Persistence" }],
      kill: "Installation",
      refs: [{ label: "HackTricks — File upload", href: HT + "file-upload/index.html" }],
      narrative: {
        es: "Upload inseguro: si el servidor ejecuta lo subido, es webshell. DVWA /vulnerabilities/upload/ y hackable/uploads escribible (setup.php). Defensa: validar tipo en servidor, guardar fuera del docroot o sin ejecución, nombres aleatorios, no confiar en MIME del cliente.",
        en: "Insecure upload can become a webshell if the server executes it. Validate server-side; store non-executable; random names.",
      },
      exec: {
        es: "Módulo de upload y/o directorio escribible. Riesgo de persistencia en el servidor web.",
        en: "Upload module and/or writable directory. Persistence risk on the web server.",
      },
      steps: {
        es: ["Validación de extensión y contenido en servidor.", "Directorio sin ejecución (php_admin_flag engine off).", "Permisos 0750.", "Antivirus/scan de uploads en prod."],
        en: ["Server-side type checks.", "Non-executable upload dir.", "Tight ACLs.", "Scan uploads in prod."],
      },
    }),
    dvwaCard({
      re: /vulnerabilities\/csrf|Módulo CSRF/i,
      cwe: ["CWE-352"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Collection" }],
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
      refs: [{ label: "HackTricks — CSRF", href: HT + "csrf-cross-site-request-forgery/index.html" }],
      narrative: {
        es: "CSRF: el navegador de la víctima autenticada envía una petición que el servidor trata como intencionada. DVWA /vulnerabilities/csrf/. Defensa: token anti-CSRF por sesión (DVWA ya usa user_token en login), SameSite, no GET para cambios de estado.",
        en: "CSRF: the victim browser sends a forged request while authenticated. Anti-CSRF tokens, SameSite, no state-changing GET.",
      },
      exec: {
        es: "Módulo CSRF accesible. Un tercero puede disparar acciones con la sesión de la víctima.",
        en: "CSRF module reachable. Third parties can trigger actions in the victim session.",
      },
      steps: {
        es: ["Token CSRF sincronizado en todos los POST.", "SameSite=Lax/Strict.", "Re-auth para cambios de password.", "No usar GET para mutaciones."],
        en: ["CSRF tokens on all POSTs.", "SameSite.", "Re-auth for password changes.", "No state-changing GET."],
      },
    }),
    dvwaCard({
      re: /Brute Force \(DVWA\)|vulnerabilities\/brute/i,
      cwe: ["CWE-307", "CWE-799"],
      owasp: "A07:2021 Identification and Authentication Failures",
      mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "medium", availability: "low" },
      refs: [{ label: "HackTricks (índice)", href: "https://hacktricks.wiki/en/index.html" }],
      narrative: {
        es: "Fuerza bruta de login: sin lockout, CAPTCHA ni rate limit, un diccionario prueba cuentas. DVWA /vulnerabilities/brute/. Defensa: rate limiting, lockout, MFA, mensajes de error genéricos, logging.",
        en: "Login brute force without lockout or rate limit. Rate-limit, lockout, MFA, generic errors, logging.",
      },
      exec: {
        es: "Módulo brute-force accesible. Las credenciales débiles caen en minutos. Rate-limit y MFA.",
        en: "Brute-force module reachable. Weak passwords fall quickly. Rate-limit and MFA.",
      },
      steps: {
        es: ["Rate limit por IP y por cuenta.", "Lockout progresivo.", "MFA en admin.", "Alertas de picos de 401/403."],
        en: ["Rate limit per IP and account.", "Progressive lockout.", "MFA for admin.", "Alert on 401/403 spikes."],
      },
    }),
    dvwaCard({
      re: /Weak Session|vulnerabilities\/weak_id/i,
      cwe: ["CWE-330", "CWE-340"],
      owasp: "A07:2021",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Collection" }],
      refs: [{ label: "HackTricks — cookies", href: HT + "hacking-with-cookies/index.html" }],
      narrative: {
        es: "IDs de sesión predecibles (incrementales, time-based) permiten secuestrar sesiones ajenas. DVWA /vulnerabilities/weak_id/. Defensa: CSPRNG, longitud suficiente, regenerar al login, HttpOnly/Secure/SameSite.",
        en: "Predictable session IDs enable session hijack. Use a CSPRNG, rotate on login, HttpOnly/Secure/SameSite.",
      },
      exec: {
        es: "Identificadores de sesión débiles. Regenerar IDs criptográficamente fuertes.",
        en: "Weak session identifiers. Switch to a cryptographic session ID.",
      },
      steps: {
        es: ["session.sid_length / CSPRNG.", "Regenerar ID tras autenticación.", "Flags de cookie.", "Invalidar al logout."],
        en: ["CSPRNG session IDs.", "Regenerate on login.", "Cookie flags.", "Invalidate on logout."],
      },
    }),
    dvwaCard({
      re: /Insecure CAPTCHA|vulnerabilities\/captcha/i,
      cwe: ["CWE-804", "CWE-307"],
      owasp: "A07:2021",
      mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      narrative: {
        es: "CAPTCHA inseguro o bypassable (validación solo en cliente, reCAPTCHA mal verificado). DVWA /vulnerabilities/captcha/. Defensa: verificación server-side de reCAPTCHA, umbrales, no confiar en el POST del cliente.",
        en: "Insecure CAPTCHA (client-only checks). Verify reCAPTCHA server-side.",
      },
      exec: {
        es: "CAPTCHA del lab bypassable. La protección anti-bot no cuenta si no se valida en servidor.",
        en: "Lab CAPTCHA is bypassable unless verified server-side.",
      },
      steps: {
        es: ["Verificar token CAPTCHA en servidor.", "Claves reCAPTCHA no en JS público como único control.", "Rate limit adicional."],
        en: ["Verify CAPTCHA server-side.", "Do not rely on public JS keys alone.", "Extra rate limit."],
      },
    }),
    dvwaCard({
      re: /CSP Bypass|vulnerabilities\/csp/i,
      cwe: ["CWE-693", "CWE-79"],
      owasp: "A05:2021",
      mitre: [{ id: "T1059.007", name: "JavaScript", tactic: "Execution" }],
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      refs: [{ label: "HackTricks — CSP", href: HT + "content-security-policy-csp-bypass/index.html" }],
      narrative: {
        es: "CSP débil (unsafe-inline, wildcards, JSONP) no para XSS. DVWA /vulnerabilities/csp/. Defensa: CSP nonce/hash, sin unsafe-inline, script-src estricto, report-uri.",
        en: "Weak CSP (unsafe-inline, wildcards) does not stop XSS. Use nonces/hashes; drop unsafe-inline.",
      },
      exec: {
        es: "Política CSP bypassable. Endurecer cabeceras y quitar inline scripts.",
        en: "Bypassable CSP. Harden headers; remove inline scripts.",
      },
      steps: {
        es: ["script-src con nonce o hash.", "Quitar unsafe-inline/eval.", "Revisar JSONP y CDNs amplios.", "report-to para violaciones."],
        en: ["nonce/hash script-src.", "No unsafe-inline/eval.", "Tighten CDNs.", "report-to."],
      },
    }),
    dvwaCard({
      re: /vulnerabilities\/javascript|Módulo JavaScript \(DVWA\)/i,
      cwe: ["CWE-602", "CWE-656"],
      owasp: "A04:2021 Insecure Design",
      mitre: [{ id: "T1059.007", name: "JavaScript", tactic: "Execution" }],
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      narrative: {
        es: "Validación solo en JavaScript de cliente: se omite con un proxy. DVWA /vulnerabilities/javascript/. Toda regla de negocio y auth debe vivir en servidor.",
        en: "Client-only JS validation is skipped with a proxy. Enforce rules on the server.",
      },
      exec: {
        es: "Controles solo en el cliente. Reimplementar validación en servidor.",
        en: "Client-only controls. Reimplement validation on the server.",
      },
      steps: {
        es: ["Duplicar validación en backend.", "No confiar en hidden fields / JS flags.", "Tests que envían POST sin el JS."],
        en: ["Server-side validation.", "Do not trust hidden fields.", "Tests that POST without JS."],
      },
    }),

    {
      re: /config\.inc\.php\.bak/i,
      cwe: ["CWE-538", "CWE-200", "CWE-540"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" },
        { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
      ],
      gdpr: ["Art. 5.1.f", "Art. 32", "Art. 33"],
      iso: ["A.8.12", "A.8.24", "A.5.33"],
      ens: "Alto (confidencialidad)",
      nis2: "Art. 21 — medidas de ciberseguridad",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "low" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      narrative: {
        es: "Un backup de configuración servido por HTTP es una fuga de secretos, no un hallazgo cosmética. Los ficheros .bak/.dist/.old suelen quedar fuera de las reglas que bloquean .inc.php y contienen usuario, contraseña y host de base de datos. Un atacante anónimo puede copiar el archivo, autenticarse en MySQL y extraer o alterar datos personales. El informe debe exigir prueba del código HTTP de ESTA ruta (no un 200 de otra página) y el hash del cuerpo si hay secretos.",
        en: "A configuration backup served over HTTP is a secrets leak. .bak/.dist/.old files often bypass rules that block .inc.php and hold database credentials. An unauthenticated attacker can retrieve the file and access the data store.",
      },
      exec: {
        es: "Exposición de copia de configuración de aplicación. Riesgo de compromiso de base de datos y de datos personales. Prioridad inmediata: retirar el fichero del document root y rotar credenciales.",
        en: "Application config backup exposed. Immediate: remove from document root and rotate credentials.",
      },
      steps: {
        es: [
          "Confirmar GET autenticado y anónimo a /config/config.inc.php.bak (código y cuerpo).",
          "Eliminar .bak/.dist/.old del document root y bloquear /config/ en el servidor web.",
          "Rotar contraseñas de BD, tokens y claves que pudieran ir en el backup.",
          "Revisar copias en git, tarballs y snapshots del mismo directorio.",
          "Verificar con curl que la ruta responde 403/404 y registrar evidencia.",
        ],
        en: [
          "Confirm anonymous GET to the backup path (status and body).",
          "Remove backup files from the document root; deny /config/.",
          "Rotate any credentials that may have been in the file.",
          "Search git history and snapshots for copies.",
          "Re-test until the path is 403/404; keep evidence.",
        ],
      },
    },
    {
      re: /config\.inc\.php/i,
      cwe: ["CWE-538", "CWE-200", "CWE-215"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" },
        { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      ],
      gdpr: ["Art. 5.1.f integridad y confidencialidad", "Art. 32 seguridad del tratamiento", "Art. 33 notificación de brechas"],
      iso: ["A.8.12 Prevención de fugas", "A.8.24 Uso de criptografía", "A.5.33 Protección de registros"],
      ens: "Medio–Alto (dimensión confidencialidad)",
      nis2: "Art. 21.2.e — seguridad en la adquisición y desarrollo",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "medium", availability: "low" },
      narrative: {
        es: "config.inc.php (o equivalentes .env, wp-config.php, settings.py) no debe ser interpretado ni descargable desde Internet. Si el motor marcó HTTP 200, hay que argumentar: (1) la petición fue contra esa URL concreta, (2) el cuerpo contiene directivas de aplicación o secretos, (3) no se confundió con un 200 de login.php u otra ruta. Un 404 en /config.inc.php de la raíz no justifica este título; un 200 en /config/config.inc.php o .bak sí. Impacto: compromiso de credenciales de BD, session keys y, en DVWA, usuario admin por defecto. Tratamiento RGPD: si la BD guarda datos de alumnos o usuarios de laboratorio, es una violación de seguridad del tratamiento (Art. 32) y puede activar el deber de evaluar notificación (Art. 33–34).",
        en: "config.inc.php must not be downloadable. A 200 must be bound to that exact URL and body, not another page. Root 404 is not this finding; /config/*.bak 200 is. Impact: database credentials and session secrets.",
      },
      exec: {
        es: "Posible exposición de archivo de configuración de la aplicación web. Criticidad alta/crítica si el cuerpo incluye secretos. Acción: denegar el acceso web, sacar la config del document root y rotar secretos si hubo descarga pública.",
        en: "Possible web-accessible application config. Deny access, move config off the document root, rotate secrets if publicly fetched.",
      },
      steps: {
        es: [
          "Reproducir GET a la URL exacta del hallazgo; adjuntar código HTTP y excerpt redacted del cuerpo.",
          "Si 200 con secretos: rotar credenciales de BD y tokens de sesión de inmediato.",
          "Mover la configuración fuera del document root; el código PHP debe incluir por ruta de sistema.",
          "Denegar en Apache/nginx (FilesMatch para .inc .env .bak .dist) y desactivar Indexes.",
          "Añadir test de regresión en CI o en el playbook: esperar 403/404.",
          "Actualizar el registro de tratamiento (Art. 30) si hay datos personales en esa BD.",
        ],
        en: [
          "Replay GET to the exact URL; attach status and redacted body.",
          "If 200 with secrets: rotate DB and session credentials immediately.",
          "Move config outside the document root.",
          "Deny .inc/.env/.bak via web server; disable directory indexes.",
          "Add a regression check expecting 403/404.",
          "Update RoPA (GDPR Art. 30) if personal data sits in that database.",
        ],
      },
    },
    {
      re: /Secretos de aplicaci[oó]n|secretos en cuerpo|application secrets|db_password/i,
      cwe: ["CWE-200", "CWE-540"],
      owasp: "A02:2021 Cryptographic Failures",
      mitre: [
        { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
      ],
      gdpr: ["Art. 5.1.f", "Art. 32", "Art. 33"],
      iso: ["A.8.12", "A.8.24"],
      ens: "Alto (confidencialidad)",
      nis2: "Art. 21 — medidas de ciberseguridad",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      narrative: {
        es: "Secretos de aplicación (contraseñas de BD, keys, tokens) en una respuesta HTTP son una fuga de confidencialidad. Rotar lo revelado, dejar de emitir secretos en HTML/JSON y restringir debug. No confundir con un token CSRF de formulario.",
        en: "Application secrets in an HTTP body are a confidentiality leak. Rotate what was disclosed; stop emitting secrets in HTML/JSON; restrict debug.",
      },
      exec: {
        es: "Fuga de secretos de aplicación en cuerpo HTTP. Rotar credenciales y eliminar la exposición.",
        en: "Application secrets leaked in an HTTP body. Rotate credentials and stop the exposure.",
      },
      steps: {
        es: [
          "Identificar qué secreto se vio (BD, sesión, API) y rotarlo de inmediato.",
          "Retirar phpinfo, backups y páginas de debug que vuelquen configuración.",
          "No interpolar credenciales en HTML, logs ni respuestas de error.",
          "Verificar con la misma URL que el cuerpo ya no contiene el secreto.",
        ],
        en: [
          "Identify the leaked secret and rotate it immediately.",
          "Remove phpinfo, backups and debug pages that dump config.",
          "Do not interpolate credentials into HTML, logs or error bodies.",
          "Re-test the same URL until the secret is gone from the body.",
        ],
      },
    },
    {
      re: /allow_url_include/i,
      cwe: ["CWE-98", "CWE-829"],
      owasp: "A03:2021 Injection",
      mitre: [
        { id: "T1505.003", name: "Web Shell", tactic: "Persistence" },
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      ],
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.8", "A.8.26"],
      ens: "Alto",
      nis2: "Art. 21.2.e — seguridad en desarrollo",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "high" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      narrative: {
        es: "allow_url_include=On habilita RFI: include/require puede cargar código remoto. En producción debe estar Off; open_basedir limita paths; nunca pasar paths de usuario a include(). Distinto de una página phpinfo: aquí el control es la directiva PHP, no el diagnóstico.",
        en: "allow_url_include=On enables RFI. Disable it in production; use open_basedir; never pass user paths to include(). This is not a phpinfo finding.",
      },
      exec: {
        es: "Directiva PHP allow_url_include habilitada. Riesgo de inclusión remota de código. Desactivar y no pasar paths de usuario a include.",
        en: "PHP allow_url_include is on. Remote file inclusion risk. Turn it off; do not pass user paths to include.",
      },
      steps: {
        es: [
          "Poner allow_url_include=Off en php.ini y recargar PHP-FPM/Apache.",
          "Activar open_basedir al document root de la aplicación.",
          "Sustituir include de path de usuario por un mapa id→fichero en servidor.",
          "Verificar que phpinfo (si existe) ya no muestra allow_url_include On.",
        ],
        en: [
          "Set allow_url_include=Off and reload PHP.",
          "Set open_basedir to the app document root.",
          "Replace user-controlled include paths with a server-side id-to-file map.",
          "Confirm phpinfo no longer shows allow_url_include On.",
        ],
      },
    },
    {
      re: /phpinfo\.php|phpinfo\(\)|Cuerpo phpinfo/i,
      cwe: ["CWE-215", "CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
        { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
      ],
      gdpr: ["Art. 32", "Art. 25 (privacidad desde el diseño)"],
      iso: ["A.8.9", "A.8.27"],
      ens: "Medio",
      nis2: "Art. 21.2.a — políticas de análisis de riesgos",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      narrative: {
        es: "phpinfo() volca versión de PHP, módulos, rutas, variables de entorno y a veces credenciales. Un 302 a login no es exposición; un 200 autenticado o anónimo sí lo es. Facilita exploits de versiones (p. ej. PHP 7.0.x) y el mapeo de include paths para LFI.",
        en: "phpinfo() dumps PHP version, modules, paths and sometimes secrets. A 302 to login is not exposure; a 200 is. It aids version-specific exploits and LFI path mapping.",
      },
      exec: {
        es: "Página de diagnóstico PHP accesible. Reduce el coste de reconocimiento y puede filtrar rutas internas. Retirar phpinfo.php de cualquier entorno no aislado.",
        en: "PHP diagnostic page reachable. Remove phpinfo.php from non-lab environments.",
      },
      steps: {
        es: [
          "Distinguir 302 (redirige a login) de 200 con cuerpo phpinfo.",
          "Eliminar phpinfo.php y cualquier llamada a phpinfo() en código de aplicación.",
          "Restringir entornos de debug (display_errors Off en producción).",
          "Parchear PHP si la versión revelada está fuera de soporte.",
        ],
        en: [
          "Distinguish 302-to-login from a 200 phpinfo body.",
          "Delete phpinfo.php and phpinfo() calls.",
          "Disable display_errors in production.",
          "Patch EOL PHP versions disclosed by the page.",
        ],
      },
    },
    {
      re: /credenciales por defecto|default cred|admin\/password/i,
      cwe: ["CWE-798", "CWE-521"],
      owasp: "A07:2021 Identification and Authentication Failures",
      mitre: [
        { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
        { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
      ],
      gdpr: ["Art. 32.1.b", "Art. 5.1.f", "Art. 25"],
      iso: ["A.8.5", "A.5.17"],
      ens: "Alto (autenticación)",
      nis2: "Art. 21.2.d — control de acceso",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      narrative: {
        es: "Un POST de login que establece sesión con admin/password es compromiso de cuenta, no un hallazgo informativo. Debe documentarse el token CSRF si aplica, el 302 de redirección y las cookies de sesión. En DVWA es el diseño del lab; en cualquier otro activo es incidente. Tras el acceso, el atacante alcanza módulos de inyección, XSS y upload.",
        en: "A login POST that creates a session with default admin/password is account takeover. Document CSRF handling, the 302, and session cookies.",
      },
      exec: {
        es: "Autenticación con credenciales de fábrica. Acceso privilegiado trivial. Forzar cambio de contraseña, deshabilitar cuentas por defecto y MFA.",
        en: "Factory-default credentials accepted. Force password change, disable defaults, add MFA.",
      },
      steps: {
        es: [
          "Invalidar sesiones emitidas con la cuenta por defecto.",
          "Forzar reset y política de contraseñas; desactivar admin de fábrica.",
          "MFA en cuentas de administración.",
          "Monitorizar logins desde el mismo origen del pentest.",
        ],
        en: [
          "Invalidate sessions issued to the default account.",
          "Force reset; disable factory admin.",
          "MFA for admin accounts.",
          "Watch auth logs for the pentest source.",
        ],
      },
    },
    {
      re: /DVWA expuesta|Damn Vulnerable|aplicación DVWA/i,
      cwe: ["CWE-489", "CWE-489"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.9", "A.8.19"],
      ens: "Alto si hay datos reales; lab si está aislado",
      nis2: "Art. 21 — no operar software deliberadamente vulnerable en producción",
      kill: "Delivery",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      narrative: {
        es: "DVWA es un laboratorio de vulnerabilidades conocidas (SQLi, XSS, CSRF, upload, RFI). Exponerlo fuera de un segmento aislado equivale a publicar un polígono de tiro contra la propia organización. El informe debe dejar claro el alcance (IP/puerto), que no es un falso positivo de fingerprint, y que cada módulo es un hallazgo hijo si está autenticado.",
        en: "DVWA is a known-vulnerable lab. Hosting it outside an isolated segment is equivalent to publishing an attack range on the organisation.",
      },
      exec: {
        es: "Aplicación de entrenamiento deliberadamente insegura en el objetivo. No debe existir en redes con datos reales ni ser accesible desde fuera del lab.",
        en: "Deliberately vulnerable training app on the target. Must not sit on networks with real data.",
      },
      steps: {
        es: [
          "Confirmar que el host es lab (RFC1918 / localhost) y no un VPS de producción.",
          "Si no es lab: apagar el vhost, destruir la instancia y rotar secretos.",
          "Segmentar el lab (VLAN/NAT) y no publicarlo en Internet.",
          "Inventariar copias (Docker, snapshots) y aplicar la misma regla.",
        ],
        en: [
          "Confirm lab vs production.",
          "If production: shut down, destroy, rotate secrets.",
          "Keep labs off the public Internet.",
          "Inventory clones and snapshots.",
        ],
      },
    },
    {
      re: /nivel de seguridad.*low|security=low/i,
      cwe: ["CWE-16", "CWE-656"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      gdpr: ["Art. 32.1.b"],
      iso: ["A.8.9"],
      ens: "Alto en contexto no-lab",
      nis2: "Art. 21.2.a",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "low" },
      narrative: {
        es: "La cookie security=low en DVWA desactiva las mitigaciones de los retos. Es evidencia de que SQLi, XSS y CSRF son triviales. En un producto real equivaldría a WAF/CSP/CSRF tokens desactivados.",
        en: "DVWA security=low disables challenge mitigations. SQLi/XSS/CSRF become trivial.",
      },
      exec: {
        es: "Controles de la aplicación en el nivel mínimo. Subir el nivel solo en lab; en producción no aplica DVWA.",
        en: "App controls at minimum. Raise the DVWA level in lab only.",
      },
      steps: {
        es: ["Documentar la cookie y el Set-Cookie.", "En lab: usar medium/high para pruebas realistas.", "No replicar security=low en aplicaciones reales."],
        en: ["Document the cookie.", "Use medium/high in lab for realistic tests.", "Do not ship security=low patterns in real apps."],
      },
    },
    {
      re: /HttpOnly/i,
      cwe: ["CWE-1004", "CWE-614"],
      owasp: "A05:2021 / A07:2021",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Collection" }],
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.24", "A.8.5"],
      ens: "Medio",
      nis2: "Art. 21.2.e",
      kill: "Installation",
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      narrative: {
        es: "Sin HttpOnly, un XSS puede leer PHPSESSID y secuestrar la sesión. Hay que citar la línea Set-Cookie exacta y si hay Secure/SameSite. Encadena con el hallazgo XSS si existe.",
        en: "Without HttpOnly, XSS can steal PHPSESSID. Cite the Set-Cookie line and Secure/SameSite.",
      },
      exec: {
        es: "Cookie de sesión legible por script. Combinado con XSS es robo de sesión. Activar HttpOnly, Secure y SameSite.",
        en: "Session cookie script-readable. Enable HttpOnly, Secure, SameSite.",
      },
      steps: {
        es: ["session.cookie_httponly=1 y cookie_secure=1.", "SameSite=Lax o Strict.", "Regenerar session id tras login.", "Re-verificar Set-Cookie."],
        en: ["Enable httponly and secure.", "Set SameSite.", "Regenerate session id after login.", "Re-check Set-Cookie."],
      },
    },
    {
      id: "server-ip",
      re: /revela direcci[oó]n IP|Server revela direcci[oó]n IP/i,
      cwe: ["CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.9"],
      ens: "Bajo",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      narrative: {
        es: "El valor de Server es una IPv4, no un paquete httpd con versión. Si es RFC1918 (10/8, 172.16/12, 192.168/16) filtra un hop interno o el origen detrás del reverse proxy. No justifica inventario CVE ni ServerTokens Prod: hay que dejar de publicar esa IP en el banner.",
        en: "Server is an IPv4, not a versioned httpd banner. RFC1918 leaks internal topology. Do not treat as ServerTokens/CVE matching.",
      },
      exec: {
        es: "Banner Server con IP (posible red interna). Quitar la IP del header; no es una versión de Apache/nginx.",
        en: "Server banner is an IP (possible internal network). Strip it; not an httpd version leak.",
      },
      steps: {
        es: [
          "Confirmar el header Server en una petición HEAD/GET.",
          "Sustituir por un banner genérico en el proxy/origen.",
          "Revisar otros headers (X-Powered-By, Via, X-Backend) por IPs RFC1918.",
          "Re-verificar que el valor ya no es una IPv4.",
        ],
        en: [
          "Confirm Server on HEAD/GET.",
          "Use a generic banner on proxy/origin.",
          "Check X-Powered-By/Via/X-Backend for RFC1918.",
          "Re-check Server is no longer an IPv4.",
        ],
      },
    },
    {
      re: /cabecera Server|versión en cabecera/i,
      cwe: ["CWE-200", "CWE-497"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" }],
      gdpr: ["Art. 25"],
      iso: ["A.8.9"],
      ens: "Bajo",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "low", availability: "low" },
      narrative: {
        es: "La cabecera Server con versión (Apache/2.4.25) abarata el emparejamiento con CVE. No es explotable por sí sola; justifica parcheo y ServerTokens Prod.",
        en: "A versioned Server header cheapens CVE matching. Not exploitable alone; patch and reduce fingerprint.",
      },
      exec: {
        es: "Fingerprint de servidor web. Reducir banner y aplicar parches del paquete httpd.",
        en: "Web server fingerprint. Reduce banner and patch httpd.",
      },
      steps: {
        es: ["ServerTokens Prod / ServerSignature Off.", "Inventario de CVE para esa versión.", "Plan de parcheo."],
        en: ["ServerTokens Prod.", "CVE inventory for that version.", "Patch plan."],
      },
    },
    {
      re: /setup\.php/i,
      cwe: ["CWE-489", "CWE-250"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.3", "A.8.2"],
      ens: "Alto",
      nis2: "Art. 21.2.i — cifrado y control de acceso",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      narrative: {
        es: "setup.php en DVWA permite recrear la BD y muestra usuario MySQL, host y rutas escribibles. Es panel de instalación vivo: reset de admin, filtración de configuración y superficie de CSRF (el propio lab muestra «CSRF token is incorrect» si el POST no lleva token).",
        en: "DVWA setup.php can reset the DB and leaks MySQL user/host plus writable paths. Treat it as a live installer.",
      },
      exec: {
        es: "Instalador de la aplicación accesible. Puede resetear credenciales y filtrar datos de infraestructura. Bloquear tras el alta.",
        en: "Installer still reachable. Can reset credentials and leak infra data.",
      },
      steps: {
        es: ["Restringir setup.php por IP o autenticación.", "Retirar tras instalación.", "No filtrar usuario/host MySQL en HTML.", "Revisar CSRF del formulario de reset."],
        en: ["Restrict setup.php.", "Remove after install.", "Do not leak MySQL user/host in HTML.", "Review CSRF on the reset form."],
      },
    },
    {
      re: /Panel de módulos vulnerables/i,
      cwe: ["CWE-489"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.9", "A.8.19"],
      ens: "Alto si hay datos reales",
      nis2: "Art. 21 — no exponer laboratorios en el perímetro productivo",
      kill: "Delivery",
      govKey: "lab",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      refs: [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
      narrative: {
        es: "Tras autenticación el menú /vulnerabilities/ enumera las clases de fallo (SQLi, XSS, CSRF, exec, FI, upload, CSP…). Cada módulo hijo tiene su propia ficha. Este hallazgo es la superficie-padre: el laboratorio está montado y autenticado.",
        en: "After login /vulnerabilities/ lists the vulnerable modules. Each child has its own card. This finding is the parent surface: the lab is mounted and authenticated.",
      },
      exec: {
        es: "Panel de módulos DVWA accesible. Inventariar cada hijo; no dejar este menú en redes con datos reales.",
        en: "DVWA module panel reachable. Inventory each child; do not leave this menu on networks with real data.",
      },
      steps: {
        es: ["Confirmar que no hay 302 a login.", "Tratar cada módulo como hallazgo hijo.", "Si no es lab: apagar el vhost."],
        en: ["Confirm this is not a login 302.", "Treat each module as a child finding.", "If not a lab: shut the vhost."],
      },
    },
    {
      re: /NoSQL injection/i,
      cwe: ["CWE-943", "CWE-89"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.26", "A.8.28"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      narrative: {
        es: "El backend pasa el body de la petición directo a un filtro de MongoDB/Mongoose sin tipar ni sanear. Un operador como {\"$gt\":\"\"} es siempre verdadero, así que autentica sin credenciales reales. Es el equivalente NoSQL de una SQL injection clásica: falta de separación entre datos de entrada y sintaxis de consulta.",
        en: "The backend forwards the request body straight into a MongoDB/Mongoose filter without typing or sanitizing it. An operator like {\"$gt\":\"\"} is always true, authenticating without real credentials — the NoSQL analogue of classic SQL injection.",
      },
      exec: {
        es: "Bypass de login por inyección NoSQL. Cualquier cuenta —incluida la de administrador— es accesible sin contraseña. Sanear tipos de entrada antes del driver de Mongo.",
        en: "Login bypass via NoSQL injection. Any account, including admin, is reachable without a password. Sanitize input types before they reach the Mongo driver.",
      },
      steps: {
        es: ["Rechazar objetos donde se espera un string primitivo (usuario/contraseña).", "Usar un ODM/esquema que valide tipos (Mongoose schema strict).", "Nunca reenviar req.body sin filtrar a una query de Mongo.", "Rate-limiting y alertas de login anómalo."],
        en: ["Reject objects where a primitive string is expected.", "Use a schema-validating ODM (Mongoose strict mode).", "Never forward raw req.body into a Mongo query.", "Rate-limit and alert on anomalous logins."],
      },
    },
    {
      re: /Open redirect en/i,
      cwe: ["CWE-601"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.26"],
      ens: "Medio",
      nis2: "Art. 21.2.e",
      kill: "Delivery",
      impact: { confidentiality: "low", integrity: "low", availability: "none" },
      narrative: {
        es: "El parámetro de redirección acepta una URL externa completa y el servidor responde con Location apuntando a ella, sin validar contra una allow-list de orígenes propios. Un atacante puede blanquear un enlace de phishing bajo el dominio de confianza de esta aplicación (el usuario ve el dominio legítimo antes del salto).",
        en: "The redirect parameter accepts a full external URL and the server issues a Location header pointing at it, with no allow-list check. An attacker can launder a phishing link under this application's trusted domain.",
      },
      exec: {
        es: "Redirección abierta explotable para phishing con el dominio legítimo. Validar el destino contra una lista de rutas/orígenes propios.",
        en: "Open redirect exploitable for phishing under the legitimate domain. Validate the destination against an allow-list.",
      },
      steps: {
        es: ["Sustituir la URL completa por un índice/slug interno resuelto en servidor.", "Si se necesita URL externa, validar contra allow-list de dominios.", "Registrar y alertar redirecciones a dominios no listados."],
        en: ["Replace the raw URL with an internal index/slug resolved server-side.", "If an external URL is required, validate against a domain allow-list.", "Log and alert redirects to non-listed domains."],
      },
    },
    {
      re: /posible IDOR\)/i,
      cwe: ["CWE-639", "CWE-306"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1213", name: "Data from Information Repositories", tactic: "Collection" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.3", "A.5.15"],
      ens: "Alto",
      nis2: "Art. 21.2.d",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "none" },
      narrative: {
        es: "El endpoint devuelve el objeto por ID sin exigir ninguna sesión ni token: no es solo que un usuario pueda ver el ID de otro (IDOR horizontal clásico), es que no hace falta autenticarse en absoluto. Hay que confirmar con una segunda cuenta si además cruza usuarios, pero el hallazgo de «cero autenticación requerida» ya es explotable tal cual.",
        en: "The endpoint returns the object by ID without requiring any session or token: it is not only that a user could reach another user's ID (classic horizontal IDOR) — no authentication is required at all. Confirm cross-account access with a second account, but 'zero auth required' is already exploitable as-is.",
      },
      exec: {
        es: "Objetos accesibles por ID sin sesión. Riesgo directo de exfiltración masiva enumerando IDs consecutivos. Exigir sesión y verificar propiedad del recurso.",
        en: "Objects reachable by ID with no session. Direct risk of mass exfiltration by enumerating IDs. Require a session and verify resource ownership.",
      },
      steps: {
        es: ["Exigir sesión válida en el endpoint.", "Verificar que el ID solicitado pertenece al usuario autenticado (no solo que exista sesión).", "Rate-limit sobre enumeración secuencial de IDs.", "Auditar el resto de endpoints REST por el mismo patrón."],
        en: ["Require a valid session on the endpoint.", "Verify the requested ID belongs to the authenticated user.", "Rate-limit sequential ID enumeration.", "Audit other REST endpoints for the same pattern."],
      },
    },
    {
      re: /Falta Strict-Transport-Security|Falta X-Content-Type-Options|protecci[oó]n contra clickjacking|Falta Content-Security-Policy/i,
      cwe: ["CWE-693", "CWE-319", "CWE-1021"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" }],
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.26", "A.8.9"],
      ens: "Bajo",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "low", integrity: "low", availability: "none" },
      narrative: {
        es: "No es explotable en solitario: es defensa en profundidad ausente. Sin HSTS un downgrade a HTTP no se previene en el navegador; sin nosniff el navegador puede reinterpretar el tipo de una respuesta; sin X-Frame-Options/frame-ancestors el sitio es embebible en un iframe ajeno (clickjacking); sin CSP, un XSS que sí logre colarse (aquí o en el futuro) es mucho más fácil de explotar. El impacto real depende de qué otro hallazgo se encadene con esta ausencia.",
        en: "Not exploitable alone: it is missing defence-in-depth. No HSTS means the browser will not prevent an HTTP downgrade; no nosniff allows MIME-type reinterpretation; no X-Frame-Options/frame-ancestors allows the site to be framed (clickjacking); no CSP makes any XSS that does land far easier to exploit. Real impact depends on what else chains with this absence.",
      },
      exec: {
        es: "Cabecera(s) de hardening ausente(s). Riesgo bajo por sí solo, pero reduce el coste de explotar otros hallazgos (XSS, clickjacking, downgrade). Añadir la cabecera correspondiente.",
        en: "Missing hardening header(s). Low risk alone, but it cheapens exploitation of other findings (XSS, clickjacking, downgrade). Add the corresponding header.",
      },
      steps: {
        es: ["Strict-Transport-Security: max-age=31536000; includeSubDomains si el sitio es HTTPS.", "X-Content-Type-Options: nosniff en todas las respuestas.", "X-Frame-Options: DENY/SAMEORIGIN o CSP frame-ancestors.", "Content-Security-Policy: default-src 'self'; script-src explícito, sin unsafe-inline.", "Re-verificar con curl -I tras el despliegue."],
        en: ["Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS sites.", "X-Content-Type-Options: nosniff on every response.", "X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.", "Content-Security-Policy: default-src 'self'; explicit script-src, no unsafe-inline.", "Re-verify with curl -I after deploy."],
      },
    },
    {
      re: /sin flag Secure/i,
      cwe: ["CWE-614"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1040", name: "Network Sniffing", tactic: "Credential Access" }],
      govKey: "session",
      gdpr: ["Art. 32"],
      iso: ["A.8.24"],
      ens: "Medio",
      nis2: "Art. 21.2.e",
      kill: "Collection",
      impact: { confidentiality: "medium", integrity: "low", availability: "none" },
      narrative: {
        es: "La cookie se emite sin el flag Secure: el navegador la reenviaría igual si el sitio llegase a servirse alguna vez por HTTP plano (downgrade, proxy mal configurado, red hostil), exponiéndola en tránsito sin cifrar.",
        en: "The cookie is issued without the Secure flag: the browser would still send it over a plain-HTTP downgrade, a misconfigured proxy or a hostile network, exposing it in transit unencrypted.",
      },
      exec: {
        es: "Cookie sin Secure. Riesgo de exposición en tránsito ante un downgrade a HTTP. Añadir el flag.",
        en: "Cookie missing Secure. Exposure risk on an HTTP downgrade. Add the flag.",
      },
      steps: {
        es: ["Marcar la cookie con Secure (y HttpOnly/SameSite si corresponde).", "Forzar HSTS para evitar el downgrade a HTTP en primer lugar.", "Re-verificar el Set-Cookie con curl -I."],
        en: ["Mark the cookie Secure (and HttpOnly/SameSite where relevant).", "Enforce HSTS to prevent the HTTP downgrade in the first place.", "Re-check Set-Cookie with curl -I."],
      },
    },
    {
      re: /sin atributo SameSite/i,
      cwe: ["CWE-352"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Collection" }],
      govKey: "session",
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.26"],
      ens: "Bajo",
      nis2: "Art. 21.2.e",
      kill: "Delivery",
      impact: { confidentiality: "low", integrity: "medium", availability: "none" },
      narrative: {
        es: "Sin SameSite, la cookie se envía también en peticiones cross-site iniciadas desde un dominio ajeno, ampliando la superficie de CSRF si no hay otra mitigación (token anti-CSRF) para las acciones que dependen de ella.",
        en: "Without SameSite, the cookie is also sent on cross-site requests from a foreign origin, widening the CSRF surface for any action that relies on it, absent another mitigation such as an anti-CSRF token.",
      },
      exec: {
        es: "Cookie sin SameSite. Amplía la superficie de CSRF. Definir SameSite=Lax o Strict.",
        en: "Cookie missing SameSite. Widens CSRF surface. Set SameSite=Lax or Strict.",
      },
      steps: {
        es: ["Definir SameSite=Lax (o Strict si el flujo lo permite).", "Mantener también token anti-CSRF en formularios de estado.", "Re-verificar el Set-Cookie."],
        en: ["Set SameSite=Lax (or Strict if the flow allows it).", "Keep an anti-CSRF token on state-changing forms too.", "Re-check the Set-Cookie header."],
      },
    },
    {
      re: /\(Prometheus\) expuesto|Source map de JavaScript expuesto/i,
      cwe: ["CWE-200", "CWE-540"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.9"],
      ens: "Bajo",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      narrative: {
        es: "El endpoint filtra información interna (rutas, contadores, nombres de variable, lógica de negocio del código fuente sin minificar) sin exigir autenticación. No es explotable por sí solo, pero facilita reconocimiento y abarata el resto de la cadena de ataque.",
        en: "The endpoint leaks internal information (paths, counters, variable names, un-minified business logic) with no authentication required. Not exploitable alone, but it eases reconnaissance and cheapens the rest of the attack chain.",
      },
      exec: {
        es: "Información interna expuesta sin autenticación. Restringir el acceso o retirar el artefacto de producción.",
        en: "Internal information exposed with no auth. Restrict access or remove the artifact from production.",
      },
      steps: {
        es: ["Restringir el endpoint a la red interna o exigir autenticación.", "Excluir artefactos de debug (.map) del build de producción.", "Re-verificar que ya no es accesible públicamente."],
        en: ["Restrict the endpoint to the internal network or require auth.", "Exclude debug artifacts (.map) from the production build.", "Re-verify it is no longer publicly reachable."],
      },
    },
    {
      re: /responde sin control de acceso real/i,
      cwe: ["CWE-200", "CWE-306"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.3"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "none", availability: "none" },
      narrative: {
        es: "robots.txt declaraba Disallow para esta ruta, pero Disallow es una convención dirigida a crawlers educados, no un control de acceso. La ruta responde con contenido real (HTTP 200) sin exigir autenticación.",
        en: "robots.txt declared Disallow for this path, but Disallow is a convention aimed at well-behaved crawlers, not an access control. The path responds with real content (HTTP 200) without requiring authentication.",
      },
      exec: {
        es: "Ruta 'oculta' por robots.txt accesible sin autenticación. Proteger con autenticación real o retirarla de producción.",
        en: "Path 'hidden' via robots.txt is reachable without auth. Protect with real authentication or remove it from production.",
      },
      steps: {
        es: ["No depender de robots.txt para ocultar rutas.", "Proteger la ruta con autenticación/autorización si contiene datos sensibles.", "Retirarla de producción si no es necesaria."],
        en: ["Do not rely on robots.txt to hide paths.", "Protect the path with real authentication/authorization if it holds sensitive data.", "Remove it from production if unnecessary."],
      },
    },
    {
      re: /Secreto JWT débil/i,
      cwe: ["CWE-798", "CWE-347"],
      owasp: "A02:2021 Cryptographic Failures",
      mitre: [{ id: "T1606", name: "Forge Web Credentials", tactic: "Credential Access" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.24", "A.8.28"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      refs: [{ label: "HackTricks — Hacking JWT", href: HT + "hacking-jwt-json-web-tokens.html" }],
      narrative: {
        es: "El JWT capturado usa alg=HS256 firmado con un secreto que aparece en un diccionario curado de valores habituales (defaults de librería, ejemplos de documentación de frameworks, palabras genéricas). El crackeo es puramente offline: se prueba HMAC-SHA256(header.payload, candidato) contra la firma real hasta que coincide. Con el secreto en mano, cualquiera puede firmar un token con los claims que quiera (rol admin, cualquier usuario) sin conocer ninguna contraseña ni tocar la base de datos.",
        en: "The captured JWT uses alg=HS256 signed with a secret present in a curated wordlist of common values (library defaults, framework doc examples, generic words). Cracking is purely offline: HMAC-SHA256(header.payload, candidate) is tried against the real signature until it matches. With the secret in hand, anyone can sign a token with any claims they want (admin role, any user) without knowing any password or touching the database.",
      },
      exec: {
        es: "El secreto que firma las sesiones es adivinable. Cualquiera puede forjar tokens de administrador. Rotar el secreto por uno aleatorio de 256 bits y considerar migrar a claves asimétricas (RS256/ES256).",
        en: "The secret signing sessions is guessable. Anyone can forge admin tokens. Rotate to a random 256-bit secret and consider migrating to asymmetric keys (RS256/ES256).",
      },
      steps: {
        es: ["Generar un secreto aleatorio de al menos 256 bits con un CSPRNG.", "Rotar el secreto invalida todos los tokens ya emitidos (forzar re-login).", "Evaluar migrar a RS256/ES256 (clave privada nunca sale del servidor de auth).", "No usar el mismo secreto en dev/staging/producción."],
        en: ["Generate a random secret of at least 256 bits with a CSPRNG.", "Rotating the secret invalidates all issued tokens (forces re-login).", "Evaluate migrating to RS256/ES256 (private key never leaves the auth server).", "Never reuse the same secret across dev/staging/production."],
      },
    },
    {
      re: /Bypass de autorización con JWT alg=none/i,
      cwe: ["CWE-347"],
      owasp: "A02:2021 Cryptographic Failures",
      mitre: [{ id: "T1606", name: "Forge Web Credentials", tactic: "Credential Access" }],
      govKey: "access_control",
      gdpr: ["Art. 32"],
      iso: ["A.8.3", "A.8.24"],
      ens: "Muy Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      refs: [{ label: "HackTricks — Hacking JWT", href: HT + "hacking-jwt-json-web-tokens.html" }],
      narrative: {
        es: "El JWT original se reforjó cambiando su cabecera a {\"alg\":\"none\"} y vaciando la firma, manteniendo intacto el payload (mismos claims de rol/usuario). El endpoint protegido lo aceptó igualmente (HTTP 2xx en vez de 401/403): el servidor confía en el algoritmo declarado por el propio token en vez de imponer una allow-list fija, así que basta con decir 'no hay firma que verificar' para saltarse por completo la autenticación.",
        en: "The original JWT was refored by switching its header to {\"alg\":\"none\"} and emptying the signature, keeping the payload intact (same role/user claims). The protected endpoint accepted it anyway (HTTP 2xx instead of 401/403): the server trusts the algorithm the token itself declares instead of enforcing a fixed allow-list, so simply saying 'there is no signature to verify' fully bypasses authentication.",
      },
      exec: {
        es: "La API acepta tokens sin firmar. Un atacante puede forjar cualquier rol sin conocer ningún secreto. Corregir la verificación de JWT de inmediato: es explotación trivial y automatizable.",
        en: "The API accepts unsigned tokens. An attacker can forge any role without knowing any secret. Fix JWT verification immediately: this is trivial, automatable exploitation.",
      },
      steps: {
        es: ["Fijar el algoritmo esperado en el propio código de verificación (allow-list explícita), nunca leerlo del token.", "Rechazar explícitamente alg=none en la librería JWT.", "Actualizar a una versión reciente de la librería JWT (los bypasses alg=none suelen ser CVEs conocidos y ya parcheados).", "Añadir un test de regresión que envíe un token alg=none y espere 401."],
        en: ["Pin the expected algorithm in the verification code itself (explicit allow-list), never read it from the token.", "Explicitly reject alg=none in the JWT library.", "Upgrade to a recent JWT library version (alg=none bypasses are usually known, already-patched CVEs).", "Add a regression test that sends an alg=none token and expects 401."],
      },
    },
    {
      re: /hardcodead[ao] en bundle JS/i,
      cwe: ["CWE-798", "CWE-540"],
      owasp: "A02:2021 Cryptographic Failures",
      mitre: [{ id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.12", "A.8.24"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Reconnaissance",
      impact: { confidentiality: "high", integrity: "medium", availability: "none" },
      refs: [{ label: "HackTricks — External recon", href: "https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html" }],
      narrative: {
        es: "Las SPAs (React/Vue/Angular) se compilan a JavaScript que corre en el navegador del visitante: todo lo que esté embebido ahí es público, aunque el fichero se sirva sin listarlo en ningún menú. Este bundle contiene un valor con el formato de una credencial real (clave de API, token, o clave privada) en texto plano. Cualquiera que abra las herramientas de desarrollador o simplemente descargue el .js puede copiarla.",
        en: "SPAs (React/Vue/Angular) compile down to JavaScript that runs in the visitor's browser: anything embedded there is public, even if the file is served without being listed in any menu. This bundle contains a value shaped like a real credential (API key, token, or private key) in plain text. Anyone opening dev tools or simply downloading the .js can copy it.",
      },
      exec: {
        es: "Una credencial real quedó embebida en el código que se descarga al navegador de cualquier visitante. Rotarla de inmediato y mover la lógica que la usa a un backend/proxy.",
        en: "A real credential ended up embedded in code downloaded to any visitor's browser. Rotate it immediately and move the logic that uses it to a backend/proxy.",
      },
      steps: {
        es: ["Rotar la credencial expuesta de inmediato (puede llevar tiempo cacheada en CDN/buscadores/Wayback Machine).", "Mover cualquier llamada que necesite esa clave a un backend que la use server-side.", "Usar variables de entorno de build solo para valores realmente públicos (p. ej. claves publishable de Stripe, apiKey pública de Firebase).", "Añadir un scanner de secretos (gitleaks/trufflehog) al pipeline de CI antes de publicar el bundle."],
        en: ["Rotate the exposed credential immediately (it may stay cached in CDNs/search engines/Wayback Machine for a while).", "Move any call needing that key to a backend that uses it server-side.", "Only use build-time env vars for values that are genuinely meant to be public (e.g. Stripe publishable keys, Firebase Web apiKey).", "Add a secrets scanner (gitleaks/trufflehog) to the CI pipeline before publishing the bundle."],
      },
    },
    {
      re: /WAF\/CDN identificado/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.8.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      narrative: {
        es: "Huella pasiva a partir de cabeceras de respuesta (sin enviar ningún payload malicioso de prueba): identifica qué WAF/CDN opera delante de la aplicación. No es una vulnerabilidad por sí sola; es contexto de gobierno que explica por qué ciertas sondas activas del propio informe pueden llegar bloqueadas o alteradas, y documenta que existe una capa de defensa perimetral que un atacante real tendría que sortear.",
        en: "Passive fingerprint from response headers (no malicious test payload sent): identifies which WAF/CDN sits in front of the application. Not a vulnerability by itself; it is governance context explaining why some of the report's own active probes may arrive blocked or altered, and documents that a perimeter defense layer exists that a real attacker would have to bypass.",
      },
      exec: {
        es: "Se identificó la solución de WAF/CDN delante de la aplicación. Información de contexto para el informe, sin acción correctiva requerida.",
        en: "The WAF/CDN solution in front of the application was identified. Context information for the report, no remediation required.",
      },
      steps: {
        es: ["Ninguna acción requerida.", "Si no se esperaba WAF y no aparece ninguna firma, valorar desplegar uno.", "Revisar las reglas del WAF cubren las clases de ataque relevantes para esta app (OWASP CRS o equivalente)."],
        en: ["No action required.", "If a WAF was expected and no signature appears, consider deploying one.", "Review that WAF rules cover the attack classes relevant to this app (OWASP CRS or equivalent)."],
      },
    },
    {
      re: /WAF activo: bloqueó una sonda/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.8.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      narrative: {
        es: "Caja negra: se envió una sonda inofensiva con forma de UNION SELECT en la query string y el perímetro la cortó (403/406/429 y página o firma de WAF). Demuestra control activo, no solo un CDN que reenvía. No es un fallo; es evidencia de que un atacante real tropieza con esa capa antes de la aplicación.",
        en: "Black-box: a harmless UNION SELECT-shaped probe in the query string was cut off at the perimeter (403/406/429 plus a WAF page or signature). That is active control, not merely a forwarding CDN. Not a flaw; evidence a real attacker hits this layer before the app.",
      },
      exec: {
        es: "El WAF bloqueó una sonda de inyección. Contexto de defensa perimetral, sin remediación.",
        en: "The WAF blocked an injection probe. Perimeter-defense context, no remediation.",
      },
      steps: {
        es: ["Ninguna acción requerida.", "Verificar que el mismo WAF cubre también APIs y vhosts paralelos.", "Revisar falsos positivos que puedan romper flujos legítimos."],
        en: ["No action required.", "Verify the same WAF also covers APIs and sibling vhosts.", "Review false positives that may break legitimate flows."],
      },
    },
    {
      re: /Sin WAF\/CDN identificable/i,
      cwe: ["CWE-693"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: ["Art. 32"],
      iso: ["A.8.9", "A.8.20"],
      ens: "Bajo",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      narrative: {
        es: "Desde fuera no hay huella de WAF/CDN ni bloqueo de una sonda de inyección inofensiva. Un dominio público sin esa capa deja la aplicación como primer salto de un atacante. No prueba que no exista un filtro opaco (iptables/SG que no responde), pero sí que no hay control de capa 7 observable.",
        en: "From the outside there is neither a WAF/CDN fingerprint nor a block of a harmless injection probe. A public domain without that layer makes the app an attacker's first hop. This does not prove an opaque filter (iptables/SG that drops silently) is absent — only that no layer-7 control is observable.",
      },
      exec: {
        es: "No hay WAF observable delante del dominio. Valorar desplegar uno (Cloudflare, AWS WAF, ModSecurity/CRS) antes de publicar más superficie.",
        en: "No observable WAF in front of the domain. Consider deploying one (Cloudflare, AWS WAF, ModSecurity/CRS) before publishing more surface.",
      },
      steps: {
        es: ["Poner un WAF con OWASP CRS delante de 80/443.", "No publicar orígenes de API sin el mismo control.", "Re-verificar con una sonda de SQLi/XSS que ahora sí se corta."],
        en: ["Put a WAF with OWASP CRS in front of 80/443.", "Do not publish API origins without the same control.", "Re-verify with an SQLi/XSS probe that it is now blocked."],
      },
    },
    {
      re: /expuesto a Internet sin filtrar/i,
      cwe: ["CWE-284", "CWE-668"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
        { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
      ],
      govKey: "access_control",
      gdpr: ["Art. 32"],
      iso: ["A.8.20", "A.8.22"],
      ens: "Alto",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "high", integrity: "medium", availability: "low" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      narrative: {
        es: "Caja negra: nmap ve el puerto open desde Internet (no filtered). SSH, RDP, SMB o un motor de base de datos no deberían ser alcanzables desde 0.0.0.0/0. Es el hallazgo de infraestructura que más se ve en auditorías reales: el Security Group o el ufw del cliente dejó el servicio publicado al mundo.",
        en: "Black-box: nmap sees the port open from the Internet (not filtered). SSH, RDP, SMB or a database engine should not be reachable from 0.0.0.0/0. This is the infrastructure finding most often seen in real audits: the client's Security Group or ufw left the service published to the world.",
      },
      exec: {
        es: "Un servicio de gestión o de datos está abierto a Internet. Cerrarlo al mundo y permitir solo la red de administración (ufw, iptables o Security Group).",
        en: "A management or data service is open to the Internet. Close it to the world and allow only the admin network (ufw, iptables, or Security Group).",
      },
      steps: {
        es: ["ufw: `ufw deny <puerto>/tcp` y `ufw allow from <red-admin> to any port <puerto>`.", "iptables: ACCEPT desde la red de admin, DROP al resto en ese dport.", "AWS: retirar 0.0.0.0/0 de ese puerto en el Security Group; usar bastion o SSM Session Manager para SSH.", "Confirmar con nmap desde fuera que pasa a filtered/closed."],
        en: ["ufw: `ufw deny <port>/tcp` and `ufw allow from <admin-net> to any port <port>`.", "iptables: ACCEPT from the admin net, DROP everyone else on that dport.", "AWS: remove 0.0.0.0/0 from that port on the Security Group; use a bastion or SSM Session Manager for SSH.", "Confirm with nmap from outside that it is now filtered/closed."],
      },
    },
    {
      re: /Perímetro con filtrado de paquetes/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1046", name: "Network Service Discovery", tactic: "Discovery" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.8.20"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      narrative: {
        es: "nmap marca puertos como filtered: el paquete se descarta (SG, NACL, iptables DROP, WAF de red) en vez de responder RST. Es la postura correcta para servicios que no deben existir en Internet. Contexto, no fallo.",
        en: "nmap marks ports as filtered: the packet is dropped (SG, NACL, iptables DROP, network WAF) instead of answering RST. That is the correct posture for services that must not exist on the Internet. Context, not a flaw.",
      },
      exec: {
        es: "El perímetro descarta puertos no publicados. Información de contexto.",
        en: "The perimeter drops unpublished ports. Context information.",
      },
      steps: {
        es: ["Ninguna acción por el filtrado en sí.", "Comprobar que 80/443 siguen open y que 22/3389/BD siguen filtered."],
        en: ["No action for the filtering itself.", "Check that 80/443 stay open and that 22/3389/DB stay filtered."],
      },
    },
    {
      re: /UFW inactivo en el host auditado|iptables INPUT con política ACCEPT|nftables input hook con policy accept/i,
      cwe: ["CWE-284"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1562.004", name: "Impair Defenses: Disable or Modify System Firewall", tactic: "Defense Evasion" }],
      govKey: "access_control",
      gdpr: ["Art. 32"],
      iso: ["A.8.20", "A.8.22"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "low", availability: "low" },
      cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
      narrative: {
        es: "Caja gris, solo cuando el objetivo es el propio host (127.0.0.1): se leyeron las reglas locales y UFW está apagado o INPUT/nft acepta por defecto. Cualquier proceso en LISTEN queda al alcance del segmento. No se confunde con el firewall de Kali al auditar un target remoto: esos pasos no corren fuera de loopback.",
        en: "Gray-box, only when the target is the host itself (127.0.0.1): local rules were read and UFW is off or INPUT/nft accepts by default. Any LISTEN process is reachable on the segment. This is not confused with Kali's firewall when auditing a remote target: those steps do not run off loopback.",
      },
      exec: {
        es: "El host firewall está inactivo o en allow-by-default. Activar UFW con default deny y allow solo 22/80/443.",
        en: "The host firewall is inactive or allow-by-default. Enable UFW with default deny and allow only 22/80/443.",
      },
      steps: {
        es: ["`ufw default deny incoming`", "`ufw allow 22/tcp` (red de admin) y `ufw allow 80,443/tcp`", "`ufw enable`", "No publicar contenedores Docker en 0.0.0.0 salvo los puertos previstos."],
        en: ["`ufw default deny incoming`", "`ufw allow 22/tcp` (admin net) and `ufw allow 80,443/tcp`", "`ufw enable`", "Do not publish Docker containers on 0.0.0.0 except intended ports."],
      },
    },
    {
      re: /UFW activo pero política por defecto ALLOW/i,
      cwe: ["CWE-284"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1562.004", name: "Impair Defenses: Disable or Modify System Firewall", tactic: "Defense Evasion" }],
      govKey: "access_control",
      gdpr: ["Art. 32"],
      iso: ["A.8.20"],
      ens: "Alto",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "low", availability: "none" },
      cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
      narrative: {
        es: "UFW está encendido pero default allow incoming: las reglas deny no cubren el puerto que un servicio nuevo abra mañana. La postura profesional es default deny más allow explícito.",
        en: "UFW is on but default allow incoming: deny rules will not cover a port a new service opens tomorrow. The professional posture is default deny plus explicit allows.",
      },
      exec: {
        es: "Cambiar UFW a default deny incoming y dejar allow solo de lo publicado.",
        en: "Switch UFW to default deny incoming and allow only what is published.",
      },
      steps: {
        es: ["`ufw default deny incoming`", "Allow 22 (admin), 80 y 443.", "Revisar `ufw status numbered` y borrar allows a Anywhere en puertos de BD."],
        en: ["`ufw default deny incoming`", "Allow 22 (admin), 80 and 443.", "Review `ufw status numbered` and remove Anywhere allows on DB ports."],
      },
    },
    {
      re: /UFW activo \(default deny\)|iptables INPUT con política default deny/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.8.20"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      narrative: {
        es: "Caja gris: el host auditado tiene UFW o iptables en default deny. Contexto de gobierno, no hallazgo negativo.",
        en: "Gray-box: the audited host has UFW or iptables on default deny. Governance context, not a negative finding.",
      },
      exec: {
        es: "Host firewall activo con default deny. Información de contexto.",
        en: "Host firewall active with default deny. Context information.",
      },
      steps: {
        es: ["Ninguna acción requerida.", "Auditar que no haya ACCEPT a 0.0.0.0/0 en puertos de gestión."],
        en: ["No action required.", "Audit that there is no ACCEPT to 0.0.0.0/0 on management ports."],
      },
    },
    {
      re: /Infraestructura identificada como AWS/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1526", name: "Cloud Service Discovery", tactic: "Discovery" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.8.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      narrative: {
        es: "Las cabeceras de respuesta (x-amz-cf-id, x-amzn-requestid, x-amz-apigw-id, etc.) identifican infraestructura AWS delante de la aplicación (CloudFront, API Gateway o un Application Load Balancer). Es huella pasiva, no una vulnerabilidad: contexto de gobierno que ayuda a priorizar qué superficie cloud relacionada (IAM, S3, Security Groups, metadata de instancia) revisar junto con el resto de hallazgos.",
        en: "Response headers (x-amz-cf-id, x-amzn-requestid, x-amz-apigw-id, etc.) identify AWS infrastructure in front of the application (CloudFront, API Gateway, or an Application Load Balancer). Passive fingerprint, not a vulnerability: governance context that helps prioritize which related cloud surface (IAM, S3, Security Groups, instance metadata) to review alongside the rest of the findings.",
      },
      exec: {
        es: "La aplicación corre sobre infraestructura AWS. Información de contexto para priorizar la revisión de configuración cloud junto con el resto del informe.",
        en: "The application runs on AWS infrastructure. Context information to prioritize cloud configuration review alongside the rest of the report.",
      },
      steps: {
        es: ["Ninguna acción requerida por sí sola.", "Si hay hallazgos de credenciales o SSRF, revisar también permisos IAM del rol asociado y políticas de bucket S3.", "Confirmar que IMDSv2 está forzado en las instancias EC2 relevantes."],
        en: ["No action required by itself.", "If there are credential or SSRF findings, also review the associated IAM role permissions and S3 bucket policies.", "Confirm IMDSv2 is enforced on the relevant EC2 instances."],
      },
    },
    {
      re: /Bucket S3 referenciado por la app es listable/i,
      cwe: ["CWE-284", "CWE-200"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.9", "A.8.10"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      refs: [{ label: "HackTricks — AWS S3 Unauthenticated Enum", href: "https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum/index.html" }],
      narrative: {
        es: "Un bucket S3 referenciado por la propia aplicación (visto en HTML/JS ya servido) responde con un listado XML (&lt;ListBucketResult&gt;) al pedirlo sin ninguna credencial: la ACL/política del bucket permite listado público. Esto expone los nombres (y a menudo el contenido, si también permite GetObject) de todos los objetos del bucket a cualquiera, sea o no cliente legítimo de la app.",
        en: "An S3 bucket referenced by the app itself (seen in already-served HTML/JS) responds with an XML listing (&lt;ListBucketResult&gt;) when requested with no credentials at all: the bucket's ACL/policy allows public listing. This exposes the names (and often the content, if GetObject is also allowed) of every object in the bucket to anyone, legitimate app client or not.",
      },
      exec: {
        es: "Un bucket de almacenamiento en la nube usado por la app es enumerable públicamente. Bloquear el acceso público al bucket de inmediato y auditar qué se pudo haber descargado.",
        en: "A cloud storage bucket used by the app is publicly enumerable. Block public bucket access immediately and audit what may have been downloaded.",
      },
      steps: {
        es: ["Activar S3 Block Public Access a nivel de cuenta y de bucket.", "Revisar la bucket policy y las ACLs: retirar cualquier Principal: \"*\" salvo objetos explícitamente públicos.", "Servir contenido realmente público solo vía CloudFront con Origin Access Control (OAC), nunca exponiendo el bucket directo.", "Revisar los logs de acceso del bucket por descargas anómalas anteriores al hallazgo."],
        en: ["Enable S3 Block Public Access at both account and bucket level.", "Review the bucket policy and ACLs: remove any Principal: \"*\" except for explicitly public objects.", "Serve genuinely public content only via CloudFront with Origin Access Control (OAC), never exposing the bucket directly.", "Review the bucket's access logs for anomalous downloads predating the finding."],
      },
    },
    {
      re: /Contenedor Azure Blob referenciado por la app es listable/i,
      cwe: ["CWE-284", "CWE-200"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.9", "A.8.10"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      narrative: {
        es: "Un contenedor Azure Blob Storage referenciado por la propia aplicación responde con un listado XML (&lt;EnumerationResults&gt;) sin ninguna credencial: el nivel de acceso público del contenedor permite listado. Expone los nombres (y el contenido si el acceso también es de lectura) de todos los blobs a cualquiera.",
        en: "An Azure Blob Storage container referenced by the app itself responds with an XML listing (&lt;EnumerationResults&gt;) with no credentials at all: the container's public access level allows listing. Exposes blob names (and content if read access is also public) to anyone.",
      },
      exec: {
        es: "Contenedor de almacenamiento cloud usado por la app es enumerable públicamente. Restringir el acceso público de inmediato.",
        en: "Cloud storage container used by the app is publicly enumerable. Restrict public access immediately.",
      },
      steps: {
        es: ["Cambiar el nivel de acceso público del contenedor a Private en Azure Storage.", "Revisar políticas de acceso compartido (SAS) y roles RBAC del Storage Account.", "Servir contenido público solo vía Azure CDN/Front Door con token firmado.", "Revisar logs de diagnóstico del Storage Account por descargas anómalas."],
        en: ["Set the container's public access level to Private in Azure Storage.", "Review shared access (SAS) policies and Storage Account RBAC roles.", "Serve public content only via Azure CDN/Front Door with a signed token.", "Review Storage Account diagnostic logs for anomalous downloads."],
      },
    },
    {
      re: /Bucket GCS referenciado por la app es listable/i,
      cwe: ["CWE-284", "CWE-200"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.9", "A.8.10"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      narrative: {
        es: "Un bucket de Google Cloud Storage referenciado por la propia aplicación responde con un listado JSON (storage#objects) sin ninguna credencial: la IAM policy del bucket concede acceso a allUsers/allAuthenticatedUsers. Expone los nombres y metadatos de todos los objetos.",
        en: "A Google Cloud Storage bucket referenced by the app itself responds with a JSON listing (storage#objects) with no credentials at all: the bucket's IAM policy grants access to allUsers/allAuthenticatedUsers. Exposes the names and metadata of every object.",
      },
      exec: {
        es: "Bucket de almacenamiento cloud usado por la app es enumerable públicamente. Retirar el acceso público de inmediato.",
        en: "Cloud storage bucket used by the app is publicly enumerable. Remove public access immediately.",
      },
      steps: {
        es: ["Quitar allUsers/allAuthenticatedUsers de la IAM policy del bucket.", "Activar Bucket Policy Only / Uniform access y Public Access Prevention.", "Servir contenido público solo vía Cloud CDN con URL firmada.", "Revisar Cloud Audit Logs por descargas anómalas."],
        en: ["Remove allUsers/allAuthenticatedUsers from the bucket's IAM policy.", "Enable Uniform bucket-level access and Public Access Prevention.", "Serve public content only via Cloud CDN with signed URLs.", "Review Cloud Audit Logs for anomalous downloads."],
      },
    },
    {
      re: /hardcodeada en bundle JS/i,
      cwe: ["CWE-798", "CWE-321"],
      owasp: "A02:2021 Cryptographic Failures",
      mitre: [{ id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.24", "A.8.9"],
      ens: "Crítico",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "low" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
      narrative: {
        es: "El bundle JavaScript servido públicamente contiene una credencial de un proveedor identificable por su formato (regex de baja tasa de falso positivo). El código que corre en el navegador del cliente es, por definición, público: cualquier credencial embebida ahí ya está comprometida frente a cualquiera que abra las herramientas de desarrollador o descargue el bundle.",
        en: "The publicly served JavaScript bundle contains a credential matching a known provider's format (low false-positive regex). Client-side code is public by definition: any embedded credential is already compromised to anyone opening dev tools or downloading the bundle.",
      },
      exec: {
        es: "Credencial de proveedor cloud/SaaS embebida en código público. Rotar la credencial de inmediato y sacar los secretos del bundle cliente.",
        en: "Cloud/SaaS provider credential embedded in public code. Rotate the credential immediately and remove secrets from the client bundle.",
      },
      steps: {
        es: ["Rotar/revocar la credencial expuesta de inmediato en el panel del proveedor.", "Mover la llamada que usa esa credencial a un backend propio (BFF) en vez del navegador.", "Auditar logs del proveedor por uso no autorizado desde la exposición.", "Añadir un scanner de secretos al pipeline de build para prevenir recurrencia."],
        en: ["Rotate/revoke the exposed credential immediately in the provider's console.", "Move the call using that credential to a backend of your own (BFF) instead of the browser.", "Audit the provider's logs for unauthorized use since exposure.", "Add a secret scanner to the build pipeline to prevent recurrence."],
      },
    },
    {
      re: /sin registro SPF|SPF de .+ permite cualquier origen|SPF de .+ sin hard fail/i,
      cwe: ["CWE-290"],
      owasp: "A07:2021 Identification and Authentication Failures",
      mitre: [{ id: "T1590.001", name: "Gather Victim Network Information: Domain Properties", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: ["Art. 32"],
      iso: ["A.5.14", "A.8.20"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Weaponization",
      impact: { confidentiality: "low", integrity: "medium", availability: "none" },
      narrative: {
        es: "SPF ausente, débil (sin -all) o excesivamente permisivo (+all) permite que terceros envíen correo falsificando el dominio de la organización. Es la base técnica de campañas de phishing/BEC (Business Email Compromise) que se hacen pasar por la propia empresa ante empleados, clientes o proveedores.",
        en: "Missing, weak (no -all), or overly permissive (+all) SPF lets third parties send email spoofing the organization's domain. This is the technical basis of phishing/BEC campaigns impersonating the company itself against employees, customers, or vendors.",
      },
      exec: {
        es: "El dominio no protege adecuadamente su email contra suplantación. Publicar/endurecer el registro SPF (TXT) con hard fail (-all).",
        en: "The domain doesn't adequately protect its email against spoofing. Publish/harden the SPF (TXT) record with a hard fail (-all).",
      },
      steps: {
        es: ["Inventariar todos los emisores legítimos de correo del dominio (proveedor de email, marketing, transaccional, etc.).", "Publicar/corregir el TXT SPF incluyendo solo esos emisores.", "Terminar el registro en -all.", "Monitorizar reportes DMARC (rua) tras el cambio por si rompe correo legítimo."],
        en: ["Inventory every legitimate email sender for the domain (email provider, marketing, transactional, etc.).", "Publish/fix the SPF TXT record including only those senders.", "End the record in -all.", "Monitor DMARC (rua) reports after the change for legitimate mail breakage."],
      },
    },
    {
      re: /sin política DMARC|DMARC de .+ en modo monitorización/i,
      cwe: ["CWE-290"],
      owasp: "A07:2021 Identification and Authentication Failures",
      mitre: [{ id: "T1590.001", name: "Gather Victim Network Information: Domain Properties", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: ["Art. 32"],
      iso: ["A.5.14", "A.8.20"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Weaponization",
      impact: { confidentiality: "low", integrity: "medium", availability: "none" },
      narrative: {
        es: "Sin DMARC (o con p=none), no hay política de rechazo/cuarentena para correo que falla SPF/DKIM ni reporte agregado de abuso del dominio. El correo falsificado llega igual a la bandeja del destinatario, y la organización no se entera de que está siendo suplantada.",
        en: "Without DMARC (or with p=none), there is no reject/quarantine policy for mail failing SPF/DKIM, nor aggregate abuse reporting. Spoofed mail still reaches the inbox, and the organization has no visibility into impersonation attempts.",
      },
      exec: {
        es: "El dominio no aplica ni monitoriza activamente su política anti-spoofing de correo. Publicar DMARC y escalar la política progresivamente hasta p=reject.",
        en: "The domain doesn't actively enforce or monitor its email anti-spoofing policy. Publish DMARC and progressively raise the policy to p=reject.",
      },
      steps: {
        es: ["Publicar TXT en _dmarc.<dominio> con p=quarantine y rua= apuntando a un buzón monitorizado.", "Revisar reportes agregados durante 2-4 semanas.", "Subir a p=reject una vez confirmado que no rompe correo legítimo.", "Alinear con SPF y DKIM (alignment strict cuando sea viable)."],
        en: ["Publish a TXT record at _dmarc.<domain> with p=quarantine and rua= pointing to a monitored mailbox.", "Review aggregate reports for 2-4 weeks.", "Raise to p=reject once confirmed not to break legitimate mail.", "Align with SPF and DKIM (strict alignment where feasible)."],
      },
    },
    {
      re: /anunciada por/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1590.001", name: "Gather Victim Network Information: Domain Properties", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.5.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      narrative: {
        es: "RDAP de la IP en scope identifica la organización/red que la anuncia (ASN). Contexto de inventario de activos: confirma si el host pertenece a infraestructura propia del cliente o a un tercero (CDN, cloud compartido), y si aparece infraestructura hermana bajo la misma organización que debería sumarse al alcance.",
        en: "RDAP of the in-scope IP identifies the organization/network announcing it (ASN). Asset-inventory context: confirms whether the host belongs to the client's own infrastructure or a third party (CDN, shared cloud), and whether sibling infrastructure under the same organization should be added to scope.",
      },
      exec: {
        es: "Contexto de titularidad de red. Ninguna acción de remediación: confirmar con el cliente si coincide con el alcance autorizado.",
        en: "Network ownership context. No remediation action: confirm with the client whether it matches the authorized scope.",
      },
      steps: {
        es: ["Confirmar con el cliente si la organización identificada es la propia o un tercero.", "Si es un tercero (CDN/hosting compartido), no reportar hallazgos de infraestructura como propiedad del cliente.", "Si aparece un bloque/ASN hermano, evaluar si debe ampliarse el scope firmado."],
        en: ["Confirm with the client whether the identified organization is theirs or a third party.", "If third-party (CDN/shared hosting), don't report infrastructure findings as the client's own.", "If a sibling block/ASN appears, evaluate whether the signed scope should be expanded."],
      },
    },
    {
      re: /confirmado como tenant Microsoft 365/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1589.002", name: "Gather Victim Identity Information: Email Addresses", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.5.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      narrative: {
        es: "Un endpoint público de Microsoft (getuserrealm.srf) confirma que el dominio es un tenant de Microsoft 365/Entra ID, y si es federado o cloud-managed. Es discovery pasivo (una sola petición GET, sin credenciales probadas ni usuarios enumerados): dimensiona el riesgo de password-spray/phishing contra Office 365 para el informe.",
        en: "A public Microsoft endpoint (getuserrealm.srf) confirms the domain is a Microsoft 365/Entra ID tenant, and whether it is federated or cloud-managed. Passive discovery only (a single GET, no credentials tried, no users enumerated): sizes the password-spray/phishing risk against Office 365 for the report.",
      },
      exec: {
        es: "El dominio usa Microsoft 365/Entra ID como IdP. Recomendar MFA obligatorio y Conditional Access para mitigar password-spray.",
        en: "The domain uses Microsoft 365/Entra ID as IdP. Recommend mandatory MFA and Conditional Access to mitigate password-spray.",
      },
      steps: {
        es: ["Confirmar MFA obligatorio para todos los usuarios (sin excepciones legacy).", "Bloquear protocolos de autenticación legacy (IMAP/POP/SMTP básico) en Entra ID.", "Activar Conditional Access con detección de riesgo (Identity Protection).", "Si es federado, revisar la configuración del ADFS/IdP externo."],
        en: ["Confirm mandatory MFA for all users (no legacy exceptions).", "Block legacy auth protocols (IMAP/POP/basic SMTP) in Entra ID.", "Enable Conditional Access with risk detection (Identity Protection).", "If federated, review the external ADFS/IdP configuration."],
      },
    },
    {
      re: /expone metadata OIDC propia/i,
      cwe: [],
      owasp: "N/A",
      mitre: [{ id: "T1590.001", name: "Gather Victim Network Information: Domain Properties", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: [],
      iso: ["A.5.9"],
      ens: "Informativo",
      nis2: "N/A",
      kill: "Reconnaissance",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      impact: { confidentiality: "none", integrity: "none", availability: "none" },
      narrative: {
        es: "El dominio expone su propio endpoint OIDC (/.well-known/openid-configuration): aloja un Identity Provider self-hosted (Okta, Auth0, Keycloak u otro) en vez de, o además de, un IdP SaaS externo. Discovery pasivo: confirma la existencia del IdP, no prueba credenciales.",
        en: "The domain exposes its own OIDC endpoint (/.well-known/openid-configuration): it hosts a self-hosted Identity Provider (Okta, Auth0, Keycloak, or other) instead of, or alongside, an external SaaS IdP. Passive discovery: confirms the IdP exists, does not try credentials.",
      },
      exec: {
        es: "El dominio aloja su propio Identity Provider. Verificar que la configuración OIDC no filtre detalles internos más allá del estándar.",
        en: "The domain hosts its own Identity Provider. Verify the OIDC configuration doesn't leak internal detail beyond the standard.",
      },
      steps: {
        es: ["Revisar issuer, authorization_endpoint y jwks_uri publicados.", "Confirmar que el IdP tiene rate-limiting en endpoints de autenticación (mitiga password-spray).", "Confirmar MFA obligatorio en el IdP self-hosted."],
        en: ["Review the published issuer, authorization_endpoint, and jwks_uri.", "Confirm the IdP rate-limits authentication endpoints (mitigates password-spray).", "Confirm mandatory MFA on the self-hosted IdP."],
      },
    },
    {
      re: /SSRF confirmado hacia metadata AWS|Posible SSRF hacia metadata AWS/i,
      cwe: ["CWE-918"],
      owasp: "A10:2021 Server-Side Request Forgery",
      mitre: [{ id: "T1552.005", name: "Unsecured Credentials: Cloud Instance Metadata API", tactic: "Credential Access" }],
      govKey: "data_breach",
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.24", "A.8.26"],
      ens: "Crítico",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      refs: [{ label: "HackTricks — Cloud SSRF", href: HT + "ssrf-server-side-request-forgery/cloud-ssrf.html" }],
      narrative: {
        es: "Un parámetro que la app usa para obtener contenido de una URL (imagen, callback, webhook…) acepta apuntar a 169.254.169.254, la dirección del Instance Metadata Service (IMDS) de AWS. Si la instancia corre con un rol IAM, IMDS expone sus credenciales temporales (AccessKeyId/SecretAccessKey/Token) a cualquier proceso en la propia instancia — y, vía este SSRF, a cualquier atacante externo sin necesidad de comprometer el sistema operativo. Es la ruta más habitual para escalar de una vulnerabilidad web 'simple' a control total de la cuenta cloud.",
        en: "A parameter the app uses to fetch content from a URL (image, callback, webhook…) accepts pointing at 169.254.169.254, AWS's Instance Metadata Service (IMDS) address. If the instance runs with an IAM role, IMDS exposes its temporary credentials (AccessKeyId/SecretAccessKey/Token) to any process on the instance itself — and, via this SSRF, to any external attacker with no need to compromise the operating system at all. This is the most common path from a 'simple' web vulnerability to full cloud account takeover.",
      },
      exec: {
        es: "Un endpoint puede ser forzado a pedir la metadata de la instancia AWS por cuenta del atacante, lo que puede filtrar credenciales del rol IAM. Bloquear el fetch de URLs internas/metadata de inmediato y forzar IMDSv2.",
        en: "An endpoint can be forced to request the AWS instance metadata on the attacker's behalf, which can leak IAM role credentials. Block fetching internal/metadata URLs immediately and enforce IMDSv2.",
      },
      steps: {
        es: ["Forzar IMDSv2 (requiere token con hop-limit=1 vía PUT) en todas las instancias EC2: un SSRF simple con GET ya no basta.", "Validar/allow-list los destinos que la app puede fetch del lado servidor; bloquear explícitamente 169.254.169.254, fd00:ec2::254 y rangos RFC1918.", "Aplicar mínimo privilegio al rol IAM de la instancia: limitar el daño si igualmente se filtran credenciales.", "Rotar cualquier credencial IAM que se haya confirmado filtrada."],
        en: ["Enforce IMDSv2 (requires a PUT-obtained token with hop-limit=1) on all EC2 instances: a simple GET-based SSRF is no longer enough.", "Validate/allow-list the destinations the app can fetch server-side; explicitly block 169.254.169.254, fd00:ec2::254, and RFC1918 ranges.", "Apply least privilege to the instance's IAM role: limits the blast radius if credentials do leak.", "Rotate any IAM credential confirmed to have leaked."],
      },
    },
    {
      re: /Wayback Machine indexó/i,
      cwe: ["CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1593", name: "Search Open Websites/Domains", tactic: "Reconnaissance" }],
      govKey: "context",
      gdpr: ["Art. 32"],
      iso: ["A.8.9"],
      ens: "Bajo",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "low", integrity: "none", availability: "none" },
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      refs: [{ label: "HackTricks — External recon", href: "https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html" }],
      narrative: {
        es: "archive.org (Wayback Machine) conserva snapshots históricos de rutas del dominio que hoy ya no están enlazadas desde ningún sitio, pero siguen indexadas para siempre por su propia naturaleza de archivo. Entre ellas aparecen rutas con extensión o nombre típico de contenido sensible (.env, .sql, .bak, /admin, /backup). No confirma que sigan accesibles hoy — solo que existieron en algún momento y podrían: reaparecer en un despliegue futuro, seguir vivas en un servidor espejo olvidado, o dar pistas de la estructura interna del proyecto.",
        en: "archive.org (Wayback Machine) keeps historical snapshots of domain paths that are no longer linked from anywhere today, but remain indexed forever by the very nature of an archive. Among them are paths with a typical sensitive-content extension or name (.env, .sql, .bak, /admin, /backup). This does not confirm they are still reachable today — only that they existed at some point and could: reappear in a future deployment, still be alive on a forgotten mirror server, or hint at the project's internal structure.",
      },
      exec: {
        es: "Rutas históricamente sensibles quedaron indexadas en Wayback Machine. Verificar manualmente si alguna sigue accesible; en caso contrario, es solo hallazgo informativo de higiene histórica.",
        en: "Historically sensitive paths were indexed on the Wayback Machine. Manually verify whether any is still reachable; otherwise it is purely an informational historical-hygiene finding.",
      },
      steps: {
        es: ["Verificar manualmente cada ruta listada contra el sitio en vivo.", "Si alguna sigue accesible, tratarla como el hallazgo (exposición/fuga) que corresponda según su contenido real.", "Solicitar a archive.org la exclusión de snapshots que contengan secretos reales confirmados (robots.txt histórico o formulario de exclusión)."],
        en: ["Manually verify each listed path against the live site.", "If any is still reachable, treat it as whatever finding (exposure/leak) its actual content warrants.", "Request archive.org exclude snapshots containing confirmed real secrets (historical robots.txt or the exclusion form)."],
      },
    },
    {
      re: /SQL Injection|SQLi/i,
      cwe: ["CWE-89"],
      owasp: "A03:2021 Injection",
      mitre: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
      gdpr: ["Art. 32", "Art. 33", "Art. 5.1.f"],
      iso: ["A.8.26", "A.8.28"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      narrative: {
        es: "El módulo o el patrón SQLi indica que la consulta se construye con entrada del usuario. El dossier debe separar: (a) endpoint accesible, (b) evidencia de interpretación SQL, (c) datos alcanzables. En lab DVWA (a) basta para el hallazgo de superficie; en producción se exige (b).",
        en: "SQLi means user input reaches the query. Lab DVWA: reachable module is enough for a surface finding; production needs query-level evidence.",
      },
      exec: {
        es: "Superficie de inyección SQL. Riesgo de lectura/escritura de BD y de datos personales. Parametrizar consultas y mínimo privilegio.",
        en: "SQL injection surface. Parameterize queries; least privilege on the DB role.",
      },
      steps: {
        es: ["Inventariar parámetros del endpoint.", "Consultas parametrizadas / ORM.", "Cuenta de BD de solo lo necesario.", "WAF como defensa en profundidad, no única."],
        en: ["Inventory parameters.", "Parameterized queries.", "Least-privilege DB account.", "WAF as defence in depth only."],
      },
    },
    {
      re: /\bXSS\b|cross-site scripting/i,
      cwe: ["CWE-79"],
      owasp: "A03:2021 Injection",
      mitre: [
        { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" },
        { id: "T1059.007", name: "JavaScript", tactic: "Execution" },
      ],
      gdpr: ["Art. 32", "Art. 25"],
      iso: ["A.8.26"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Exploitation",
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      narrative: {
        es: "XSS refleja o almacena script en el navegador de la víctima. Encadena con cookies sin HttpOnly. El informe debe indicar el módulo (xss_r, xss_s, DOM) y si hubo sesión.",
        en: "XSS runs in the victim browser. Chains with missing HttpOnly. Name the module and whether a session was present.",
      },
      exec: {
        es: "Cross-site scripting en la aplicación. Codificar salida, CSP y cookies HttpOnly.",
        en: "Cross-site scripting. Encode output, CSP, HttpOnly cookies.",
      },
      steps: {
        es: ["Contextual encoding (HTML/attr/JS).", "CSP estricta.", "HttpOnly + SameSite.", "Auditoría de sinks (innerHTML, document.write)."],
        en: ["Contextual encoding.", "Strict CSP.", "HttpOnly + SameSite.", "Audit sinks."],
      },
    },
    {
      re: /php\.ini/i,
      cwe: ["CWE-538", "CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.12"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "low", availability: "low" },
      narrative: {
        es: "Servir php.ini desde el document root filtra directivas (allow_url_include, display_errors) útiles para LFI/RFI y para saber si el lab está endurecido.",
        en: "A web-readable php.ini leaks directives useful for LFI/RFI and hardening status.",
      },
      exec: {
        es: "php.ini accesible por HTTP. Sacarlo del document root y denegar .ini.",
        en: "php.ini web-accessible. Remove from document root.",
      },
      steps: {
        es: ["Denegar *.ini en el vhost.", "No copiar php.ini al árbol web.", "Re-testear 403/404."],
        en: ["Deny *.ini.", "Do not copy php.ini into the web tree.", "Re-test 403/404."],
      },
    },
    {
      re: /listado de directorio|Index of/i,
      cwe: ["CWE-548"],
      owasp: "A01:2021 Broken Access Control",
      mitre: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.3"],
      ens: "Medio",
      nis2: "Art. 21.2.a",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "low", availability: "low" },
      narrative: {
        es: "Options Indexes permite enumerar módulos y backups sin autenticación. En DVWA /vulnerabilities/ lista sqli, xss, upload, exec, csrf, fi.",
        en: "Directory listing enumerates modules and backups without auth.",
      },
      exec: {
        es: "Listado de directorio habilitado. Desactivar Indexes y exigir autenticación.",
        en: "Directory listing enabled. Disable Indexes; require auth.",
      },
      steps: {
        es: ["Options -Indexes.", "Auth en rutas sensibles.", "No depender de robots.txt."],
        en: ["Options -Indexes.", "Auth on sensitive paths.", "Do not rely on robots.txt."],
      },
    },
    {
      re: /upload|hackable\/uploads/i,
      cwe: ["CWE-434"],
      owasp: "A04:2021 Insecure Design",
      mitre: [{ id: "T1505.003", name: "Web Shell", tactic: "Persistence" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.26"],
      ens: "Alto",
      nis2: "Art. 21.2.e",
      kill: "Installation",
      impact: { confidentiality: "high", integrity: "high", availability: "medium" },
      narrative: {
        es: "Directorio de upload escribible por el usuario del servidor web abre la puerta a webshells si la subida no valida tipo y el servidor ejecuta lo subido.",
        en: "A web-user-writable upload directory enables webshells if type checks are weak.",
      },
      exec: {
        es: "Upload escribible. Validar tipos, no ejecutar uploads, permisos mínimos.",
        en: "Writable upload path. Validate types; do not execute uploads.",
      },
      steps: {
        es: ["Validación MIME/extensión en servidor.", "Almacenar fuera del docroot o sin ejecución.", "Permisos 0750 y owner dedicado."],
        en: ["Server-side type checks.", "Store uploads non-executable.", "Tight filesystem ACLs."],
      },
    },
    {
      re: /repositorio \.git|\.git\/config expuesta|\.git\/HEAD/i,
      cwe: ["CWE-527", "CWE-538", "CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" },
        { id: "T1213", name: "Data from Information Repositories", tactic: "Collection" },
      ],
      gdpr: ["Art. 5.1.f", "Art. 32", "Art. 33"],
      iso: ["A.8.12 Prevención de fugas", "A.8.9 Gestión de la configuración", "A.8.26 Seguridad en desarrollo"],
      ens: "Alto (confidencialidad)",
      nis2: "Art. 21.2.e — seguridad en la adquisición, desarrollo y mantenimiento",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "high", availability: "low" },
      narrative: {
        es: "Un despliegue que copia el árbol de trabajo sin retirar el metadato de control de versiones deja el repositorio Git completo descargable por HTTP: código fuente, historial de commits (incluidos los borrados) y cualquier secreto que se subiera y luego se \"eliminara\" sin reescribir el historial. Aunque el listado de directorio esté desactivado, /.git/HEAD confirma la exposición y el árbol de objetos se puede reconstruir objeto a objeto (git-dumper y similares). Es de las fugas de mayor impacto por menor esfuerzo en reconocimiento web.",
        en: "A deployment that copies the working tree without stripping VCS metadata leaves the full Git repository downloadable: source, commit history (including deleted content) and any secret ever committed and later 'removed' without rewriting history. Even with directory listing off, /.git/HEAD confirms exposure and the object graph is reconstructible.",
      },
      exec: {
        es: "El repositorio .git es descargable desde el document root. Riesgo crítico de fuga de código fuente y secretos históricos (claves, contraseñas de BD, tokens). Prioridad inmediata: retirar .git del despliegue y rotar cualquier secreto que haya pasado por el historial.",
        en: "The .git repository is downloadable from the document root. Critical risk of source code and historical secret leakage. Immediate: remove .git from the deployment and rotate any secret that ever touched the history.",
      },
      steps: {
        es: [
          "Confirmar con curl -s /.git/HEAD y /.git/config que el cuerpo es Git real (ref: refs/heads/…, [core]).",
          "Retirar .git del document root del despliegue (excluir en el pipeline de build/deploy, no solo bloquear por URL).",
          "Denegar rutas ocultas (dotfiles) a nivel de servidor web como defensa en profundidad.",
          "Si hubo exposición pública, tratar TODO secreto del historial como comprometido: rotar claves, contraseñas de BD, tokens de API.",
          "Buscar con herramientas como trufflehog sobre un dump local del repo para inventariar qué se filtró antes de rotar.",
        ],
        en: [
          "Confirm with curl -s /.git/HEAD and /.git/config that the body is real Git output.",
          "Strip .git from the deployed artifact in the build/deploy pipeline, not just block by URL.",
          "Deny dotfiles at the web server as defense in depth.",
          "Treat every historical secret as compromised; rotate DB credentials and API tokens.",
          "Run trufflehog against a local dump to inventory what leaked before rotating.",
        ],
      },
      refs: [{ label: "HackTricks — Git", href: "https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/git.html" }],
    },
    {
      re: /archivo \.env expuesto|\.htpasswd expuesto|web\.config expuesto/i,
      cwe: ["CWE-538", "CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" }],
      gdpr: ["Art. 5.1.f", "Art. 32", "Art. 33"],
      iso: ["A.8.12 Prevención de fugas", "A.8.24 Uso de criptografía"],
      ens: "Alto (confidencialidad)",
      nis2: "Art. 21 — medidas de ciberseguridad",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "medium", availability: "low" },
      narrative: {
        es: "Un fichero de configuración/credenciales (.env, .htpasswd, web.config) es servido tal cual por el servidor web en lugar de ser interpretado o bloqueado. El cuerpo debe atarse a ESA URL concreta: hay que confirmar el patrón esperado (variables de entorno, hashes htpasswd, connectionStrings) antes de cerrar el hallazgo. Impacto directo: credenciales de aplicación, base de datos o servicios de terceros en texto claro o crackeable offline.",
        en: "A config/credential file (.env, .htpasswd, web.config) is served verbatim instead of being blocked. Bind the body to that exact URL and confirm the expected pattern before closing. Direct impact: application, database or third-party credentials in the clear or offline-crackable.",
      },
      exec: {
        es: "Archivo de configuración/credenciales accesible por HTTP. Acción inmediata: retirarlo del document root y rotar cualquier secreto que contuviera.",
        en: "Config/credential file accessible over HTTP. Immediate: remove from the document root and rotate any secret it held.",
      },
      steps: {
        es: [
          "Reproducir el GET exacto y adjuntar código HTTP + excerpt redactado del cuerpo como evidencia.",
          "Sacar el fichero del document root o denegarlo por configuración del servidor web (nginx/Apache/IIS).",
          "Rotar de inmediato toda credencial/clave que apareciera en el cuerpo.",
          "Añadir el patrón a un test de regresión (esperar 403/404) en el pipeline de despliegue.",
        ],
        en: [
          "Reproduce the exact GET; attach status and a redacted body excerpt as evidence.",
          "Remove the file from the document root or deny it via the web server config.",
          "Rotate any credential/secret found in the body immediately.",
          "Add a regression test (expect 403/404) to the deploy pipeline.",
        ],
      },
      refs: [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
    },
    {
      re: /Swagger\/OpenAPI expuesta|Actuator \/env expuesto|Panel phpMyAdmin accesible/i,
      cwe: ["CWE-200", "CWE-538"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [
        { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
        { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
      ],
      gdpr: ["Art. 32", "Art. 25 (privacidad desde el diseño)"],
      iso: ["A.8.9 Gestión de la configuración", "A.8.27 Arquitectura de sistemas segura"],
      ens: "Medio (Alto si filtra credenciales)",
      nis2: "Art. 21.2.a — políticas de análisis de riesgos y seguridad de sistemas",
      kill: "Reconnaissance",
      impact: { confidentiality: "medium", integrity: "low", availability: "low" },
      narrative: {
        es: "Un panel administrativo o endpoint de introspección (Swagger/OpenAPI, Spring Boot Actuator /env, phpMyAdmin) queda accesible sin restricción de red ni autenticación. Por sí solo ya amplía la superficie de ataque conocida por un atacante (mapa completo de la API, variables de entorno del proceso, o acceso directo a la consola de base de datos); combinado con credenciales por defecto o débiles, se convierte en compromiso directo.",
        en: "An admin panel or introspection endpoint (Swagger/OpenAPI, Spring Boot Actuator /env, phpMyAdmin) is reachable without network restriction or auth. Alone it widens the known attack surface; combined with weak/default credentials it becomes a direct compromise.",
      },
      exec: {
        es: "Panel/endpoint de administración o introspección expuesto sin restricción. Restringir por red (IP allow-list/VPN) y exigir autenticación; deshabilitar en producción si no es imprescindible.",
        en: "Admin/introspection endpoint exposed without restriction. Restrict by network and require auth; disable in production if not essential.",
      },
      steps: {
        es: [
          "Confirmar el cuerpo real de la respuesta (JSON de swagger/openapi, propertySources de actuator, HTML de phpMyAdmin).",
          "Restringir por IP allow-list o VPN; exigir autenticación adicional (SSO, roles de Spring Security).",
          "Deshabilitar el endpoint en producción si no aporta valor operativo (management.endpoints.web.exposure en Spring).",
          "Si el endpoint filtró credenciales (actuator/env), rotarlas de inmediato.",
        ],
        en: [
          "Confirm the actual response body (swagger/openapi JSON, actuator propertySources, phpMyAdmin HTML).",
          "Restrict by IP allow-list or VPN; require additional auth (SSO, Spring Security roles).",
          "Disable the endpoint in production if it adds no operational value.",
          "If credentials leaked (actuator/env), rotate them immediately.",
        ],
      },
      refs: [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
    },
    {
      re: /CORS: .*Origin/i,
      cwe: ["CWE-942"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" }],
      gdpr: ["Art. 32", "Art. 5.1.f"],
      iso: ["A.8.26 Seguridad en desarrollo", "A.8.9 Gestión de la configuración"],
      ens: "Alto",
      nis2: "Art. 21.2.e — seguridad en la adquisición y desarrollo",
      kill: "Exploitation",
      impact: { confidentiality: "high", integrity: "low", availability: "low" },
      narrative: {
        es: "El servidor refleja el header Origin recibido en Access-Control-Allow-Origin (o combina un comodín * con Access-Control-Allow-Credentials: true) en lugar de validarlo contra una lista blanca de orígenes de confianza. Cualquier sitio, incluido uno controlado por un atacante, puede así realizar peticiones autenticadas (con cookies de sesión) al servicio y leer la respuesta desde JavaScript: es el equivalente a desactivar la política de mismo origen para ese endpoint.",
        en: "The server reflects the received Origin header into Access-Control-Allow-Origin (or combines wildcard * with Access-Control-Allow-Credentials: true) instead of validating against a trusted allow-list. Any site, including an attacker-controlled one, can then make authenticated requests and read the response from JavaScript.",
      },
      exec: {
        es: "Mala configuración CORS: el servicio confía en el Origin recibido en vez de validarlo. Riesgo de robo de datos autenticados cross-origin. Prioridad alta: implementar allow-list estricta en servidor.",
        en: "CORS misconfiguration: the service trusts the received Origin instead of validating it. High risk of cross-origin authenticated data theft. Priority: implement a strict server-side allow-list.",
      },
      steps: {
        es: [
          "Reproducir con curl -H \"Origin: https://dominio-no-confiable\" y confirmar el reflejo en Access-Control-Allow-Origin.",
          "Sustituir el reflejo por una allow-list explícita de orígenes de confianza en el servidor.",
          "Nunca combinar Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true.",
          "Añadir un test de regresión que envíe un Origin no confiable y espere que NO se refleje.",
        ],
        en: [
          "Reproduce with curl -H \"Origin: https://untrusted-domain\" and confirm the reflection.",
          "Replace the reflection with an explicit server-side allow-list.",
          "Never combine wildcard * with Access-Control-Allow-Credentials: true.",
          "Add a regression test sending an untrusted Origin and expecting no reflection.",
        ],
      },
      refs: [{ label: "HackTricks — CORS Misconfigurations & Bypass", href: HT + "cors-bypass.html" }],
    },
    {
      re: /método HTTP TRACE habilitado|Cross-Site Tracing/i,
      cwe: ["CWE-16", "CWE-200"],
      owasp: "A05:2021 Security Misconfiguration",
      mitre: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" }],
      gdpr: ["Art. 32"],
      iso: ["A.8.9 Gestión de la configuración"],
      ens: "Medio",
      nis2: "Art. 21.2.a — políticas de análisis de riesgos y seguridad de sistemas",
      kill: "Exploitation",
      impact: { confidentiality: "medium", integrity: "low", availability: "low" },
      narrative: {
        es: "El método HTTP TRACE está habilitado: el servidor devuelve en el cuerpo de la respuesta la petición completa, incluidas cabeceras que el navegador normalmente oculta a JavaScript (cookies con flag HttpOnly). No es explotable en solitario, pero combinado con un XSS en el mismo origen permite leer esas cookies vía XMLHttpRequest a TRACE (Cross-Site Tracing), saltándose la protección HttpOnly.",
        en: "The HTTP TRACE method is enabled: the server echoes the full request, including headers normally hidden from JavaScript (HttpOnly cookies). Not exploitable alone, but combined with a same-origin XSS it enables Cross-Site Tracing, bypassing HttpOnly.",
      },
      exec: {
        es: "Método TRACE habilitado en el servidor web. Riesgo medio en solitario, alto si coexiste con XSS. Deshabilitar TRACE/TRACK en la configuración del servidor.",
        en: "TRACE method enabled on the web server. Medium risk alone, high if an XSS coexists. Disable TRACE/TRACK in the server config.",
      },
      steps: {
        es: [
          "Confirmar con curl -i -X TRACE que el cuerpo de la respuesta refleja la petición.",
          "Deshabilitar los métodos TRACE y TRACK (Apache: TraceEnable Off; IIS: HTTP Verbs; nginx no los soporta por defecto).",
          "Revisar si existe algún XSS en el mismo origen que pudiera encadenarse con este hallazgo.",
          "Verificar que solo los métodos HTTP necesarios (GET/POST/HEAD, etc.) están permitidos.",
        ],
        en: [
          "Confirm with curl -i -X TRACE that the response body echoes the request.",
          "Disable TRACE/TRACK (Apache: TraceEnable Off; restrict allowed verbs on IIS).",
          "Check for any same-origin XSS that could chain with this finding.",
          "Verify only the necessary HTTP methods are allowed.",
        ],
      },
      refs: [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
    },
  ];

  function sevKey(sev) {
    var s = String(sev || "info").toLowerCase();
    if (CVSS[s]) return s;
    return "info";
  }

  function looksLikeServerIpLeak(f) {
    var blob = ((f && f.title) || "") + " " + ((f && f.description) || "");
    if (!/cabecera Server|Server header|versi[oó]n en cabecera|revela direcci[oó]n IP/i.test(blob)) return false;
    if (/(apache|nginx|microsoft-iis|litespeed|openresty|tomcat)\/\d/i.test(blob)) return false;
    var m = blob.match(/«\s*(\d{1,3}(?:\.\d{1,3}){3})\s*»/);
    return !!(m && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(m[1]));
  }

  function matchCatalog(f) {
    if (looksLikeServerIpLeak(f)) {
      var ipCat = null;
      CATALOG.forEach(function (c) { if (c.id === "server-ip") ipCat = c; });
      if (ipCat) return ipCat;
    }
    var title = (f && f.title) || "";
    var blob = title + " " + ((f && f.description) || "");
    var i;
    for (i = 0; i < CATALOG.length; i++) {
      if (CATALOG[i].re.test(title)) return CATALOG[i];
    }
    for (i = 0; i < CATALOG.length; i++) {
      if (CATALOG[i].re.test(blob)) return CATALOG[i];
    }
    return null;
  }

  function genericNarrative(f) {
    var title = (f && f.title) || L("Hallazgo", "Finding");
    var desc = (f && f.description) || "";
    var rem = (f && f.remediation) || "";
    return {
      cwe: ["CWE-1035"],
      owasp: "OWASP Top 10 (clasificación a confirmar con evidencia)",
      mitre: [{ id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" }],
      gdpr: ["Art. 32 — seguridad del tratamiento (evaluación caso a caso)"],
      iso: ["A.8.8 Gestión de vulnerabilidades técnicas"],
      ens: L("Según criticidad del activo", "Per asset classification"),
      nis2: "Art. 21 — medidas técnicas y organizativas",
      kill: "Exploitation",
      impact: { confidentiality: "medium", integrity: "medium", availability: "low" },
      narrative: {
        es: "El motor registró «" + title + "». La evidencia bruta del playbook es: " + (desc || "sin cuerpo") + ". Este dossier amplía el hallazgo a lenguaje de gobierno: qué significa para confidencialidad/integridad/disponibilidad, qué normas toca y qué hay que hacer. No sustituye la validación manual: hay que atar cada afirmación a un código HTTP, una cookie o un volcado de herramienta.",
        en: "The engine recorded «" + title + "». Raw evidence: " + (desc || "none") + ". This dossier maps it to governance language. Bind every claim to HTTP status, cookies or tool output.",
      },
      exec: {
        es: (desc || title) + (rem ? " Remediación inicial: " + rem : ""),
        en: (desc || title) + (rem ? " Initial remediation: " + rem : ""),
      },
      steps: {
        es: [
          rem || "Aplicar la remediación indicada por el motor.",
          "Reproducir la evidencia (misma URL, mismos headers).",
          "Asignar owner y fecha SLA según criticidad.",
          "Verificar el cierre y adjuntar prueba (código HTTP / captura).",
        ],
        en: [
          rem || "Apply the engine remediation.",
          "Reproduce evidence (same URL and headers).",
          "Assign owner and SLA by severity.",
          "Verify closure with proof.",
        ],
      },
      refs: [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
    };
  }

  function enrich(f) {
    var cat = matchCatalog(f) || genericNarrative(f);
    var sk = sevKey(f && f.severity);
    var vector = cat.cvssVector || (CVSS[sk] && CVSS[sk].vector) || CVSS.info.vector;
    var cv = cvssFromVector(vector);
    var hours = SLA[sk];
    var lg = lang();
    return {
      finding: f,
      severity: sk,
      cvss: cv,
      slaHours: hours,
      slaLabel: hours <= 24 ? L("24 horas", "24 hours") : hours <= 168 ? L("7 días", "7 days") : hours <= 720 ? L("30 días", "30 days") : L("90 días", "90 days"),
      cwe: cat.cwe,
      owasp: cat.owasp,
      mitre: cat.mitre,
      gdpr: cat.gdpr,
      iso: cat.iso,
      ens: cat.ens,
      nis2: cat.nis2,
      kill: cat.kill,
      impact: cv.impact,
      narrative: lg === "en" ? cat.narrative.en : cat.narrative.es,
      exec: lg === "en" ? cat.exec.en : cat.exec.es,
      steps: lg === "en" ? cat.steps.en : cat.steps.es,
      engineDescription: (f && f.description) || "",
      engineRemediation: (f && f.remediation) || "",
      refs: cat.refs || [{ label: "HackTricks", href: "https://hacktricks.wiki/en/index.html" }],
      gov: pickGov(cat),
    };
  }

  function bar(pct, tone) {
    var color = tone === "error" ? "#ba1a1a" : tone === "tertiary" ? "#0a8575" : "#0078d4";
    var w = Math.max(0, Math.min(100, Math.round((pct || 0) * 100)));
    return (
      '<div class="h-1.5 rounded-full bg-surface-variant overflow-hidden">' +
      '<div style="width:' + w + "%;background:" + color + '" class="h-full rounded-full"></div></div>'
    );
  }

  function graphSvg(d, esc) {
    var asset = String((d.finding && d.finding.asset) || "asset");
    var title = String((d.finding && d.finding.title) || "finding");
    if (title.length > 22) title = title.slice(0, 20) + "…";
    if (asset.length > 22) asset = asset.slice(0, 20) + "…";
    asset = esc(asset);
    title = esc(title);
    var impactTop = L("Impacto", "Impact");
    var impactSub = L("datos / sesión", "data / session");
    var markerId = "ds-arr-" + String((d.finding && d.finding.id) || "g").replace(/[^a-zA-Z0-9_-]/g, "");
    function node(x, fill, stroke, line1, line2, c1, c2) {
      return (
        '<rect x="' + x + '" y="36" width="140" height="56" rx="8" fill="' + fill + '" stroke="' + stroke + '"/>' +
        '<text x="' + (x + 70) + '" y="58" text-anchor="middle" font-size="11" font-family="Public Sans, sans-serif" fill="' + (c1 || "#181c1f") + '">' + line1 + "</text>" +
        '<text x="' + (x + 70) + '" y="76" text-anchor="middle" font-size="10" font-family="Public Sans, sans-serif" fill="' + (c2 || "#404752") + '">' + line2 + "</text>"
      );
    }
    function arrow(x1, x2) {
      return '<line x1="' + x1 + '" y1="64" x2="' + x2 + '" y2="64" stroke="#717783" marker-end="url(#' + markerId + ')"/>';
    }
    return (
      '<svg viewBox="0 0 680 128" class="w-full h-32" role="img" aria-label="' +
      esc(L("Grafo del hallazgo", "Finding graph")) + '">' +
      '<defs><marker id="' + markerId + '" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#717783"/></marker></defs>' +
      node(8, "#d3e3ff", "#0078d4", "Internet", L("atacante", "attacker"), "#001c39", "#004883") +
      arrow(148, 178) +
      node(180, "#ebeef2", "#c0c7d4", asset, L("activo", "asset"), "#181c1f", "#404752") +
      arrow(320, 350) +
      node(352, "#ffdad6", "#ba1a1a", title, L("hallazgo", "finding"), "#93000a", "#404752") +
      arrow(492, 522) +
      node(524, "#91f4e1", "#0a8575", impactTop, impactSub, "#00201b", "#005046") +
      "</svg>"
    );
  }

  function render(root, f, opts) {
    opts = opts || {};
    var esc = opts.escapeHtml || function (s) { return String(s || "").replace(/[<>&]/g, ""); };
    var rel = opts.relativeTime || function () { return "—"; };
    var d = enrich(f);
    if (!d.gov) d.gov = GOV.misconfig;
    var qScan = opts.scanId ? ("&scan=" + encodeURIComponent(opts.scanId)) : "";
    var qScanOnly = opts.scanId ? ("?scan=" + encodeURIComponent(opts.scanId)) : "";
    var id = encodeURIComponent(f.id || "");
    var metrics = [
      { label: L("Confidencialidad", "Confidentiality"), v: d.impact.confidentiality },
      { label: L("Integridad", "Integrity"), v: d.impact.integrity },
      { label: L("Disponibilidad", "Availability"), v: d.impact.availability },
    ];
    function impactPct(v) {
      if (v === "high") return 1;
      if (v === "medium") return 0.55;
      if (v === "low") return 0.22;
      return 0;
    }
    var m = d.cvss.metrics || parseCvssVector(d.cvss.vector);
    var avLab = { N: L("Red", "Network"), A: L("Adyacente", "Adjacent"), L: L("Local", "Local"), P: L("Físico", "Physical") };
    var acLab = { L: L("Baja", "Low"), H: L("Alta", "High") };
    var prLab = { N: L("Ninguno", "None"), L: L("Bajos", "Low"), H: L("Altos", "High") };
    var ciaLab = { H: "HIGH", L: "LOW", N: "NONE" };
    var cvssDims = [
      { label: L("Vector de ataque", "Attack vector"), text: avLab[m.AV] || m.AV, v: d.cvss.av },
      { label: L("Complejidad", "Attack complexity"), text: acLab[m.AC] || m.AC, v: d.cvss.ac },
      { label: L("Privilegios requeridos", "Privileges required"), text: prLab[m.PR] || m.PR, v: d.cvss.pr },
      { label: "C", text: ciaLab[m.C] || m.C, v: d.cvss.c },
      { label: "I", text: ciaLab[m.I] || m.I, v: d.cvss.i },
      { label: "A", text: ciaLab[m.A] || m.A, v: d.cvss.a },
    ];
    var stepsHtml = d.steps
      .map(function (s, i) {
        return (
          '<li class="flex gap-sm items-start"><span class="w-6 h-6 rounded-full bg-primary-container text-on-primary-container flex items-center justify-center font-label-md shrink-0">' +
          (i + 1) +
          "</span><span class=\"font-body-md text-on-surface\">" +
          esc(s) +
          "</span></li>"
        );
      })
      .join("");
    var chip = function (text, href) {
      var inner = esc(text);
      if (href) {
        return '<a href="' + href + '" class="px-sm py-xs rounded-full bg-primary-container/10 text-primary font-label-md hover:bg-primary-container/20">' + inner + "</a>";
      }
      return '<span class="px-sm py-xs rounded-full bg-surface-container-high font-label-md text-on-surface">' + inner + "</span>";
    };
    var mitreHtml = d.mitre
      .map(function (m) {
        return chip(m.id + " · " + m.name, "mitre.html" + (qScanOnly || "?scan=program"));
      })
      .join("");
    var gdprHtml = d.gdpr.map(function (g) { return chip(g, "gdpr-alignment.html" + qScanOnly); }).join("");
    var isoHtml = d.iso.map(function (g) { return chip(g); }).join("");
    var cweHtml = d.cwe.map(function (g) { return chip(g); }).join("");
    var matScore = d.severity === "critical" ? 22 : d.severity === "high" ? 38 : d.severity === "medium" ? 55 : 72;
    var matLabel = matScore < 40 ? L("Inicial", "Initial") : matScore < 60 ? L("Gestionado", "Managed") : L("Definido", "Defined");

    root.innerHTML =
      '<nav class="flex items-center font-body-sm text-on-surface-variant gap-xs mb-md flex-wrap">' +
      '<a class="hover:text-primary" href="index.html">Dashboard</a><i data-lucide="chevron-right" class="icon-sm"></i>' +
      '<a class="hover:text-primary" href="reporting.html">' + L("Informes", "Reporting") + "</a><i data-lucide=\"chevron-right\" class=\"icon-sm\"></i>" +
      '<span class="text-on-surface font-semibold font-mono-md">' + esc(f.id || "—") + "</span></nav>" +
      '<header class="glass-panel rounded-xl p-lg flex flex-col gap-md mb-md">' +
      '<div class="flex flex-col md:flex-row justify-between items-start gap-md">' +
      "<div><div class=\"flex items-center gap-sm mb-sm flex-wrap\">" +
      '<span class="font-mono-md text-secondary">' + esc(f.id || "—") + "</span>" +
      '<span class="px-2 py-0.5 rounded-full font-label-md text-label-md border ' + (opts.sevBadgeClass ? opts.sevBadgeClass(d.severity) : "") + '">' +
      esc(String(f.severity || "").toUpperCase()) +
      "</span>" +
      '<span class="px-2 py-0.5 rounded-full font-label-md bg-error/10 text-error">CVSS ' + d.cvss.score.toFixed(1) + "</span>" +
      '<span class="px-2 py-0.5 rounded-full font-label-md bg-surface-container-high">' + esc(d.kill) + "</span></div>" +
      '<h1 class="font-headline-xl text-headline-xl text-on-surface">' + esc(f.title || L("Hallazgo", "Finding")) + "</h1>" +
      '<p class="font-mono-md text-on-surface-variant mt-xs">' + esc(f.asset || "—") + " · " + esc(f.status || "proposed") + " · " + esc(rel(f.created_at)) + "</p></div>" +
      '<div class="flex flex-wrap gap-sm">' +
      '<a href="remediation-detail.html?finding=' + id + '" class="px-md py-sm rounded-lg bg-primary-container text-on-primary-container hover:bg-primary font-label-md flex items-center gap-xs"><i data-lucide="wrench" class="icon-sm"></i> ' + L("Remediar", "Remediate") + "</a>" +
      '<a href="attack-graph.html' + qScanOnly + '" class="px-md py-sm rounded-lg border border-outline-variant font-label-md flex items-center gap-xs"><i data-lucide="share-2" class="icon-sm"></i> ' + L("Grafo", "Graph") + "</a>" +
      '<a href="graph-evidence.html' + qScanOnly + (qScanOnly ? "&" : "?") + "finding=" + id + '" class="px-md py-sm rounded-lg border border-outline-variant font-label-md flex items-center gap-xs"><i data-lucide="waypoints" class="icon-sm"></i> ' + L("Evidencia grafo", "Graph evidence") + "</a>" +
      "</div></div>" +
      '<nav class="flex flex-wrap gap-xs pt-sm border-t border-outline-variant/30">' +
      [["#ds-exec", L("Ejecutivo", "Executive")], ["#ds-cvss", L("Criticidad", "Criticality")], ["#ds-tech", L("Técnico", "Technical")], ["#ds-mitre", "MITRE"], ["#ds-gov", L("Gobernanza", "Governance")], ["#ds-graph", L("Grafo", "Graph")], ["#ds-plan", L("Plan", "Plan")], ["#ds-metrics", L("Métricas", "Metrics")]].map(function (a) {
        return '<a href="' + a[0] + '" class="px-sm py-xs rounded font-label-md text-primary hover:bg-primary-container/10">' + a[1] + "</a>";
      }).join("") +
      "</nav></header>" +
      '<section id="ds-exec" class="glass-panel rounded-xl p-lg mb-md">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="briefcase" class="text-primary"></i> ' + L("Resumen ejecutivo", "Executive summary") + "</h2>" +
      '<p class="font-body-lg text-on-surface leading-relaxed">' + esc(d.exec) + "</p>" +
      '<p class="font-body-md text-on-surface-variant mt-md leading-relaxed">' +
      L("SLA de remediación recomendado: ", "Recommended remediation SLA: ") +
      "<strong>" + d.slaLabel + "</strong>. " +
      L("Este hallazgo degrada la madurez del control hacia «", "This finding pulls control maturity toward «") +
      esc(matLabel) +
      L("». Debe figurar en el plan de remediación y, si hay datos personales, en la evaluación Art. 32 RGPD.", "». It belongs on the remediation plan and, if personal data is in scope, in the Art. 32 GDPR assessment.") +
      "</p></section>" +
      '<div class="grid grid-cols-1 lg:grid-cols-3 gap-md mb-md">' +
      '<section id="ds-cvss" class="glass-panel rounded-xl p-lg lg:col-span-1">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="gauge" class="text-error"></i> ' + L("Criticidad", "Criticality") + "</h2>" +
      '<p class="font-headline-xl text-headline-xl text-error">' + d.cvss.score.toFixed(1) + ' <span class="font-body-sm text-on-surface-variant">CVSS 3.1</span></p>' +
      '<p class="font-mono-md text-[11px] text-on-surface-variant break-all mt-xs mb-md">' + esc(d.cvss.vector) + "</p>" +
      cvssDims.map(function (x) {
        return '<div class="mb-sm"><div class="flex justify-between font-label-md text-on-surface-variant mb-xs"><span>' + esc(x.label) + "</span><span>" + esc(x.text) + "</span></div>" + bar(x.v, x.v > 0.7 ? "error" : "primary") + "</div>";
      }).join("") +
      '<div class="mt-md pt-md border-t border-outline-variant/30">' +
      metrics.map(function (m) {
        return '<div class="mb-sm"><div class="flex justify-between font-label-md mb-xs"><span>' + esc(m.label) + "</span><span class=\"uppercase\">" + esc(m.v) + "</span></div>" + bar(impactPct(m.v), m.v === "high" ? "error" : "tertiary") + "</div>";
      }).join("") +
      "</div></section>" +
      '<section id="ds-tech" class="glass-panel rounded-xl p-lg lg:col-span-2">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="file-text" class="text-primary"></i> ' + L("Análisis técnico argumentado", "Technical analysis") + "</h2>" +
      '<p class="font-body-md text-on-surface leading-relaxed whitespace-pre-wrap">' + esc(d.narrative) + "</p>" +
      (d.engineDescription
        ? '<div class="mt-md p-md rounded-lg bg-surface-container-low"><p class="font-label-md text-secondary uppercase mb-xs">' + L("Evidencia del motor", "Engine evidence") + "</p><p class=\"font-body-sm text-on-surface-variant whitespace-pre-wrap\">" + esc(d.engineDescription) + "</p></div>"
        : "") +
      '<div class="flex flex-wrap gap-xs mt-md">' + cweHtml + chip(d.owasp) + "</div>" +
      (d.refs && d.refs.length
        ? '<p class="font-label-md text-secondary uppercase mt-md mb-xs">' + L("Referencias de clase (no son PoC)", "Class references (not PoCs)") + "</p><div class=\"flex flex-wrap gap-xs\">" +
          d.refs.map(function (r) {
            return '<a class="px-sm py-xs rounded-full bg-primary-container/10 text-primary font-label-md hover:underline" href="' + esc(r.href) + '" target="_blank" rel="noopener noreferrer">' + esc(r.label) + "</a>";
          }).join("") +
          "</div>"
        : "") +
      "</section></div>" +
      '<div class="grid grid-cols-1 lg:grid-cols-2 gap-md mb-md">' +
      '<section id="ds-mitre" class="glass-panel rounded-xl p-lg">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="swords" class="text-primary"></i> MITRE ATT&CK</h2>' +
      '<p class="font-body-sm text-on-surface-variant mb-md">' + L("Técnicas observadas o plausibles a partir de este hallazgo. La matriz completa está en MITRE ATT&CK.", "Techniques observed or plausible from this finding. Full matrix is under MITRE ATT&CK.") + "</p>" +
      '<div class="flex flex-wrap gap-xs">' + mitreHtml + "</div>" +
      '<p class="font-body-sm text-on-surface-variant mt-md">' + L("Fase de kill chain: ", "Kill-chain stage: ") + "<strong>" + esc(d.kill) + "</strong></p>" +
      '<a class="inline-flex items-center gap-xs font-label-md text-primary mt-sm hover:underline" href="kill-chain.html' + qScanOnly + '"><i data-lucide="link" class="icon-sm"></i> ' + L("Ver cadena de ataque del análisis", "View scan kill chain") + "</a></section>" +
      '<section id="ds-gov" class="glass-panel rounded-xl p-lg">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="scale" class="text-primary"></i> ' + L("Gobernanza y cumplimiento", "Governance & compliance") + "</h2>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' + L("Molde de ficha GRC: obligación, hueco, riesgo AEPD, impacto de negocio y plan 30/60/90. Los techos 83.4/83.5 son el máximo de la norma, no una multa calculada para este activo.", "GRC card: duty, gap, DPA risk, business impact and 30/60/90 plan. 83.4/83.5 ceilings are the legal maximum, not a calculated fine for this asset.") + "</p>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Categoría", "Category") + "</p>" +
      '<p class="font-body-md text-on-surface mb-md">' + esc(loc(d.gov.category)) + "</p>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">RGPD</p><div class="flex flex-wrap gap-xs mb-md">' + gdprHtml + "</div>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">ISO 27001:2022</p><div class="flex flex-wrap gap-xs mb-md">' + isoHtml + d.gov.iso.map(function (g) { return chip(g); }).join("") + "</div>" +
      '<dl class="font-body-sm space-y-sm mb-md">' +
      "<div><dt class=\"text-on-surface-variant\">" + L("Base legal", "Legal basis") + "</dt><dd class=\"text-on-surface\">" + esc(loc(d.gov.legalBase)) + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">" + L("Tramo sancionador", "Sanction tier") + "</dt><dd class=\"text-on-surface\"><strong>" + esc(d.gov.sanction.art) + "</strong> — " + esc(loc(d.gov.sanction)) + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">ENS</dt><dd class=\"text-on-surface\">" + esc(loc(d.gov.ens) || d.ens) + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">NIS2</dt><dd class=\"text-on-surface\">" + esc(loc(d.gov.nis2) || d.nis2) + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">" + L("Madurez implicada", "Maturity pull") + "</dt><dd class=\"text-on-surface\">" + esc(matLabel) + " (" + matScore + "/100) · " + L("un hallazgo crítico/alto tira el índice hacia Inicial, como 2.5/10 en un SGSI inmaduro.", "a critical/high finding pulls the index toward Initial, like 2.5/10 on an immature ISMS.") + "</dd></div></dl>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Obligación legal", "Legal duty") + "</p>" +
      '<p class="font-body-sm text-on-surface mb-md leading-relaxed">' + esc(loc(d.gov.obligation)) + "</p>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Qué vería la AEPD", "What the DPA would see") + "</p>" +
      '<p class="font-body-sm text-on-surface mb-md leading-relaxed">' + esc(loc(d.gov.aepd)) + "</p>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Impacto de negocio", "Business impact") + "</p>" +
      '<div class="grid grid-cols-2 gap-sm mb-md font-body-sm">' +
      [["Operativo", "Operational", d.gov.business.operational], ["Reputacional", "Reputational", d.gov.business.reputational], ["Legal", "Legal", d.gov.business.legal], ["€", "€", d.gov.business.economic]].map(function (row) {
        var tone = row[2] === "Alto" || row[2] === "High" ? "text-error" : row[2] === "Medio" || row[2] === "Medium" ? "text-tertiary" : "text-on-surface-variant";
        return '<div class="rounded-lg bg-surface-container-low p-sm"><p class="font-label-md text-on-surface-variant">' + L(row[0], row[1]) + '</p><p class="font-headline-md ' + tone + '">' + esc(row[2]) + "</p></div>";
      }).join("") +
      "</div>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Qué le cuesta a la empresa", "What it costs the company") + "</p>" +
      '<p class="font-body-sm text-on-surface mb-sm leading-relaxed"><strong>' + L("Cerrar ahora. ", "Fix now. ") + "</strong>" + esc(loc(d.gov.costFix)) + "</p>" +
      '<p class="font-body-sm text-on-surface mb-md leading-relaxed"><strong>' + L("Si escala a incidente. ", "If it becomes an incident. ") + "</strong>" + esc(loc(d.gov.costIncident)) + "</p>" +
      '<p class="font-label-md text-secondary uppercase mb-xs">' + L("Plan 30 / 60 / 90", "30 / 60 / 90 plan") + "</p>" +
      '<ol class="font-body-sm text-on-surface space-y-sm mb-md list-decimal pl-md">' +
      "<li><strong>0–30 d.</strong> " + esc(loc(d.gov.plan30)) + "</li>" +
      "<li><strong>30–60 d.</strong> " + esc(loc(d.gov.plan60)) + "</li>" +
      "<li><strong>60–90 d.</strong> " + esc(loc(d.gov.plan90)) + "</li></ol>" +
      '<div class="flex flex-wrap gap-sm mt-md">' +
      '<a class="font-label-md text-primary hover:underline" href="gdpr-alignment.html' + qScanOnly + '">RGPD</a>' +
      '<a class="font-label-md text-primary hover:underline" href="maturity-index.html' + qScanOnly + '">' + L("Matriz de riesgos", "Risk matrix") + "</a>" +
      '<a class="font-label-md text-primary hover:underline" href="executive-summary.html' + qScanOnly + '">' + L("Resumen ejecutivo del análisis", "Scan executive summary") + "</a></div></section></div>" +
      '<section id="ds-graph" class="glass-panel rounded-xl p-lg mb-md">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="share-2" class="text-primary"></i> ' + L("Evidencia de grafo de esta vulnerabilidad", "Graph evidence for this vulnerability") + "</h2>" +
      '<p class="font-body-sm text-on-surface-variant mb-md">' + L("Camino de abuso resumido: red → activo → hallazgo → impacto. Ábrelo en Attack Graph para el mapa del engagement.", "Abuse path: network → asset → finding → impact. Open Attack Graph for the full engagement map.") + "</p>" +
      graphSvg(d, esc) +
      '<a class="inline-flex items-center gap-xs font-label-md text-primary mt-sm hover:underline" href="attack-graph.html' + qScanOnly + '"><i data-lucide="arrow-up-right" class="icon-sm"></i> Attack Graph</a></section>' +
      '<div class="grid grid-cols-1 lg:grid-cols-3 gap-md mb-md">' +
      '<section id="ds-plan" class="glass-panel rounded-xl p-lg lg:col-span-2 border-l-4 border-l-tertiary">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="list-checks" class="text-tertiary"></i> ' + L("Plan de remediación explicado", "Remediation plan") + "</h2>" +
      (d.engineRemediation
        ? '<p class="font-body-md text-on-surface-variant mb-md">' + L("Indicación del motor: ", "Engine hint: ") + esc(d.engineRemediation) + "</p>"
        : "") +
      "<ol class=\"space-y-sm\">" + stepsHtml + "</ol>" +
      '<a class="inline-flex items-center gap-xs font-label-md text-primary mt-md hover:underline" href="remediation-plan.html' + qScanOnly + '"><i data-lucide="list-checks" class="icon-sm"></i> ' + L("Plan del análisis completo", "Full scan remediation plan") + "</a></section>" +
      '<section id="ds-metrics" class="glass-panel rounded-xl p-lg">' +
      '<h2 class="font-headline-md text-on-surface flex items-center gap-xs mb-md"><i data-lucide="timer" class="text-primary"></i> ' + L("Métricas de remediación", "Remediation metrics") + "</h2>" +
      '<dl class="space-y-md font-body-sm">' +
      "<div><dt class=\"text-on-surface-variant\">SLA</dt><dd class=\"font-headline-md text-on-surface\">" + d.slaLabel + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">MTTR " + L("objetivo", "target") + "</dt><dd class=\"font-headline-md text-on-surface\">" + d.slaHours + " h</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">" + L("Esfuerzo estimado", "Estimated effort") + "</dt><dd class=\"text-on-surface\">" + (d.severity === "critical" || d.severity === "high" ? L("4–16 h ingeniería", "4–16 h engineering") : L("1–4 h", "1–4 h")) + "</dd></div>" +
      "<div><dt class=\"text-on-surface-variant\">" + L("Owner sugerido", "Suggested owner") + "</dt><dd class=\"text-on-surface\">" + L("AppSec / plataforma web", "AppSec / web platform") + "</dd></div></dl>" +
      '<a class="inline-flex items-center gap-xs font-label-md text-primary mt-md hover:underline" href="remediation-metrics.html' + qScanOnly + '"><i data-lucide="gauge" class="icon-sm"></i> ' + L("Métricas del programa", "Program metrics") + "</a>" +
      '<a href="remediation-detail.html?finding=' + id + qScan + '" class="mt-md block text-center py-sm rounded-lg bg-primary-container text-on-primary-container font-label-md">' + L("Abrir ticket de remediación", "Open remediation ticket") + "</a></section></div>" +
      '<p class="text-center pb-lg"><a href="critical-findings.html' + qScanOnly + '" class="font-label-md text-primary hover:underline">← ' + L("Volver a hallazgos críticos", "Back to critical findings") + "</a></p>";

    if (global.lucide) global.lucide.createIcons();
  }

  global.DarkSpearDossier = { enrich: enrich, render: render };
})(window);
