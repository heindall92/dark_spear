(function () {
  var I18N = {
    es: {
      brand: "Dark Spear",
      "brand.tagline": "Consola SecOps",
      skip: "Saltar al contenido",
      "nav.dashboard": "Dashboard",
      "nav.metrics": "Métricas de remediación",
      "nav.engagement": "Engagement activo",
      "nav.scans": "Escaneos activos",
      "nav.vulns": "Vulnerabilidades",
      "nav.critical": "Hallazgos críticos",
      "nav.reporting": "Informes",
      "nav.osint": "OSINT",
      "nav.graph": "Grafo de ataque",
      "nav.mitre": "MITRE ATT&CK",
      "nav.assets": "Activos",
      "nav.newScan": "Nuevo escaneo",
      "nav.settings": "Ajustes",
      "nav.help": "Centro de ayuda",
      "nav.signOut": "Cerrar sesión",
      "search.placeholder": "Buscar hallazgos, activos o escaneos…",
      "aria.notifications": "Notificaciones",
      "aria.settings": "Ajustes",
      "aria.sidebarHide": "Retraer menú",
      "aria.sidebarShow": "Expandir menú",
      "chap.informe": "Informe",
      "chap.resumen": "Resumen",
      "chap.hallazgo": "Hallazgo",
      "chap.leyenda": "Leyenda",
      "chap.remediacion": "Remediación",
      "chap.rgpd": "RGPD",
      "chap.madurez": "Madurez",
      "chap.killchain": "Kill Chain",
      "settings.title": "Ajustes",
      "settings.lead": "Apariencia, idioma y preferencias de la organización.",
      "settings.appearance": "Apariencia e idioma",
      "settings.theme": "Tema",
      "settings.light": "Claro",
      "settings.dark": "Oscuro",
      "settings.english": "Inglés",
      "aria.themeSwitch": "Modo oscuro",
      "aria.langSwitch": "Idioma inglés",
      "settings.language": "Idioma",
      "settings.general": "General",
      "settings.security": "Seguridad",
      "settings.integrations": "Integraciones",
      "settings.notifications": "Notificaciones",
      "settings.team": "Equipo",
      "settings.profile": "Perfil general",
      "settings.logo": "Logo de la organización",
      "settings.logoHelp": "Tamaño recomendado: 256×256 px (PNG o JPG)",
      "settings.upload": "Subir nuevo",
      "settings.orgName": "Nombre de la organización",
      "settings.email": "Correo de soporte",
      "settings.tz": "Zona horaria",
      "settings.save": "Guardar cambios"
    },
    en: {
      brand: "Dark Spear",
      "brand.tagline": "SecOps Console",
      skip: "Skip to content",
      "nav.dashboard": "Dashboard",
      "nav.metrics": "Remediation Metrics",
      "nav.engagement": "Active Engagement",
      "nav.scans": "Active Scans",
      "nav.vulns": "Vulnerabilities",
      "nav.critical": "Critical Findings",
      "nav.reporting": "Reporting",
      "nav.osint": "OSINT",
      "nav.graph": "Attack Graph",
      "nav.mitre": "MITRE ATT&CK",
      "nav.assets": "Assets",
      "nav.newScan": "New Scan",
      "nav.settings": "Settings",
      "nav.help": "Help Center",
      "nav.signOut": "Sign Out",
      "search.placeholder": "Search findings, assets, or scans...",
      "aria.notifications": "Notifications",
      "aria.settings": "Settings",
      "aria.sidebarHide": "Collapse menu",
      "aria.sidebarShow": "Expand menu",
      "chap.informe": "Report",
      "chap.resumen": "Summary",
      "chap.hallazgo": "Finding",
      "chap.leyenda": "Legend",
      "chap.remediacion": "Remediation",
      "chap.rgpd": "GDPR",
      "chap.madurez": "Maturity",
      "chap.killchain": "Kill Chain",
      "settings.title": "Settings",
      "settings.lead": "Appearance, language, and organization preferences.",
      "settings.appearance": "Appearance and language",
      "settings.theme": "Theme",
      "settings.light": "Light",
      "settings.dark": "Dark",
      "settings.english": "English",
      "aria.themeSwitch": "Dark mode",
      "aria.langSwitch": "English language",
      "settings.language": "Language",
      "settings.general": "General",
      "settings.security": "Security",
      "settings.integrations": "Integrations",
      "settings.notifications": "Notifications",
      "settings.team": "Team Management",
      "settings.profile": "General Profile",
      "settings.logo": "Organization Logo",
      "settings.logoHelp": "Recommended size: 256×256px (PNG or JPG)",
      "settings.upload": "Upload New",
      "settings.orgName": "Organization Name",
      "settings.email": "Support Email",
      "settings.tz": "Default Time Zone",
      "settings.save": "Save Changes"
    }
  };

  var TITLES = {
    "index.html": { es: "Dark Spear — Dashboard", en: "Dark Spear — Dashboard" },
    "settings.html": { es: "Dark Spear — Ajustes", en: "Dark Spear — Settings" },
    "help-center.html": { es: "Dark Spear — Centro de ayuda", en: "Dark Spear — Help Center" },
    "engagement.html": { es: "Dark Spear — Engagement activo", en: "Dark Spear — Active Engagement" },
    "active-scans.html": { es: "Dark Spear — Escaneos activos", en: "Dark Spear — Active Scans" },
    "vulnerabilities.html": { es: "Dark Spear — Vulnerabilidades", en: "Dark Spear — Vulnerabilities" },
    "critical-findings.html": { es: "Dark Spear — Hallazgos críticos", en: "Dark Spear — Critical Findings" },
    "reporting.html": { es: "Dark Spear — Informes", en: "Dark Spear — Reporting" },
    "osint.html": { es: "Dark Spear — OSINT", en: "Dark Spear — OSINT" },
    "attack-graph.html": { es: "Dark Spear — Grafo de ataque", en: "Dark Spear — Attack Graph" },
    "mitre.html": { es: "Dark Spear — MITRE ATT&CK", en: "Dark Spear — MITRE ATT&CK" },
    "assets.html": { es: "Dark Spear — Activos", en: "Dark Spear — Assets" },
    "start-engagement.html": { es: "Dark Spear — Nuevo escaneo", en: "Dark Spear — New Scan" },
    "remediation-metrics.html": { es: "Dark Spear — Métricas de remediación", en: "Dark Spear — Remediation Metrics" },
    "executive-summary.html": { es: "Dark Spear — Resumen ejecutivo", en: "Dark Spear — Executive Summary" },
    "comprehensive-report.html": { es: "Dark Spear — Informe", en: "Dark Spear — Report" },
    "finding-detail.html": { es: "Dark Spear — Hallazgo", en: "Dark Spear — Finding" },
    "findings-summary.html": { es: "Dark Spear — Leyenda", en: "Dark Spear — Legend" },
    "remediation-plan.html": { es: "Dark Spear — Remediación", en: "Dark Spear — Remediation" },
    "gdpr-alignment.html": { es: "Dark Spear — RGPD", en: "Dark Spear — GDPR" },
    "maturity-index.html": { es: "Dark Spear — Madurez", en: "Dark Spear — Maturity" },
    "kill-chain.html": { es: "Dark Spear — Kill Chain", en: "Dark Spear — Kill Chain" },
    "graph-evidence.html": { es: "Dark Spear — Evidencia de grafo", en: "Dark Spear — Graph Evidence" },
    "remediation-detail.html": { es: "Dark Spear — Detalle de remediación", en: "Dark Spear — Remediation Detail" },
    "remediation-complete.html": { es: "Dark Spear — Remediación enviada", en: "Dark Spear — Remediation Submitted" },
    "verification-request.html": { es: "Dark Spear — Verificación", en: "Dark Spear — Verification" },
    "tool-approval.html": { es: "Dark Spear — Aprobación de herramienta", en: "Dark Spear — Tool Approval" },
    "report-preview.html": { es: "Dark Spear — Vista previa PDF", en: "Dark Spear — PDF Preview" },
    "profile.html": { es: "Dark Spear — Perfil", en: "Dark Spear — Profile" },
    "notifications.html": { es: "Dark Spear — Notificaciones", en: "Dark Spear — Notifications" }
  };

  function lang() {
    var l = localStorage.getItem("ds-lang") || "es";
    return l === "en" ? "en" : "es";
  }

  function theme() {
    var t = localStorage.getItem("ds-theme") || "light";
    return t === "dark" ? "dark" : "light";
  }

  function dict() {
    return I18N[lang()] || I18N.es;
  }

  function t(key) {
    var d = dict();
    return d[key] != null ? d[key] : key;
  }

  function applyI18n() {
    var d = dict();
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var key = el.getAttribute("data-i18n");
      if (d[key] != null) el.textContent = d[key];
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (el) {
      var key = el.getAttribute("data-i18n-placeholder");
      if (d[key] != null) el.setAttribute("placeholder", d[key]);
    });
    document.querySelectorAll("[data-i18n-aria]").forEach(function (el) {
      var key = el.getAttribute("data-i18n-aria");
      if (d[key] != null) el.setAttribute("aria-label", d[key]);
    });
    var page = location.pathname.split("/").pop() || "index.html";
    if (!page || page.indexOf(".html") === -1) page = "index.html";
    var titles = TITLES[page];
    if (titles) document.title = titles[lang()];
    document.documentElement.lang = lang();
    syncNavTitles();
    syncSidebarUi(false);
  }

  function applyTheme(next) {
    if (next !== "dark") next = "light";
    localStorage.setItem("ds-theme", next);
    document.documentElement.classList.remove("light", "dark");
    document.documentElement.classList.add(next);
    syncPrefsUi();
  }

  function applyLang(next) {
    if (next !== "en") next = "es";
    localStorage.setItem("ds-lang", next);
    document.documentElement.lang = next;
    applyI18n();
    if (window.lucide) lucide.createIcons();
    syncPrefsUi();
  }

  function syncPrefsUi() {
    var dark = theme() === "dark";
    var en = lang() === "en";
    document.querySelectorAll("[data-switch=\"theme\"]").forEach(function (el) {
      el.setAttribute("aria-checked", dark ? "true" : "false");
    });
    document.querySelectorAll("[data-switch=\"lang\"]").forEach(function (el) {
      el.setAttribute("aria-checked", en ? "true" : "false");
    });
  }

  function bindPrefs() {
    document.querySelectorAll("[data-switch=\"theme\"]").forEach(function (el) {
      el.addEventListener("click", function () {
        applyTheme(theme() === "dark" ? "light" : "dark");
      });
    });
    document.querySelectorAll("[data-switch=\"lang\"]").forEach(function (el) {
      el.addEventListener("click", function () {
        applyLang(lang() === "en" ? "es" : "en");
      });
    });
    syncPrefsUi();
  }

  function sidebarCollapsed() {
    return document.documentElement.classList.contains("sidebar-collapsed");
  }

  function syncNavTitles() {
    document.querySelectorAll("[data-app-nav] a").forEach(function (a) {
      var span = a.querySelector("span");
      if (span && span.textContent) a.setAttribute("title", span.textContent.trim());
    });
  }

  function syncSidebarUi(redrawIcons) {
    var collapsed = sidebarCollapsed();
    document.querySelectorAll("[data-sidebar-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
      btn.setAttribute("aria-label", collapsed ? t("aria.sidebarShow") : t("aria.sidebarHide"));
      var icon = btn.querySelector("[data-lucide]");
      if (icon) icon.setAttribute("data-lucide", collapsed ? "chevron-right" : "chevron-left");
    });
    if (redrawIcons !== false && window.lucide) lucide.createIcons();
  }

  function applySidebar(collapsed) {
    localStorage.setItem("ds-sidebar", collapsed ? "collapsed" : "expanded");
    document.documentElement.classList.toggle("sidebar-collapsed", !!collapsed);
    syncSidebarUi(true);
  }

  function bindSidebar() {
    document.querySelectorAll("[data-sidebar-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        applySidebar(!sidebarCollapsed());
      });
    });
    syncNavTitles();
    syncSidebarUi(false);
  }

  window.DarkSpear = {
    I18N: I18N,
    t: t,
    lang: lang,
    theme: theme,
    applyI18n: applyI18n,
    applyTheme: applyTheme,
    applyLang: applyLang,
    applySidebar: applySidebar,
    bindPrefs: bindPrefs
  };

  document.addEventListener("DOMContentLoaded", function () {
    applyI18n();
    bindPrefs();
    bindSidebar();
    if (window.lucide) lucide.createIcons();
  });
})();
