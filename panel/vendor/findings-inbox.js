(function () {
  var STORAGE = "ds-findings-inbox";
  var READ_KEY = "ds-findings-read";
  var TOKEN_KEY = "ds-engine-token";
  var URL_KEY = "ds-engine-url";
  var ENGINE_DEFAULT = "http://127.0.0.1:8420";

  function t(key, fallback) {
    if (window.DarkSpear && DarkSpear.t) {
      var v = DarkSpear.t(key);
      if (v && v !== key) return v;
    }
    return fallback;
  }

  function lang() {
    return (window.DarkSpear && DarkSpear.lang && DarkSpear.lang()) || localStorage.getItem("ds-lang") || "es";
  }

  function fingerprint(title, asset) {
    var blob = ((title || "") + " " + (asset || "")).toLowerCase();
    if ((/cookie|session/).test(blob) && /security|httponly|secure|low/.test(blob)) {
      return "cookie-session:" + (asset || "").toLowerCase();
    }
    var words = blob.replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/)
      .filter(function (w) { return w.length > 3; })
      .sort()
      .slice(0, 6);
    if (words.length) return words.join("-");
    return blob.slice(0, 48) || "finding";
  }

  function isNoise(f) {
    if (!f || !f.title) return true;
    if (f.status === "rejected") return true;
    var blob = ((f.title || "") + " " + (f.description || "") + " " + (f.remediation || "")).toLowerCase();
    if (/ollama_missing_tool|invalid_json|empty_content|agent_error|json only|follow the json/.test(blob)) return true;
    if (f.tool === "(agent)" || f.verdict === "agent_error") return true;
    return false;
  }

  function loadLocal() {
    try { return JSON.parse(sessionStorage.getItem(STORAGE) || "[]"); }
    catch (e) { return []; }
  }

  function saveLocal(items) {
    sessionStorage.setItem(STORAGE, JSON.stringify(items));
  }

  function loadRead() {
    try { return JSON.parse(sessionStorage.getItem(READ_KEY) || "[]"); }
    catch (e) { return []; }
  }

  function saveRead(ids) {
    sessionStorage.setItem(READ_KEY, JSON.stringify(ids));
  }

  function merge(existing, incoming) {
    var byFp = {};
    existing.concat(incoming).forEach(function (f) {
      if (isNoise(f)) return;
      var fp = f.fingerprint || fingerprint(f.title, f.asset);
      var prev = byFp[fp];
      if (!prev || (f.created_at || 0) >= (prev.created_at || 0)) {
        byFp[fp] = Object.assign({}, f, { fingerprint: fp });
      }
    });
    return Object.keys(byFp).map(function (k) { return byFp[k]; })
      .sort(function (a, b) { return (b.created_at || 0) - (a.created_at || 0); });
  }

  function push(finding) {
    var items = merge(loadLocal(), [finding]);
    saveLocal(items);
    updateBell();
    return items;
  }

  function captureTokenFromUrl() {
    var params = new URLSearchParams(location.search);
    var token = params.get("token");
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
  }

  function engineBase() {
    return sessionStorage.getItem(URL_KEY) || ENGINE_DEFAULT;
  }

  function fetchEngine() {
    captureTokenFromUrl();
    var token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) return Promise.resolve(loadLocal());
    return fetch(engineBase() + "/findings/list", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auditor-Token": token },
      body: "{}"
    }).then(function (res) {
      if (!res.ok) return loadLocal();
      return res.json();
    }).then(function (data) {
      var list = Array.isArray(data) ? data : (data && data.findings) || [];
      var merged = merge(loadLocal(), list);
      saveLocal(merged);
      updateBell();
      return merged;
    }).catch(function () {
      return loadLocal();
    });
  }

  function sevKey(severity) {
    var s = String(severity || "info").toLowerCase();
    if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
    return "info";
  }

  function sevMeta(sev) {
    if (sev === "critical") {
      return {
        border: "border-error",
        iconWrap: "bg-error-container",
        icon: "triangle-alert",
        iconColor: "text-error",
        badge: "bg-error/10 text-error",
        label: t("notif.critical", "Crítico")
      };
    }
    if (sev === "high") {
      return {
        border: "border-tertiary",
        iconWrap: "bg-tertiary-container/20",
        icon: "bug",
        iconColor: "text-tertiary",
        badge: "bg-tertiary-container/20 text-tertiary",
        label: t("notif.high", "Alto")
      };
    }
    if (sev === "medium") {
      return {
        border: "border-outline",
        iconWrap: "bg-surface-container-high",
        icon: "shield",
        iconColor: "text-secondary",
        badge: "bg-surface-variant text-on-surface",
        label: t("notif.medium", "Medio")
      };
    }
    if (sev === "low") {
      return {
        border: "border-outline",
        iconWrap: "bg-surface-container-high",
        icon: "shield",
        iconColor: "text-secondary",
        badge: "bg-surface-variant text-on-surface",
        label: t("notif.low", "Bajo")
      };
    }
    return {
      border: "border-primary",
      iconWrap: "bg-primary-container/15",
      icon: "circle-check",
      iconColor: "text-primary",
      badge: "bg-primary-container/15 text-primary",
      label: t("notif.info", "Info")
    };
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function relativeTime(ts) {
    if (!ts) return "";
    var sec = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    var en = lang() === "en";
    if (sec < 60) return en ? "just now" : "ahora";
    if (sec < 3600) {
      var m = Math.floor(sec / 60);
      return en ? m + " min ago" : "hace " + m + " min";
    }
    if (sec < 86400) {
      var h = Math.floor(sec / 3600);
      return en ? h + " h ago" : "hace " + h + " h";
    }
    var d = Math.floor(sec / 86400);
    return en ? d + " d ago" : "hace " + d + " d";
  }

  function hrefFor(sev) {
    return sev === "critical" ? "critical-findings.html" : "finding-detail.html";
  }

  function unreadCount(items) {
    var read = loadRead();
    return (items || loadLocal()).filter(function (f) {
      return read.indexOf(f.id) === -1;
    }).length;
  }

  function updateBell() {
    var n = unreadCount();
    document.querySelectorAll('[data-i18n-aria="aria.notifications"] .bg-error').forEach(function (dot) {
      dot.classList.toggle("hidden", n === 0);
    });
  }

  function markAllRead() {
    saveRead(loadLocal().map(function (f) { return f.id; }));
    document.querySelectorAll(".notif-item").forEach(function (el) {
      el.classList.remove("unread");
    });
    updateBell();
  }

  function renderList(container, items, filter) {
    if (!container) return;
    var list = items || loadLocal();
    var sevFilter = filter || "all";
    var visible = list.filter(function (f) {
      return sevFilter === "all" || sevKey(f.severity) === sevFilter;
    });
    var read = loadRead();
    container.innerHTML = "";
    if (!visible.length) {
      var empty = document.createElement("div");
      empty.className = "glass-panel rounded-lg p-lg text-center";
      empty.innerHTML =
        '<i data-lucide="bell" class="icon-lg text-outline mx-auto mb-sm"></i>' +
        '<p class="font-headline-md text-on-surface" data-i18n="notif.empty">' +
        escapeHtml(t("notif.empty", "Todavía no hay hallazgos")) + "</p>" +
        '<p class="font-body-sm text-on-surface-variant mt-xs" data-i18n="notif.emptyLead">' +
        escapeHtml(t("notif.emptyLead", "Los hallazgos únicos del engagement aparecen aquí. El ruido del agente no se notifica.")) +
        "</p>";
      container.appendChild(empty);
      if (window.lucide) lucide.createIcons();
      return;
    }
    visible.forEach(function (f) {
      var sev = sevKey(f.severity);
      var meta = sevMeta(sev);
      var unread = read.indexOf(f.id) === -1;
      var a = document.createElement("a");
      a.className = "glass-panel rounded-lg p-md flex gap-md items-start border-l-4 " +
        meta.border + " hover:border-primary notif-item" + (unread ? " unread" : "");
      a.href = hrefFor(sev);
      a.setAttribute("data-sev", sev);
      a.setAttribute("data-finding-id", f.id || "");
      var body = (f.description || f.asset || "").slice(0, 220);
      a.innerHTML =
        '<div class="w-10 h-10 rounded-full ' + meta.iconWrap +
        ' flex items-center justify-center shrink-0"><i data-lucide="' + meta.icon +
        '" class="' + meta.iconColor + '"></i></div>' +
        '<div class="flex-1 min-w-0">' +
        '<div class="flex justify-between gap-sm">' +
        '<h3 class="font-semibold text-on-surface">' + escapeHtml(f.title) + "</h3>" +
        '<span class="font-mono-md text-[11px] text-on-surface-variant shrink-0">' +
        escapeHtml(relativeTime(f.created_at)) + "</span></div>" +
        '<p class="font-body-sm text-on-surface-variant mt-xs">' + escapeHtml(body) + "</p>" +
        '<span class="inline-flex mt-sm px-sm py-xs rounded font-label-md text-[10px] ' +
        meta.badge + '">' + escapeHtml(meta.label) + "</span></div>";
      container.appendChild(a);
    });
    if (window.lucide) lucide.createIcons();
  }

  function boot() {
    captureTokenFromUrl();
    updateBell();
    var list = document.getElementById("notif-list");
    fetchEngine().then(function (items) {
      updateBell();
      if (list) renderList(list, items, list.getAttribute("data-filter") || "all");
    });
  }

  window.DarkSpearFindings = {
    push: push,
    fetchEngine: fetchEngine,
    renderList: renderList,
    updateBell: updateBell,
    markAllRead: markAllRead,
    fingerprint: fingerprint,
    unreadCount: unreadCount,
    boot: boot
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
