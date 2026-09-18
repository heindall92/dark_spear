#!/usr/bin/env node
/** Ajustes/Perfil → portada/export: persistencia v2, wipe de semillas, escape y payload. */
import { readFileSync } from "node:fs";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import vm from "node:vm";

const root = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

let fail = 0;
function check(cond, msg) {
  try {
    assert(cond, msg);
    console.log("ok ", msg);
  } catch (e) {
    fail += 1;
    console.error("FAIL", e.message);
  }
}

function memoryStorage() {
  const map = new Map();
  return {
    getItem(k) {
      return map.has(k) ? map.get(k) : null;
    },
    setItem(k, v) {
      map.set(String(k), String(v));
    },
    removeItem(k) {
      map.delete(k);
    },
    _map: map,
  };
}

function bootPrefs(localStorage) {
  const classList = {
    _c: new Set(["light"]),
    remove() {
      for (const a of arguments) this._c.delete(a);
    },
    add() {
      for (const a of arguments) this._c.add(a);
    },
    contains(c) {
      return this._c.has(c);
    },
  };
  const documentElement = { classList, lang: "es", className: "light" };
  const document = { documentElement };
  const sandbox = {
    window: {},
    document,
    localStorage,
    console,
  };
  sandbox.window = sandbox;
  vm.runInNewContext(readFileSync(`${root}/panel/vendor/prefs-boot.js`, "utf8"), sandbox);
  return sandbox;
}

function loadExport(localStorage) {
  const classList = { add() {}, remove() {}, contains() { return false; }, toggle() {} };
  const body = { appendChild() {}, classList, innerHTML: "" };
  const listeners = {};
  const document = {
    documentElement: { className: "light", lang: "es", classList },
    body,
    head: { appendChild() {} },
    addEventListener(ev, fn) {
      (listeners[ev] = listeners[ev] || []).push(fn);
    },
    querySelectorAll() {
      return [];
    },
    querySelector() {
      return null;
    },
    getElementById() {
      return null;
    },
    createElement() {
      return {
        style: {},
        classList,
        setAttribute() {},
        appendChild() {},
        click() {},
        remove() {},
      };
    },
  };
  const sessionStorage = memoryStorage();
  const sandbox = {
    window: {},
    document,
    localStorage,
    sessionStorage,
    location: { href: "http://127.0.0.1/panel/reporting.html", pathname: "/panel/reporting.html" },
    URL: class {
      constructor(path, base) {
        this.href = String(base || "") + String(path);
      }
    },
    Blob: class {},
    setTimeout,
    clearTimeout,
    console,
    lucide: null,
    DarkSpear: { t: (k) => k },
    DarkSpearParty: null,
  };
  sandbox.window = sandbox;
  sandbox.global = sandbox;
  vm.runInNewContext(readFileSync(`${root}/panel/vendor/prefs-boot.js`, "utf8"), sandbox);
  vm.runInNewContext(readFileSync(`${root}/panel/vendor/export.js`, "utf8"), sandbox);
  if (listeners.DOMContentLoaded) listeners.DOMContentLoaded.forEach((fn) => fn());
  return sandbox;
}

const settings = readFileSync(`${root}/panel/settings.html`, "utf8");
const profile = readFileSync(`${root}/panel/profile.html`, "utf8");
const live = readFileSync(`${root}/panel/vendor/panel-live.js`, "utf8");
const exportJs = readFileSync(`${root}/panel/vendor/export.js`, "utf8");
const prefs = readFileSync(`${root}/panel/vendor/prefs-boot.js`, "utf8");
const i18n = readFileSync(`${root}/panel/vendor/i18n.js`, "utf8");
const comp = readFileSync(`${root}/panel/comprehensive-report.html`, "utf8");

check(!/Evolve Cyber Audit/.test(settings), "settings.html no trae placeholder de cliente");
check(!/placeholder="ops@example\.com"/.test(settings), "settings.html no trae correo de ejemplo");
check(!/placeholder="Auditor \/ Lead"/.test(profile), "profile.html no trae rol de ejemplo");
check(prefs.includes("window.DarkSpearParty"), "prefs-boot expone DarkSpearParty");
check(live.includes("function reportParty"), "panel-live tiene reportParty");
check(live.includes("function partyTeam"), "panel-live tiene partyTeam");
check(live.includes("htmlCoverPage(all, meta"), "portada se pinta en el informe integral");
check(live.includes("htmlSignatures(party)"), "firmas usan party");
check(exportJs.includes("organization: party.org"), "export payload incluye organización");
check(exportJs.includes("auditor: party.operator"), "export payload incluye auditor");
check(comp.includes('id="comp-doc-footer-brand"'), "pie de informe con marca de org");
check(comp.includes('id="comp-doc-footer-class"'), "pie de informe con clasificación");
check(live.includes("escapeHtml(party.org"), "org se escapa en portada");
check(exportJs.includes("escHtml(org)"), "org se escapa en coverHTML de export");

const keys = [
  "comp.coverOrg", "comp.coverOrgEmail", "comp.coverAuditorEmail",
  "comp.coverTeam", "comp.dtClient", "comp.dtAuditor", "comp.coverClass",
  "settings.classInternal", "settings.classRestricted",
];
for (const k of keys) {
  const hits = i18n.split('"' + k + '"').length - 1;
  check(hits >= 2, "i18n " + k + " en ES+EN (hits=" + hits + ")");
}

{
  const store = memoryStorage();
  store.setItem("ds-settings", JSON.stringify({
    v: 1,
    orgName: "SEED-CLIENT",
    orgEmail: "seed@example.invalid",
    classification: "internal",
  }));
  const sb = bootPrefs(store);
  const party = sb.DarkSpearParty.read();
  check(party.org === "", "wipe v1 no deja orgName de semilla");
  check(party.orgEmail === "", "wipe v1 no deja correo de semilla");
  check(JSON.parse(store.getItem("ds-settings")).v == 2, "wipe deja schema v2");
}

{
  const store = memoryStorage();
  store.setItem("ds-settings", JSON.stringify({
    v: 2,
    orgName: "Acme Audit",
    orgEmail: "ops@acme.test",
    classification: "restricted",
    tz: "UTC",
  }));
  store.setItem("ds-profile", JSON.stringify({
    v: 2,
    "profile-name": "Ada",
    "profile-last": "Lovelace",
    "profile-role": "Lead",
    "profile-email": "ada@acme.test",
  }));
  const sb = bootPrefs(store);
  const party = sb.DarkSpearParty.read();
  check(party.org === "Acme Audit", "v2 conserva organización");
  check(party.orgEmail === "ops@acme.test", "v2 conserva correo org");
  check(party.operator === "Ada Lovelace", "v2 concatena nombre y apellidos");
  check(party.role === "Lead", "v2 conserva rol");
  check(party.email === "ada@acme.test", "v2 conserva correo auditor");
  check(party.classification === "restricted", "v2 conserva clasificación");
}

{
  const store = memoryStorage();
  store.setItem("ds-settings", JSON.stringify({ v: "2", orgName: "StringV" }));
  const sb = bootPrefs(store);
  check(sb.DarkSpearParty.read().org === "StringV", "v como string '2' no se wipea");
}

{
  const store = memoryStorage();
  const xss = "<img src=x onerror=alert(1)>";
  store.setItem("ds-settings", JSON.stringify({ v: 2, orgName: xss, orgEmail: "" }));
  store.setItem("ds-profile", JSON.stringify({
    v: 2,
    "profile-name": "<script>alert(1)</script>",
    "profile-last": "",
    "profile-role": "",
    "profile-email": "",
  }));
  const sb = loadExport(store);
  check(!!sb.DarkSpearExport, "export.js carga con mocks");
  const payload = sb.DarkSpearExport.buildPayload({
    findings: [{ title: "Hallazgo demo", severity: "Low", status: "accepted" }],
    target: "https://lab.test",
  });
  check(payload.organization === xss, "payload conserva el texto crudo (no lo interpreta)");
  check(payload.auditor === "<script>alert(1)</script>", "payload conserva nombre crudo");
  check(payload.classification === "", "clasificación vacía no se inventa");
  const coverSrc = exportJs;
  check(coverSrc.includes("escHtml(org)"), "coverHTML escapa org");
  check(coverSrc.includes("escHtml(auditor)"), "coverHTML escapa auditor");
}

{
  const store = memoryStorage();
  const sb = loadExport(store);
  const payload = sb.DarkSpearExport.buildPayload({
    findings: [{ title: "x", severity: "Info", status: "accepted" }],
  });
  check(payload.organization === "", "sin datos, org vacía");
  check(payload.auditor === "", "sin datos, auditor vacío");
  check(payload.classification === "", "sin datos, clasificación vacía");
}

{
  const empty = bootPrefs(memoryStorage()).DarkSpearParty.read();
  check(empty.operator === "" && empty.org === "", "instalación nueva: party vacío");
}

{
  function partyTeam(party) {
    return [party.operator, party.role].filter(Boolean).join(" · ") || "—";
  }
  check(live.includes('[party.operator, party.role].filter(Boolean).join(" · ") || "—"'), "partyTeam usa join filtrado");
  check(partyTeam({ operator: "", role: "Lead" }) === "Lead", "solo rol no pinta guion + rol");
  check(partyTeam({ operator: "Ada", role: "Lead" }) === "Ada · Lead", "nombre y rol unidos");
  check(partyTeam({ operator: "", role: "" }) === "—", "vacío → em dash");
}

function runChromiumDump(url) {
  return new Promise((resolve) => {
    const proc = spawn("chromium", [
      "--headless", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=3000",
      "--dump-dom", url,
    ], { timeout: 20000 });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => { stdout += d; });
    proc.stderr.on("data", (d) => { stderr += d; });
    proc.on("close", (code) => resolve({ status: code, stdout, stderr }));
    proc.on("error", (err) => resolve({ status: 1, stdout, stderr: String(err) }));
  });
}
const hasChromium = spawnSync("which", ["chromium"], { encoding: "utf8" }).status === 0;
if (hasChromium) {
  const partySettings = {
    v: 2,
    orgName: "Acme Audit",
    orgEmail: "ops@acme.test",
    classification: "internal",
    tz: "UTC",
  };
  const partyProfile = {
    v: 2,
    "profile-name": "Ada",
    "profile-last": "Lovelace",
    "profile-role": "Lead",
    "profile-email": "ada@acme.test",
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname === "/probe.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        "<!doctype html><meta charset=utf-8>" +
        "<script>localStorage.setItem('ds-settings'," + JSON.stringify(JSON.stringify(partySettings)) + ");" +
        "localStorage.setItem('ds-profile'," + JSON.stringify(JSON.stringify(partyProfile)) + ");</script>" +
        "<script src='/vendor/prefs-boot.js'></script>" +
        "<pre id='out'></pre>" +
        "<script>document.getElementById('out').textContent=JSON.stringify(DarkSpearParty.read());</script>"
      );
      return;
    }
    let file = url.pathname === "/" ? "/settings.html" : url.pathname;
    if (file.includes("..")) {
      res.writeHead(400);
      res.end();
      return;
    }
    try {
      const path = `${root}/panel${file}`;
      const body = readFileSync(path);
      const type = file.endsWith(".js") ? "text/javascript"
        : file.endsWith(".css") ? "text/css"
        : file.endsWith(".png") ? "image/png"
        : "text/html";
      res.writeHead(200, { "content-type": type });
      res.end(body);
    } catch (e) {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const probe = await runChromiumDump(`http://127.0.0.1:${port}/probe.html`);
    const dom = probe.stdout || "";
    check(probe.status === 0, "chromium probe.html exit 0");
    check(dom.includes("Acme Audit"), "chromium DarkSpearParty.org");
    check(dom.includes("ops@acme.test"), "chromium DarkSpearParty.orgEmail");
    check(dom.includes("Ada Lovelace"), "chromium DarkSpearParty.operator");
    check(dom.includes("ada@acme.test"), "chromium DarkSpearParty.email");
    check(dom.includes("\"classification\":\"internal\""), "chromium DarkSpearParty.classification");
  } finally {
    server.close();
  }
} else {
  console.log("skip chromium e2e (binario no encontrado)");
}

if (fail) {
  console.error("\n" + fail + " fallos");
  process.exit(1);
}
console.log("\nparty-report: todos los checks pasaron");
