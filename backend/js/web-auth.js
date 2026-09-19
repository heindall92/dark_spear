/**
 * Login web genérico: detecta CSRF + campo de usuario + botón submit, y arma
 * GET+POST. Sin form con password (SPA tipo Juice Shop) cae a POST JSON
 * contra /rest/user/login cuando el HTML/URL lo indiquen.
 */

import { hostInScope } from "./vuln-kb.js";

const CSRF_META_RE = /<meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i;
const INPUT_TAG_RE = /<input\b[^>]*>/gi;
const CSRF_FIELD_NAMES = new Set([
  "_token",
  "user_token",
  "csrf_token",
  "csrfmiddlewaretoken",
  "authenticity_token",
  "_csrf",
  "__requestverificationtoken",
]);

// Extrae el valor de un atributo dentro de un tag ya aislado, tolerante a
// que aparezca en cualquier posición (Laravel siempre pone name antes que
// value/type, pero otros stacks no lo garantizan).
function attrValue(tag, attr) {
  const m = new RegExp(`${attr}=["']([^"']*)["']`, "i").exec(tag);
  return m ? m[1] : null;
}

export function detectCsrfToken(html) {
  const meta = CSRF_META_RE.exec(html);
  if (meta) return meta[1];
  const tags = String(html || "").match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    const name = (attrValue(tag, "name") || "").toLowerCase();
    if (CSRF_FIELD_NAMES.has(name)) {
      const value = attrValue(tag, "value");
      if (value) return value;
    }
  }
  return null;
}

/** Nombre del campo CSRF hallado (para el POST); null si no hay. */
export function detectCsrfFieldName(html) {
  const meta = CSRF_META_RE.exec(html);
  if (meta) return "_token";
  const tags = String(html || "").match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    const name = attrValue(tag, "name");
    if (name && CSRF_FIELD_NAMES.has(name.toLowerCase()) && attrValue(tag, "value")) {
      return name;
    }
  }
  return null;
}

const USER_FIELD_NAMES = new Set(["email", "username", "user", "login", "uid", "uname", "userid", "user_id"]);
const USER_FIELD_TYPES = new Set(["email", "text", ""]);
const PASSWORD_FIELD_NAMES = new Set(["password", "passw", "pass", "pwd", "passwd", "user_password"]);

export function detectUserField(html) {
  const tags = String(html || "").match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    const type = (attrValue(tag, "type") || "").toLowerCase();
    const name = attrValue(tag, "name");
    if (!name) continue;
    if (USER_FIELD_TYPES.has(type) && USER_FIELD_NAMES.has(name.toLowerCase())) return name;
  }
  return "email";
}

export function detectPasswordField(html) {
  const tags = String(html || "").match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    const type = (attrValue(tag, "type") || "").toLowerCase();
    const name = attrValue(tag, "name");
    if (!name) continue;
    if (type === "password" || PASSWORD_FIELD_NAMES.has(name.toLowerCase())) return name;
  }
  return "password";
}

/** action del <form> que contiene el password; resuelto contra loginUrl. */
export function detectLoginFormAction(html, loginUrl) {
  const forms = String(html || "").match(/<form\b[^>]*>[\s\S]*?<\/form>/gi) || [];
  let action = null;
  for (const form of forms) {
    if (!/type=["']password["']/i.test(form) && !/name=["'](?:password|passw|pass|pwd)["']/i.test(form)) {
      continue;
    }
    const open = form.match(/<form\b[^>]*>/i)?.[0] || "";
    action = attrValue(open, "action");
    break;
  }
  const base = String(loginUrl || "").split("#")[0] || loginUrl;
  if (!action || action === "#" || /^javascript:/i.test(action)) return base;
  try {
    return new URL(action, base).href;
  } catch {
    return base;
  }
}

/** Botones submit del form (p.ej. DVWA Login=Login). */
export function detectSubmitFields(html) {
  const tags = String(html || "").match(INPUT_TAG_RE) || [];
  const out = [];
  for (const tag of tags) {
    const type = (attrValue(tag, "type") || "").toLowerCase();
    if (type !== "submit" && type !== "button") continue;
    const name = attrValue(tag, "name");
    const value = attrValue(tag, "value");
    if (name != null && value != null) out.push({ name, value });
  }
  return out;
}

export function hasPasswordForm(html) {
  const h = String(html || "");
  return /type=["']password["']/i.test(h) || /name=["'](?:password|passw|pass|pwd|passwd)["']/i.test(h);
}

export function looksLikeJuiceShop(html, loginUrl) {
  const blob = `${html || ""}\n${loginUrl || ""}`;
  return /juice.?shop|bkimminich|\/rest\/user\/login/i.test(blob);
}

function originFromLoginUrl(loginUrl) {
  try {
    const u = new URL(String(loginUrl || "").split("#")[0]);
    return u.origin;
  } catch {
    return "";
  }
}

function juiceLoginApiUrl(loginUrl) {
  const raw = String(loginUrl || "").split("#")[0];
  if (/\/rest\/user\/login\/?$/i.test(raw)) return raw.replace(/\/$/, "");
  const origin = originFromLoginUrl(raw);
  return origin ? `${origin}/rest/user/login` : raw;
}

export function buildLoginSteps(step, loginUrl, user, password, cookieFile, root = "") {
  const getStep = step(
    "p1-webauth-get",
    "curl",
    ["-s", "-c", cookieFile, "--max-time", "15", "-L", String(loginUrl).split("#")[0] || loginUrl],
    null,
    { desc: "Login web: GET página de login para extraer token/campo" },
  );

  const postStep = step(
    "p1-webauth-post",
    "curl",
    (ctx) => {
      const html = String(ctx.webLoginPageHtml || "");
      // SPA / API (Juice Shop): JSON email+password, no form HTML.
      if (!hasPasswordForm(html) && looksLikeJuiceShop(html, loginUrl)) {
        const apiUrl = juiceLoginApiUrl(loginUrl);
        return [
          "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
          "-H", "Content-Type: application/json",
          "-X", "POST",
          "-d", JSON.stringify({ email: user, password }),
          apiUrl,
        ];
      }

      const token = detectCsrfToken(html);
      const csrfName = detectCsrfFieldName(html) || "_token";
      const userField = detectUserField(html);
      const passField = detectPasswordField(html);
      const fields = [
        `${encodeURIComponent(userField)}=${encodeURIComponent(user)}`,
        `${encodeURIComponent(passField)}=${encodeURIComponent(password)}`,
      ];
      if (token) fields.push(`${encodeURIComponent(csrfName)}=${encodeURIComponent(token)}`);
      for (const s of detectSubmitFields(html)) {
        fields.push(`${encodeURIComponent(s.name)}=${encodeURIComponent(s.value)}`);
      }
      const postUrl = detectLoginFormAction(html, loginUrl);
      // El action del form de login lo controla el TARGET (HTML propio),
      // no el operador. Si resuelve a un host distinto del loginUrl
      // pedido y ese host tampoco está confirmado en `root`, no se
      // envían las credenciales reales ahí (fail-closed) — de lo
      // contrario un target hostil con <form action="https://evil/steal">
      // exfiltra la contraseña del operador.
      if (
        /^https?:\/\//i.test(postUrl) &&
        !hostInScope(postUrl, loginUrl) &&
        !(root && hostInScope(postUrl, root))
      ) {
        return null;
      }
      return [
        "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
        "-e", String(loginUrl).split("#")[0] || loginUrl,
        "-X", "POST", "-d", fields.join("&"), postUrl,
      ];
    },
    null,
    { desc: "Login web: POST credenciales (form CSRF o JSON SPA)" },
  );

  return [getStep, postStep];
}
