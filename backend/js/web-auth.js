/**
 * Login web genérico: detecta el patrón Laravel (CSRF token + campo de
 * usuario) y arma los steps de GET+POST correspondientes. Sin token
 * detectado, cae a un fallback genérico (POST directo sin _token) para
 * stacks que no lo exigen en su form de login.
 */

const CSRF_META_RE = /<meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i;
const INPUT_TAG_RE = /<input\b[^>]*>/gi;

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
  const tags = html.match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    if (attrValue(tag, "name") === "_token") {
      const value = attrValue(tag, "value");
      if (value) return value;
    }
  }
  return null;
}

const USER_FIELD_NAMES = new Set(["email", "username", "user", "login"]);
const USER_FIELD_TYPES = new Set(["email", "text"]);

export function detectUserField(html) {
  const tags = html.match(INPUT_TAG_RE) || [];
  for (const tag of tags) {
    const type = attrValue(tag, "type");
    const name = attrValue(tag, "name");
    if (USER_FIELD_TYPES.has(type) && USER_FIELD_NAMES.has(name)) return name;
  }
  return "email";
}

export function buildLoginSteps(step, loginUrl, user, password, cookieFile) {
  const getStep = step(
    "p1-webauth-get",
    "curl",
    ["-s", "-c", cookieFile, "--max-time", "15", loginUrl],
    null,
    { desc: "Login web: GET página de login para extraer token/campo" },
  );

  const postStep = step(
    "p1-webauth-post",
    "curl",
    (ctx) => {
      const html = String(ctx.webLoginPageHtml || "");
      const token = detectCsrfToken(html);
      const userField = detectUserField(html);
      const fields = [`${userField}=${encodeURIComponent(user)}`, `password=${encodeURIComponent(password)}`];
      if (token) fields.push(`_token=${encodeURIComponent(token)}`);
      return [
        "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
        "-X", "POST", "-d", fields.join("&"), loginUrl,
      ];
    },
    null,
    { desc: "Login web: POST credenciales (con _token si el stack lo exige)" },
  );

  return [getStep, postStep];
}
