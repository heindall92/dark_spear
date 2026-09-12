/**
 * Login web genérico: detecta el patrón Laravel (CSRF token + campo de
 * usuario) y arma los steps de GET+POST correspondientes. Sin token
 * detectado, cae a un fallback genérico (POST directo sin _token) para
 * stacks que no lo exigen en su form de login.
 */

const CSRF_META_RE = /<meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i;
const CSRF_INPUT_RE = /<input[^>]*name=["']_token["'][^>]*value=["']([^"']+)["']/i;

export function detectCsrfToken(html) {
  const meta = CSRF_META_RE.exec(html);
  if (meta) return meta[1];
  const input = CSRF_INPUT_RE.exec(html);
  if (input) return input[1];
  return null;
}

const USER_FIELD_RE = /<input[^>]*type=["'](?:email|text)["'][^>]*name=["'](email|username|user|login)["']/i;

export function detectUserField(html) {
  const match = USER_FIELD_RE.exec(html);
  return match ? match[1] : "email";
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
