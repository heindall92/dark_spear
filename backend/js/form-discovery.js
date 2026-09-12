/**
 * Descubrimiento de formularios sobre HTML ya recolectado por sondas
 * existentes (root, robots.txt-linked, etc.) — sin requests nuevas en esta
 * fase. Los campos hidden/submit/password/csrf se excluyen de los "campos
 * probables" que después reciben payloads de XSS/SQLi: no tiene sentido
 * inyectar en un token oculto ni en un botón.
 */

const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const ACTION_RE = /action=["']([^"']+)["']/i;
const METHOD_RE = /method=["']([^"']+)["']/i;
const INPUT_RE = /<input\b([^>]*)>/gi;
const TEXTAREA_RE = /<textarea\b([^>]*?)name=["']([^"']+)["']/gi;
const NAME_RE = /name=["']([^"']+)["']/i;
const TYPE_RE = /type=["']([^"']+)["']/i;

const EXCLUDED_TYPES = new Set(["hidden", "submit", "password", "button", "image", "reset"]);
const EXCLUDED_NAME_RE = /token|csrf/i;

function fieldsFromFormBody(body) {
  const fields = [];

  let m;
  INPUT_RE.lastIndex = 0;
  while ((m = INPUT_RE.exec(body)) !== null) {
    const attrs = m[1];
    const nameMatch = NAME_RE.exec(attrs);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const typeMatch = TYPE_RE.exec(attrs);
    const type = typeMatch ? typeMatch[1].toLowerCase() : "text";
    if (EXCLUDED_TYPES.has(type) || EXCLUDED_NAME_RE.test(name)) continue;
    fields.push({ name, type });
  }

  TEXTAREA_RE.lastIndex = 0;
  while ((m = TEXTAREA_RE.exec(body)) !== null) {
    const name = m[2];
    if (EXCLUDED_NAME_RE.test(name)) continue;
    fields.push({ name, type: "textarea" });
  }

  return fields;
}

export function extractForms(html) {
  const forms = [];
  const text = String(html || "");
  let m;
  FORM_RE.lastIndex = 0;
  while ((m = FORM_RE.exec(text)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const actionMatch = ACTION_RE.exec(attrs);
    const methodMatch = METHOD_RE.exec(attrs);
    forms.push({
      action: actionMatch ? actionMatch[1] : "",
      method: methodMatch ? methodMatch[1].toUpperCase() : "GET",
      fields: fieldsFromFormBody(body),
    });
  }
  return forms;
}
