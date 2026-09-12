# dark_spear — Login Web Genérico + Descubrimiento de Formularios

**Fecha:** 2026-09-12
**Estado:** Aprobado (Fase 1), Fases 2-4 documentadas como roadmap
**Depende de:** fix de disciplina de evidencia por-paso en `finding-heuristics.js` (commit `2a830b1`, mismo día).

## Contexto y motivación

dark_spear hoy solo soporta credenciales de Active Directory (`ad-user`/`ad-password` en el panel, gateadas por `ctx.isAdTarget`, usadas exclusivamente por sondas SMB/Kerberos/netexec). No existe ningún mecanismo de login HTTP con reuso de cookie de sesión para apps web. El usuario intentó meter credenciales de una app Laravel real (`web.academyx.es`) en esos campos pensando que autenticarían el escaneo web — no tuvieron ningún efecto porque `ad-user`/`ad-password` nunca se leen en el flujo HTTP.

Sin login, el motor solo puede correr sondas de reconocimiento no autenticado (headers, DNS, robots.txt, fingerprint) — todo lo que está detrás de un login (la mayoría de vulnerabilidades reales de negocio) queda fuera del alcance de cualquier escaneo.

El proyecto hermano del mismo usuario, Eskir (`~/eskir/eskir/session.py`), ya resuelve login Laravel genérico para un CLI Python de un solo target: GET a login → extraer `_token` CSRF → detectar campo de usuario → POST credenciales → cookie jar reusada. dark_spear es arquitectura distinta (motor JS en navegador, fases PTES, sondas orquestadas por `playbook.js`, ejecución vía `bridge.py`) — el patrón se adapta, no se copia literal.

## Alcance general — por fases

Este documento cubre 4 fases. **Solo la Fase 1 está aprobada para implementación inmediata** — su plan de implementación se escribe a continuación de este spec. Las Fases 2-4 quedan documentadas con su diseño ya acordado, listas para retomar como su propio ciclo spec→plan→implementación cuando corresponda (mismo patrón que `project_dark_spear_tool_integrations_roadmap.md`).

| Fase | Qué agrega | Depende de |
|---|---|---|
| **1** | Login Laravel + fallback genérico, descubrimiento de forms sobre HTML ya recolectado, sondas XSS+SQLi contra cada campo | — |
| **2** | Login WordPress (`wp-login.php`) | Fase 1 (mismo módulo `web-auth.js`, un stack más) |
| **3** | Sondas IDOR + NoSQLi contra los forms descubiertos, además de XSS+SQLi | Fase 1 (mismo pipeline de descubrimiento) |
| **4** | Crawling activo post-login (home + rutas de `robots.txt` + rutas ya descubiertas) para alimentar más HTML al descubridor de forms | Fase 1 |

**Explícitamente fuera de alcance en todas las fases:** resolución de CAPTCHA, 2FA/MFA, o rate-limiting de login. Ninguno tiene solución genérica automatizable sin intervención humana — si el login requiere alguno de estos, el motor debe fallar limpio (ver Manejo de errores) y dejar que el operador lo resuelva a mano fuera del motor.

---

## Fase 1 — Login Laravel + fallback genérico + descubrimiento pasivo + XSS/SQLi

### UI (`panel/start-engagement.html`)

Nuevos campos, opcionales, separados de los de AD:
- `web-login-url` (URL de la página de login)
- `web-user`
- `web-password`

Si `web-login-url` está vacío, el motor no intenta login — comportamiento actual sin cambios. Estos campos nunca se leen para nada relacionado con AD, y `ad-user`/`ad-password` nunca se leen para nada relacionado con HTTP (separación total, evita la confusión que originó este feature).

### `backend/js/web-auth.js` (módulo nuevo)

```js
export function detectCsrfToken(html)
// busca <meta name="csrf-token" content="..."> o <input name="_token" value="...">
// retorna el string del token, o null si no encuentra ninguno.

export function detectUserField(html)
// busca <input type="email"|"text"> cuyo name matchee /email|username|user|login/i
// retorna el name del campo, o "email" como default si no encuentra nada.

export function buildLoginSteps(loginUrl, user, password, cookieFile)
// arma los steps de playbook (formato { id, tool, args, ... }) para:
//   1. GET loginUrl guardando cookies en cookieFile
//   2. Si detectCsrfToken encuentra token en la respuesta del paso 1: POST con
//      _token + campo de usuario detectado + password, cookie jar reusado.
//   3. Si NO encuentra token (fallback genérico): POST solo con el campo de
//      usuario detectado + password, sin _token — para stacks sin CSRF en
//      login (o donde el HTML no siguió el patrón Laravel).
// retorna la lista de 2 steps para insertar en el playbook.
```

### Wiring en `backend/js/playbook.js`

Si `ctx.webLoginUrl` está seteado (no vacío tras `.trim()`), se insertan los steps de `buildLoginSteps(...)` al **inicio de Fase 1**, antes de cualquier otra sonda — mismo mecanismo ya existente para propagar `ctx.cookieFile` al resto de sondas HTTP de fases posteriores (el archivo ya tiene un `cookieFile` en `ctx` reusado por sondas AD/otras; se reusa el mismo campo, no uno nuevo). El resto del playbook sigue exactamente igual — ahora con una sesión autenticada disponible en `ctx.cookieFile` si el login se disparó.

**Confirmación de login exitoso**: el step de POST se marca `meaningful` (evaluado por `isMeaningfulToolOutput`, ya existente) si la respuesta trae `Location:` de redirect (302/303) O si el cookie jar resultante contiene una cookie de sesión nueva distinta a la que había antes del POST. Si ninguna de las dos condiciones se cumple, se asume login fallido y se registra un finding informativo ("Login web no confirmado — descubrimiento de formularios corre sin sesión autenticada") sin abortar el resto del engagement.

### `backend/js/form-discovery.js` (módulo nuevo)

```js
export function extractForms(html)
// regex/parser simple sobre HTML capturado por CUALQUIER sonda ya ejecutada.
// retorna [{ action, method, fields: [{ name, type }] }] — un elemento por
// cada <form> encontrado, con sus <input>/<textarea> internos (name + type,
// default type="text" si el input no declara type).
```

Se invoca desde `finding-heuristics.js` sobre cada entrada de `probeIdx` que ya contiene HTML de página completa (no solo headers) — reusa la indexación por-paso que el archivo ya construye, sin agregar sondas HTTP nuevas en esta fase. Los forms descubiertos se acumulan en una lista nueva devuelta junto a los findings (`{ findings, discoveredForms }`), consumida por el paso siguiente.

### Sondas por formulario descubierto

Por cada form con al menos un campo de tipo `text`/`textarea`/`email` (se excluyen campos `hidden`, `submit`, `password`, `csrf`/`_token`), se arman steps reusando los builders existentes de `vuln-kb.js`:
- XSS reflejado: mismo payload/builder ya usado en `p1-xss-*` (`XSS_REFLECTION_PAYLOAD`), adaptado para postear al `action` del form descubierto en vez de una ruta fija.
- SQLi genérico: mismo payload/builder ya usado en `p1-sqli-login-*`, misma adaptación.

Cada resultado se evalúa con la misma disciplina de evidencia por-paso reforzada en el fix de `finding-heuristics.js` de esta sesión (nunca contra el blob acumulado).

### Manejo de errores

- Login sin CSRF token y sin fallback aplicable (form sin ningún input de tipo password detectable): se registra el finding informativo de login no confirmado (ver arriba) y el resto del engagement corre igual, sin sesión.
- Login que responde con página de CAPTCHA o pide un segundo factor (detectable por heurística simple: presencia de `recaptcha`/`hcaptcha`/`g-recaptcha` o de un segundo form pidiendo un código tras el POST): se registra un finding informativo distinto ("Login bloqueado por CAPTCHA/2FA — requiere intervención manual") y el motor NO reintenta ni intenta bypasear nada — cae al mismo camino de "login no confirmado".
- Cualquier error de red (timeout, conexión rechazada) en los steps de login: igual que cualquier otro step fallido del playbook hoy — se registra como step con error, no bloquea el resto del engagement.

### Testing

Mismo patrón que el resto del proyecto (`scripts/test-*.mjs`, positivo/negativo por caso, sin red real cuando es posible):
- `detectCsrfToken`: HTML con meta tag, HTML con input hidden, HTML sin ninguno de los dos (retorna null).
- `detectUserField`: HTML con campo `email`, con campo `username`, sin ningún campo reconocible (retorna default).
- `buildLoginSteps`: con token detectado (incluye `_token` en el POST), sin token (fallback, POST sin `_token`).
- `extractForms`: HTML con un form simple, HTML con múltiples forms, HTML sin ningún form (retorna lista vacía), form con inputs de distintos tipos (confirma que excluye `hidden`/`submit`/`password` de los campos a probar).
- Test de integración liviano (sin red real): simular un `stepRecords` con la respuesta de login exitosa + una página con un form descubierto, confirmar que el pipeline completo genera steps de XSS/SQLi contra ese form.

---

## Fase 2 — Login WordPress (roadmap, no implementar aún)

`detectStack(loginPageHtml)` se extiende para reconocer WordPress: presencing de `wp-login.php` en la URL o de inputs `name="log"`/`name="pwd"` en el HTML. WordPress no exige CSRF token en su login por defecto, así que el POST va directo con `log`+`pwd`+`wp-submit=Log In` — sin necesidad del paso de extracción de token. Confirmación de éxito: cookie `wordpress_logged_in_*` presente en la respuesta (en vez de la heurística genérica de redirect/cookie-nueva de Laravel, que también seguiría aplicando como fallback).

## Fase 3 — IDOR + NoSQLi contra formularios descubiertos (roadmap, no implementar aún)

Mismo pipeline de la Fase 1, sumando dos builders más de `vuln-kb.js` ya existentes (`IDOR_PROBES`, `NOSQLI_LOGIN_PROBES`) aplicados a cada form descubierto, con la misma adaptación de "postear al `action` real" en vez de una ruta fija. IDOR requiere un cuidado adicional: solo tiene sentido contra campos que parezcan IDs (`numérico`, o nombre de campo matcheando `/id$/i`) — aplicarlo a todos los campos de texto generaría ruido sin valor.

## Fase 4 — Crawling activo post-login (roadmap, no implementar aún)

Step nuevo `p1-webauth-crawl`, condicionado a que el login de la Fase 1 haya confirmado éxito. Visita, con la sesión autenticada, un set acotado de URLs: la home del target, las rutas listadas en `robots.txt` (ya parseadas por sondas existentes), y cualquier ruta ya descubierta por sondas previas de esa misma corrida (reusa `probeIdx`). Cada respuesta se indexa igual que cualquier otro step, alimentando `form-discovery.js` con más HTML real en vez de depender solo de lo que otras sondas visitaron de casualidad. Límite explícito de URLs a visitar (a definir en su propio spec) para no convertir esto en un crawler sin cota.
