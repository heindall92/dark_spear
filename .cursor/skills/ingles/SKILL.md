---
name: ingles
description: Keeps Dark Spear bilingual (ES/EN) via vendor/i18n.js and data-i18n. Translates UI copy to English on request and syncs both dictionary sides. Use when the user invokes /ingles, asks for English UI, i18n keys, or Spanish/English panel strings.
---

# /ingles — i18n Dark Spear

Repo: [heindall92/dark_spear](https://github.com/heindall92/dark_spear). Product name is always **Dark Spear** in both locales. Never use Lanza Oscura.

Never put theme or language switches in the top bar (search + bell + settings + avatar only). Prefs live in the sidebar above Settings (and also in `settings.html`). Sidebar collapse is icon-rail, not a header CTA.

## Files

- `panel/vendor/i18n.js` — `I18N.es`, `I18N.en`, `TITLES`, `DarkSpear.applyLang('en'|'es')`
- `panel/vendor/prefs-boot.js` — reads `ds-lang` / `ds-theme` / `ds-sidebar` before paint
- Mark copy with `data-i18n="key"`, placeholders `data-i18n-placeholder`, aria `data-i18n-aria`
- `brand` is always `Dark Spear` in both dictionaries

## When translating to English

1. Add or update the **same key** in `I18N.es` and `I18N.en`.
2. Put `data-i18n` on a leaf text node (a `<span>`), not on a parent that contains Lucide `<i>`.
3. If it is a document title, add the page to `TITLES` (`es` and `en`).
4. Do not leave a string only in one language. Do not mix ES and EN inside a single locale.
5. Keep product chrome nav keys (`nav.*`, `chap.*`, `brand`, `settings.*`).
6. After edits, set language to EN in the UI (or `DarkSpear.applyLang('en')`) and confirm the new string appears.

## When adding a new screen string

```html
<span data-i18n="findings.empty">No hay hallazgos</span>
```

```javascript
es: { "findings.empty": "No hay hallazgos" },
en: { "findings.empty": "No findings" }
```

## Do not

- Hardcode English only in HTML for chrome that already has a key
- Translate `brand` away from Dark Spear
- Translate vault/redacted evidence payloads
- Change `ds-lang` default away from `es` unless the user asks
