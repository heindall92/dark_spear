/** Carga engine-panel con ?v=BUILD para no reutilizar playbook.js cacheado. */
const res = await fetch(new URL("./engine/BUILD", import.meta.url), { cache: "no-store" });
const build = res.ok ? (await res.text()).trim() : String(Date.now());
await import(`./engine-panel.js?v=${encodeURIComponent(build)}`);
