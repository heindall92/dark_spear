#!/usr/bin/env node
/**
 * Verifica statusClass() en export.js: cada estado del ciclo de vida de
 * un finding (incluyendo verifying/reported) mapea a su propia clase CSS
 * en el informe generado, en vez de todos verse igual.
 */
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("../panel/vendor/export.js", import.meta.url), "utf8");
const match = src.match(/function statusClass\(status\) \{[\s\S]*?\n  \}/);
if (!match) {
  console.log("FAIL: no se encontró statusClass() en export.js");
  process.exit(1);
}
// Safe: `match[0]` is a pure function body sliced out of our own committed
// export.js (no user/network input), used only to test it without loading
// the whole file's DOM-dependent module. new Function (not eval) so ESM's
// strict-mode scoping doesn't swallow the declaration.
const statusClass = new Function(`${match[0]}\nreturn statusClass;`)();

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check("reported -> st-reported", statusClass("reported") === "st-reported");
check("verifying -> st-verifying", statusClass("verifying") === "st-verifying");
check("accepted -> st-accepted", statusClass("accepted") === "st-accepted");
check("rejected -> st-rejected", statusClass("rejected") === "st-rejected");
check("edited -> st-edited", statusClass("edited") === "st-edited");
check("proposed -> st-proposed", statusClass("proposed") === "st-proposed");
check("valor desconocido cae a st-proposed (no rompe)", statusClass("algo-raro") === "st-proposed");

process.exit(ok ? 0 : 1);
