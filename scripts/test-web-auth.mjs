#!/usr/bin/env node
import { detectCsrfToken, detectUserField, buildLoginSteps } from "../backend/js/web-auth.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

// detectCsrfToken
check(
  "detecta token en meta tag",
  detectCsrfToken('<meta name="csrf-token" content="abc123">') === "abc123",
);
check(
  "detecta token en input hidden",
  detectCsrfToken('<input type="hidden" name="_token" value="xyz789">') === "xyz789",
);
check(
  "sin token retorna null",
  detectCsrfToken("<html><body>sin token acá</body></html>") === null,
);
check(
  "detecta token con value ANTES que name (orden de atributos invertido)",
  detectCsrfToken('<input type="hidden" value="xyz789" name="_token">') === "xyz789",
);

// detectUserField
check(
  "detecta campo email",
  detectUserField('<input type="email" name="email">') === "email",
);
check(
  "detecta campo username",
  detectUserField('<input type="text" name="username">') === "username",
);
check(
  "default a email sin campo reconocible",
  detectUserField("<html>sin inputs relevantes</html>") === "email",
);
check(
  "detecta campo con name ANTES que type (orden de atributos invertido)",
  detectUserField('<input name="username" type="text">') === "username",
);

// buildLoginSteps — fake step() que solo registra lo que se le pasó
function fakeStep(id, tool, args, when, meta) {
  return { id, tool, args: typeof args === "function" ? args({}) : args, when, meta };
}

const stepsWithToken = buildLoginSteps(fakeStep, "https://x/login", "u@x.com", "pass", "/tmp/c.txt");
check("con token: genera 2 steps (GET + POST)", stepsWithToken.length === 2);
check("con token: el GET apunta a la URL de login", stepsWithToken[0].args.includes("https://x/login"));
check("con token: el GET guarda cookies en cookieFile", stepsWithToken[0].args.includes("/tmp/c.txt"));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
