#!/usr/bin/env node
/**
 * Fase 4: descubrimiento + introspection de GraphQL. Mismo patrón que
 * GENERIC_EXPOSURE_PROBES (lista de rutas + curl + heurística sobre el
 * body), pero con POST JSON en vez de GET: GraphQL no responde nada útil
 * a un GET simple.
 */
import { GRAPHQL_PROBES, graphqlIntrospectionCurlSteps, graphqlFindings } from "../backend/js/vuln-kb.js";
import { buildPlaybookContext, stepsForPhase } from "../backend/js/playbook.js";

let fails = 0;
function check(label, ok) {
  console.log(`${ok ? "OK" : "FAIL"}: ${label}`);
  if (!ok) fails++;
}

/* ---------------------------- steps ---------------------------- */

const steps = graphqlIntrospectionCurlSteps((id, tool, args) => ({ id, tool, args }), "p1-graphql", "https://x.com", "12");
check("1 step por ruta común de GraphQL", steps.length === GRAPHQL_PROBES.length);
check("usa POST con Content-Type JSON", steps.every((s) => s.args.includes("-X") && s.args.includes("POST") && s.args.some((a) => /content-type:\s*application\/json/i.test(String(a)))));
check("manda una query de introspección real (__schema)", steps.every((s) => s.args.some((a) => String(a).includes("__schema"))));
check("cubre /graphql", steps.some((s) => s.args.some((a) => String(a).endsWith("/graphql"))));

/* ---------------------------- graphqlFindings ---------------------------- */

// Respuesta real de un servidor Apollo con introspection habilitada.
const introspectionOpen = JSON.stringify({
  data: { __schema: { queryType: { name: "Query" }, types: [{ name: "User" }, { name: "Mutation" }] } },
});
const openFindings = graphqlFindings(introspectionOpen, "/graphql");
check("introspection habilitada -> 1 finding Medium", openFindings.length === 1 && openFindings[0].severity === "Medium");
check("título menciona introspection y la ruta", /introspection/i.test(openFindings[0].title) && /\/graphql/.test(openFindings[0].title));

// Endpoint GraphQL real, pero introspection deshabilitada (buena práctica).
const introspectionClosed = JSON.stringify({
  errors: [{ message: "GraphQL introspection is not allowed" }],
});
const closedFindings = graphqlFindings(introspectionClosed, "/graphql");
check("endpoint GraphQL real con introspection cerrada -> 1 finding Info", closedFindings.length === 1 && closedFindings[0].severity === "Info");
check("no confunde 'cerrada' con 'habilitada'", !/introspection habilitada/i.test(closedFindings[0].title));

// No es un endpoint GraphQL en absoluto (404 HTML normal, o cualquier app) -> nada.
check("404 HTML normal -> cero findings (no es GraphQL)", graphqlFindings("<html><body>404 Not Found</body></html>", "/graphql").length === 0);
check("stdout vacío -> cero findings", graphqlFindings("", "/graphql").length === 0);
check("JSON no-GraphQL (API REST normal) -> cero findings", graphqlFindings(JSON.stringify({ status: "ok", user: "admin" }), "/graphql").length === 0);

/* ------------------------- wiring Fase 1 ------------------------- */

const ctx = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: true });
const stepsFase1 = stepsForPhase(1, "https://x.com", ctx);
check("Fase 1 incluye los steps p1-graphql-*", GRAPHQL_PROBES.every((p) => stepsFase1.some((s) => s.id === `p1-graphql-${p.stepId}`)));

const ctxNoWeb = buildPlaybookContext([], { host: "x.com", scope: "https://x.com", hasWebStack: false });
const stepsFase1NoWeb = stepsForPhase(1, "https://x.com", ctxNoWeb);
const graphqlStepNoWeb = stepsFase1NoWeb.find((s) => s.id === `p1-graphql-${GRAPHQL_PROBES[0].stepId}`);
check("se salta si no hay web stack", !!graphqlStepNoWeb?.skipIf?.(ctxNoWeb));

console.log("");
console.log(fails === 0 ? "RESULTADO: OK — todas pasaron" : `RESULTADO: FAIL — ${fails} fallo(s)`);
process.exit(fails === 0 ? 0 : 1);
