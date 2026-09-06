#!/usr/bin/env node
/**
 * Verifica extractSubfinderHosts()/httpxArgsForHosts()/httpxFindings():
 * parseo de subdominios pasivos + fingerprint HTTP consolidado.
 */
import { extractSubfinderHosts, httpxArgsForHosts, httpxFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const subfinderOutput = "www.example.com\napi.example.com\nexample.com\nwww.example.com\ngarbage line with spaces\n\ndev.example.com\n";
const hosts = extractSubfinderHosts(subfinderOutput, "example.com");
check("extrae 3 hosts únicos (descarta root y duplicado)", hosts.length === 3);
check("descarta líneas con espacios (ruido)", !hosts.some((h) => h.includes(" ")));
check("no incluye el root mismo", !hosts.includes("example.com"));

const manyHosts = Array.from({ length: 20 }, (_, i) => `sub${i}.example.com`).join("\n");
check("respeta el tope de hosts", extractSubfinderHosts(manyHosts, "example.com").length === 8);

const args = httpxArgsForHosts(["api.example.com", "dev.example.com"]);
check("httpxArgsForHosts pasa -u por cada host", args.filter((a) => a === "-u").length === 2);
check("httpxArgsForHosts antepone https://", args.includes("https://api.example.com"));

const httpxJsonl = [
  JSON.stringify({ url: "https://api.example.com", status_code: 200, title: "API", tech: ["nginx", "PHP"] }),
  JSON.stringify({ url: "https://dev.example.com", status_code: 401, title: "" }),
  "not-json",
].join("\n");
const findings = httpxFindings(httpxJsonl, "example.com");
check("consolida en 1 solo finding (no ruido)", findings.length === 1);
check("severity Info (es inventario, no vulnerabilidad)", findings[0].severity === "Info");
check("incluye ambos hosts en la descripción", findings[0].description.includes("api.example.com") && findings[0].description.includes("dev.example.com"));
check("sin hosts vivos -> []", httpxFindings("garbage\n", "example.com").length === 0);

process.exit(ok ? 0 : 1);
