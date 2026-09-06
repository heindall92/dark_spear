#!/usr/bin/env node
/**
 * Verifica looksLikeSourceCode() y semgrepFindings(). El fixture de
 * semgrepFindings replica el shape real de `semgrep --config=p/php --json`
 * (mismos nombres de campo, capturado corriendo semgrep contra un PHP
 * sintético con SQLi/XSS durante el desarrollo de esta feature).
 */
import { looksLikeSourceCode, semgrepFindings, guessSourceExtension } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

// --- looksLikeSourceCode ---
const realPhp = `<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
mysqli_query($conn, $query);
echo $_GET['name'];
`;
check("PHP real (2+ señales) -> true", looksLikeSourceCode(realPhp));
check("texto corto -> false (bajo el umbral de tamaño)", !looksLikeSourceCode("<?php echo 1;"));
check("prosa normal sin señales de código -> false", !looksLikeSourceCode("Error 404: la página que buscas no existe en este servidor, contacta al administrador si crees que es un error."));
check("HTML de error genérico -> false", !looksLikeSourceCode("<html><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"));

// --- semgrepFindings (shape real de `semgrep --json`) ---
const realShapedOutput = JSON.stringify({
  version: "1.176.1",
  results: [
    {
      check_id: "php.lang.security.injection.tainted-sql-string.tainted-sql-string",
      path: "/tmp/leaked.php",
      start: { line: 3, col: 10 },
      end: { line: 3, col: 56 },
      extra: {
        message: "User data flows into this manually-constructed SQL string. Use prepared statements.",
        metadata: { cwe: ["CWE-89: Improper Neutralization..."], owasp: ["A03:2021 - Injection"] },
        severity: "ERROR",
      },
    },
    {
      check_id: "php.lang.security.injection.echoed-request.echoed-request",
      path: "/tmp/leaked.php",
      start: { line: 5, col: 1 },
      end: { line: 5, col: 20 },
      extra: {
        message: "Echoing user input risks XSS.",
        fix: "echo htmlentities($_GET['name']);",
        metadata: { cwe: ["CWE-79: Improper Neutralization..."], owasp: ["A03:2021 - Injection"] },
        severity: "ERROR",
      },
    },
  ],
});

const findings = semgrepFindings(realShapedOutput, "leaked.php");
check("parsea los 2 findings reales (SQLi + XSS)", findings.length === 2);
check("severidad ERROR -> High", findings.every((f) => f.severity === "High"));
check("título incluye el nombre de archivo y línea", findings[0].title.includes("leaked.php:3"));
check("remediation incluye el fix sugerido cuando existe", findings[1].remediation.includes("htmlentities"));

check("JSON inválido -> []", semgrepFindings("no es json", "x.php").length === 0);
check("sin resultados -> []", semgrepFindings(JSON.stringify({ results: [] }), "x.php").length === 0);
check("respeta tope de 8", semgrepFindings(JSON.stringify({
  results: Array.from({ length: 20 }, (_, i) => ({
    check_id: `rule-${i}`, extra: { message: "m", severity: "WARNING", metadata: {} },
  })),
}), "x.php").length === 8);

// --- guessSourceExtension ---
check("PHP -> .php", guessSourceExtension(realPhp) === ".php");
check("Python -> .py", guessSourceExtension("def handler(request):\n    return request.GET['id']\n") === ".py");
check("desconocido -> .txt", guessSourceExtension("texto plano sin señales") === ".txt");

process.exit(ok ? 0 : 1);
