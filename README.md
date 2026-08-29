# Dark Spear


https://github.com/user-attachments/assets/1c663f47-4240-4adf-a2bf-fd18078f3828


![Intro Dark Spear](panel/vendor/splash.mp4)

Plataforma de auditoría de seguridad autorizada: un motor de agente ReAct que ejecuta el pentest (recon → enumeración → explotación → post-explotación, con gate humano en cada paso peligroso) y una consola SecOps que lo dirige y convierte lo que encontró en un informe defendible para el cliente.

No es un scanner automático ni un "auto-pwn". El diferencial es la disciplina de engagement: scope-lock del lado del servidor, fases que se avanzan a mano, cada herramienta peligrosa pasa por aprobación explícita, y cada hallazgo queda con su evidencia y su cadena de hash antes de entrar al informe.

Producto: **Dark Spear**. Interfaz en español e inglés.

Repositorio: [heindall92/dark_spear](https://github.com/heindall92/dark_spear)

## Arquitectura

```
panel/     Consola SecOps (HTML estático + vendor) — el frontend
backend/   Motor Auditor (Python + JS) — el agente que corre el engagement
```

Son dos piezas que se integran, no dos productos separados:

- **`backend/`** es el motor real: `bridge.py` es un servidor Python local (stdlib, sin dependencias salvo `cryptography` para el keystore) que ejecuta las herramientas de pentest whitelisteadas contra el target, con scope-lock, gate de fases PTES (Intelligence Gathering → Enumeration & Vuln Analysis → Exploitation → Post-Exploitation, acumulativo, avance manual del operador) y pool de API keys de Ollama Cloud cifrado con rotación automática por cuota. El loop ReAct (`js/agent.js` + `js/ollama.js`) corre en el navegador y decide qué comando ejecutar en cada paso — el servidor nunca confía en el modelo, todo el enforcement de seguridad vive del lado de `bridge.py`. En desarrollo activo: una entidad de **Hallazgo** (título/severidad/evidencia/remediación) que el LLM propone y el operador revisa, con evidencia hasheada a disco recién al aceptar (cadena de custodia real, no un volcado del chat).
- **`panel/`** es la consola que un consultor de seguridad usaría frente a un cliente: dashboard, engagement activo, aprobación de herramientas, hallazgos críticos, grafo de ataque, MITRE ATT&CK, OSINT, remediación e informes (JSON/HTML/PDF).

El historial de diseño y las specs técnicas del motor viven en `backend/docs/superpowers/` (una spec + un plan de implementación por cada pieza construida).

## Arranque rápido

### Consola (`panel/`)

Sirve la carpeta `panel/` por HTTP (no abras los HTML como `file://`).

**Python**

```bash
cd panel
python3 server.py
```

**Windows (PowerShell)**

```powershell
cd panel
.\servir.ps1
```

Abre [http://127.0.0.1:8080/](http://127.0.0.1:8080/)

### Motor (`backend/`)

```bash
cd backend
python3 bridge.py
```

Te pide una passphrase (cifra el pool de API keys), imprime una URL con token de sesión — abrí esa URL exacta, no `http://127.0.0.1:8420/` a secas.

## Qué incluye

- Dashboard, escaneos, vulnerabilidades y hallazgos críticos
- Engagement activo, New Scan, aprobación de herramientas
- Reporting (JSON / HTML / PDF), capítulos de informe y RGPD
- Attack Graph, evidencia de grafo, MITRE ATT&CK, OSINT, activos
- Perfil de usuario, centro de notificaciones, ajustes (tema e idioma)
- Intro de arranque a pantalla completa (`panel/vendor/splash.mp4`)
- Motor de agente ReAct con scope-lock, gate de fases PTES, pool de API keys con rotación, y hallazgos con evidencia hasheada a disco

Tema claro/oscuro e idioma ES/EN se guardan en el navegador (`ds-theme`, `ds-lang`). El menú lateral se retrae a un rail de iconos (`ds-sidebar`).

## Estructura

```
panel/           Consola (HTML estático + vendor)
backend/         Motor Auditor (bridge.py + keystore.py + js/) + docs/superpowers (specs y planes)
Sessiones/       Diseños de referencia del frontend
LICENSE          MIT
```

## Licencia

[MIT](LICENSE)
