# Dark Spear


https://github.com/user-attachments/assets/1c663f47-4240-4adf-a2bf-fd18078f3828


![Intro Dark Spear](panel/vendor/splash.mp4)

**Plataforma de auditoría de seguridad autorizada.** Un motor de agente ReAct que ejecuta el pentest paso a paso — recon → enumeración → explotación → post-explotación, con gate humano en cada acción peligrosa — y una consola SecOps que lo dirige y convierte lo que encontró en un informe defendible frente al cliente.

No es un scanner automático ni un "auto-pwn". El diferencial es la disciplina de engagement: scope-lock del lado del servidor, fases que se avanzan a mano, cada herramienta peligrosa pasa por aprobación explícita del operador, y cada hallazgo queda con su evidencia y su hash de integridad antes de entrar al informe final.

**Producto:** Dark Spear · Interfaz ES/EN · [MIT](LICENSE)

## Arquitectura

Dos piezas que se integran en un solo producto, no dos proyectos separados:

| | |
|---|---|
| **`backend/`** — el motor | Servidor Python local (`bridge.py`, stdlib + `cryptography`) que ejecuta las herramientas de pentest whitelisteadas contra el target. Scope-lock, gate de 4 fases PTES (Intelligence Gathering → Enumeration & Vuln Analysis → Exploitation → Post-Exploitation, acumulativo, avance manual), pool de API keys de Ollama Cloud cifrado con rotación automática por cuota agotada. El loop ReAct corre en el navegador (`js/agent.js` + `js/ollama.js`) y decide qué comando ejecutar — el servidor nunca confía en el modelo, todo el enforcement de seguridad vive en `bridge.py`. En desarrollo activo: entidad de **Hallazgo** (título/severidad/evidencia/remediación) propuesta por el LLM y revisada por el operador, con evidencia hasheada a disco recién al aceptar — cadena de custodia real, no un volcado del chat. |
| **`panel/`** — la consola | La interfaz que un consultor de seguridad mostraría frente a un cliente: dashboard, engagement activo, aprobación de herramientas, hallazgos críticos, grafo de ataque, MITRE ATT&CK, OSINT, remediación e informes (JSON/HTML/PDF). |

El historial de diseño técnico del motor (una spec + un plan de implementación por cada pieza construida, con revisión de código en cada paso) vive en `backend/docs/superpowers/`.

## Arranque rápido

### Consola (`panel/`)

Sirve la carpeta por HTTP — no abras los HTML como `file://`.

```bash
cd panel
python3 server.py          # o .\servir.ps1 en Windows PowerShell
```

Abre [http://127.0.0.1:8080/](http://127.0.0.1:8080/)

### Motor (`backend/`)

El motor está pensado para **Kali/Linux** (herramientas de pentest en el PATH). Necesita Python 3.10+ y el paquete `cryptography`.

En Kali, `pip install` a nivel sistema falla (`externally-managed-environment`). Usá apt o un venv:

```bash
cd ~/dark_spear/backend

# Opción A — paquete de Kali (la más simple)
sudo apt install -y python3-cryptography

# Opción B — venv (si preferís pip)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 bridge.py
```

Pide una passphrase (cifra el pool de API keys) e imprime una URL con token de sesión — abrí esa URL exacta que imprime, no `http://127.0.0.1:8420/` a secas.

Si ya corriste el motor antes y no recordás la passphrase:

```bash
rm ~/.auditor/keys.enc
python3 bridge.py
```

## Qué incluye

- Dashboard, escaneos, vulnerabilidades y hallazgos críticos
- Engagement activo, New Scan, aprobación de herramientas
- Reporting (JSON / HTML / PDF), capítulos de informe y RGPD
- Attack Graph, evidencia de grafo, MITRE ATT&CK, OSINT, activos
- Perfil de usuario, centro de notificaciones, ajustes (tema e idioma)
- Motor de agente ReAct: scope-lock, gate de fases PTES, pool de API keys con rotación, hallazgos con evidencia hasheada a disco

Tema claro/oscuro e idioma ES/EN se guardan en el navegador (`ds-theme`, `ds-lang`). El menú lateral se retrae a un rail de iconos (`ds-sidebar`).

## Estructura

```
panel/                 Consola SecOps (HTML estático)
  vendor/               Assets propios + Lucide icons, tokens.css, splash de intro
backend/                Motor Auditor
  bridge.py              Servidor: scope-lock, fases, exec de herramientas, keystore, findings
  keystore.py             Cifrado Fernet/PBKDF2 del pool de API keys
  js/                     Loop ReAct (browser): agent.js, ollama.js, bridge_client.js, ui.js, db.js
  index.html, style.css   UI del motor
  docs/superpowers/       Specs + planes de implementación de cada pieza del motor
Sessiones/               Diseños de referencia del frontend
LICENSE                 MIT
```

## Atribución

- Iconografía de la consola: [Lucide](https://lucide.dev) (ISC License).
- Resto de UI, motor, y diseño de producto: propios de este proyecto.

## Aviso legal y ético

Herramienta de uso profesional para auditorías de seguridad **autorizadas**.

- Usalo solo en sistemas propios, laboratorios controlados, o engagements con autorización escrita explícita del cliente.
- El scope-lock y los gates de confirmación del motor son deliberados — no los desactives para saltarte el alcance acordado.
- El autor no se hace responsable del uso indebido de este software fuera del alcance autorizado.

## Licencia

Distribuido bajo licencia [MIT](LICENSE) · Copyright © 2026 Yoandy Ramírez Delgado.

## Autor

**Yoandy Ramírez Delgado** · Pentester · eJPTv2

[LinkedIn](https://www.linkedin.com/in/yoandyrd92/) · [HackTheBox](https://profile.hackthebox.com/profile/019c5812-b4ca-7315-b12f-14db6d2b42fa)
