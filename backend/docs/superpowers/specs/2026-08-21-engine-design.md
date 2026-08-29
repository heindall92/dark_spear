# Auditor — Engine (Sub-proyecto 1) — Diseño

**Fecha:** 2026-08-21
**Estado:** Aprobado para pasar a plan de implementación
**Contexto:** herramienta de auditoría/pentesting de uso profesional real (el usuario está por graduarse de un máster y planea ejercer con esto), no solo para práctica HTB/THM. Los guardrails de scope y confirmación NO son opcionales ni decorativos — son la pieza que evita que un bug se convierta en un incidente con un cliente real.

## Objetivo

Motor local, offline-first, sin Docker, que ejecuta un agente ReAct impulsado por Ollama contra un target de pentest definido por el operador, con dos capas de guardrail duras y memoria persistente en el navegador (IndexedDB). Es el Sub-proyecto 1 de una herramienta mayor; el Sub-proyecto 2 (tracker visual, checklist ghost-ops, reporte HTML) consume los datos que este motor produce.

Inspirado explícitamente en la arquitectura de RedAmon ([[reference_tools_methodology]]) pero sin su stack pesado (sin Docker-in-Docker, sin Neo4j, sin LangGraph de 14 nodos) — se toman sus *patrones*, no su implementación.

## No-objetivos (fuera de alcance v1)

- Fireteam / multi-agente paralelo (RedAmon lo tiene, v1 acá es un solo agente, un solo target a la vez)
- Deep Think / hipótesis competidoras — se evalúa para v2 si el agente se traba mucho
- Sync multiusuario o multi-dispositivo — export/import JSON manual alcanza
- Tracker visual, checklist de fases, generador de reporte — eso es Sub-proyecto 2
- Tests automatizados formales — validación manual contra máquina HTB ya resuelta

## Arquitectura

```
┌─────────────────────────────┐         ┌──────────────────────────┐
│  Browser (index.html + JS)  │         │  bridge.py (stdlib only)  │
│  - Agent loop (ReAct)       │  fetch  │  - POST /exec             │
│  - IndexedDB (estado)       │ ──────► │    valida scope-lock      │
│  - UI de confirmación       │         │    corre subprocess       │
└──────────────┬───────────────┘        │    devuelve stdout/stderr │
               │ fetch directo           └──────────────────────────┘
               ▼
     Ollama API (localhost:11434)
```

Dos procesos: `python3 bridge.py` (sirve el HTML estático + expone `/exec`) y el navegador. Sin base de datos externa, sin contenedores.

## Componentes

### 1. `bridge.py`

Un solo archivo, librería estándar de Python únicamente (sin pip install). Responsabilidades:

- Sirve `index.html`/`app.js`/`style.css` como archivos estáticos (`http.server` o equivalente mínimo).
- `POST /exec` recibe `{tool, args, target}`. Antes de ejecutar:
  1. **Scope-lock check**: compara `target` contra el scope fijado en la sesión activa (guardado server-side en memoria del proceso, seteado una vez al arrancar el engagement vía `POST /engagement/start {scope}`). Si no coincide → 403, no ejecuta.
  2. Corre el comando vía `subprocess.run`, captura stdout/stderr/exit code, con timeout configurable (default 120s).
- No decide *qué* correr — eso lo decide el agente en el browser. El bridge es solo ejecutor + guardián de scope. Esto es deliberado: mantiene el bridge auditable en una sola lectura, todo el "cerebro" vive en JS donde es más fácil de iterar.
- Logea cada ejecución (comando, timestamp, resultado) a un archivo local append-only (`~/.auditor/exec.log`) — rastro de auditoría independiente de lo que guarde el browser, por si el navegador se cierra a mitad de una operación destructiva.

### 2. Agent loop (browser, JS)

Ciclo ReAct explícito, sin framework:

```
while not done and not paused_for_confirmation:
    state = read_from_indexeddb()
    decision = call_ollama(state, available_tools, axis_ledger)
    if decision.tool in DANGEROUS_TOOLS:
        pause_and_show_confirmation_ui(decision)
        break  # loop se retoma cuando el operador confirma/rechaza
    result = call_bridge_exec(decision.tool, decision.args, target)
    save_step_to_indexeddb(decision, result)
    update_axis_ledger(decision)
```

`DANGEROUS_TOOLS` es una constante en el código (lista inicial: dump de credenciales — secretsdump/DCSync, exploits conocidos por tumbar servicios, cualquier escritura de archivo en el target). Editable a mano, no generada dinámicamente por el LLM.

### 3. Guardrails

- **Scope-lock** (server-side, en `bridge.py`) — descrito arriba. Es la defensa principal: aunque el JS del browser esté comprometido o el LLM alucine un target erróneo, el bridge lo bloquea.
- **Confirmación en destructivas** (browser) — cualquier `decision.tool` en `DANGEROUS_TOOLS` pausa el loop y muestra un modal con el comando exacto que se va a correr; el operador aprueba o rechaza. Rechazar registra el rechazo en `steps` y el agente recibe ese contexto en la siguiente iteración (para no repetir el mismo intento).

### 4. Anti-loop — axis ledger

Por cada `(tool, params_fijos)` — ej. `(hydra, target=/login, fixed_user=admin)` — se incrementa un contador en IndexedDB. Al llegar a 3 intentos sin que el resultado cambie de forma sustancial (mismo exit code + longitud de output similar), el próximo prompt a Ollama incluye una línea explícita: *"Ya intentaste (tool, params) 3 veces sin resultado nuevo. Cambiá un parámetro distinto o abandoná este vector."* No bloquea el intento —solo lo nombra, igual que el patrón de RedAmon— para no ser demasiado rígido en casos legítimos donde repetir con timing distinto sí ayuda (ej. race conditions).

### 5. Modelo de datos (IndexedDB)

| Tabla | Campos clave | Uso |
|---|---|---|
| `engagement` | id, target, scope, started_at, status | Un engagement activo a la vez en v1 |
| `steps` | id, engagement_id, tool, args, output, exit_code, verdict, timestamp | Historial completo, fuente de verdad del agente |
| `findings` | id, engagement_id, type (cred/vuln/flag), value, source_step_id | Hallazgos extraídos, para el reporte del Sub-proyecto 2 |
| `axis_ledger` | id, engagement_id, tool, params_hash, attempt_count, last_result_hash | Anti-loop |

Todas exportables a un único JSON vía botón "Export" — es el artefacto que después se puede importar a mano al brain de ghost-ops, o guardar en el repo `tocororo` como respaldo de auditoría.

## Manejo de errores

- Bridge caído / no responde → agente pausa el loop, UI muestra "bridge desconectado, reiniciá `python3 bridge.py`".
- Comando timeout (120s default) → se registra como `verdict: timeout`, cuenta como intento fallido para el axis ledger, el agente decide si reintentar con timeout mayor o cambiar de táctica.
- Ollama no responde / modelo no cargado → mismo tratamiento que bridge caído, mensaje específico apuntando a `ollama list` / `ollama serve`.
- Scope-lock rechaza un comando → se registra en `steps` con `verdict: scope_violation`, visible en la UI en rojo, el agente NO reintenta automáticamente ese target (requiere intervención humana explícita para ampliar scope).

## Testing

Sin suite automatizada en v1 (herramienta de un solo operador, no producto distribuido). Validación: correr el motor contra una máquina HTB ya resuelta con ghost-ops (ej. Forest o Sauna, documentadas en `ghost-ops-brain.md`) y confirmar que:
1. El scope-lock rechaza intentos fuera de la IP fijada (prueba manual: pedirle al agente explícitamente un target falso y confirmar bloqueo).
2. El gate de confirmación efectivamente pausa antes de una acción marcada como peligrosa.
3. El axis ledger dispara el mensaje de "cambiá de táctica" al 3er intento repetido.
4. El export JSON contiene todo lo esperado (steps, findings, axis_ledger) y es válido.
