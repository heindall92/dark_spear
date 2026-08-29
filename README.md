# Dark Spear

![Intro Dark Spear](panel/vendor/splash.mp4)

Consola SecOps para auditorías autorizadas: engagement, hallazgos, grafo de ataque, MITRE ATT&CK, OSINT, remediación e informes.

Producto: **Dark Spear**. Interfaz en español e inglés.

Repositorio: [heindall92/dark_spear](https://github.com/heindall92/dark_spear)

## Arranque rápido

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

## Qué incluye

- Dashboard, escaneos, vulnerabilidades y hallazgos críticos
- Engagement activo, New Scan, aprobación de herramientas
- Reporting (JSON / HTML / PDF), capítulos de informe y RGPD
- Attack Graph, evidencia de grafo, MITRE ATT&CK, OSINT, activos
- Perfil de usuario, centro de notificaciones, ajustes (tema e idioma)
- Intro de arranque a pantalla completa (`panel/vendor/splash.mp4`)

Tema claro/oscuro e idioma ES/EN se guardan en el navegador (`ds-theme`, `ds-lang`). El menú lateral se retrae a un rail de iconos (`ds-sidebar`).

## Estructura

```
panel/           Consola (HTML estático + vendor)
Sessiones/       Diseños de referencia
LICENSE          MIT
```

## Licencia

[MIT](LICENSE)
