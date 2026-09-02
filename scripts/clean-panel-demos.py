#!/usr/bin/env python3
"""Replace demo main-content blocks in panel/*.html with clean empty states."""

from __future__ import annotations

import re
from pathlib import Path

PANEL = Path(__file__).resolve().parent.parent / "panel"

CTA = """<a href="start-engagement.html" class="px-md py-sm bg-primary-container text-on-primary-container rounded-lg font-label-md flex items-center gap-xs hover:bg-primary transition-colors">
<i data-lucide="plus" class="icon-sm"></i>
<span data-i18n="nav.newScan">Nuevo escaneo</span>
</a>"""

def empty_block(icon: str, title_key: str, title: str, lead_key: str, lead: str, extra: str = "") -> str:
    return f"""<div class="max-w-container-max mx-auto flex flex-col gap-lg">
<div>
<h2 class="font-headline-lg text-headline-lg text-on-surface tracking-tight" data-i18n="{title_key}">{title}</h2>
<p class="font-body-md text-on-surface-variant mt-xs" data-i18n="{lead_key}">{lead}</p>
</div>
<div class="glass-panel rounded-xl ds-empty">
<div class="ds-empty-icon"><i data-lucide="{icon}" class="icon-lg"></i></div>
<p class="font-headline-md text-on-surface" data-i18n="empty.title">Sin datos todavía</p>
<p class="font-body-md text-on-surface-variant max-w-lg" data-i18n="empty.lead">Inicia un engagement desde New Scan para poblar esta vista con hallazgos reales del motor.</p>
{extra}
{CTA}
</div>
</div>"""

def kpi_dashboard() -> str:
    cards = [
        ("folder-kanban", "dash.kpi.engagements", "Engagements activos"),
        ("triangle-alert", "dash.kpi.critical", "Hallazgos críticos"),
        ("radar", "dash.kpi.scans", "Escaneos activos"),
        ("clock", "dash.kpi.mttr", "MTTR (días)"),
    ]
    kpi_html = ""
    for icon, label_key, label in cards:
        kpi_html += f"""
<div class="glass-panel rounded-lg p-md flex flex-col justify-between">
<div class="w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-primary mb-lg">
<i data-lucide="{icon}" class="icon-lg"></i>
</div>
<p class="font-body-sm text-on-surface-variant mb-xs" data-i18n="{label_key}">{label}</p>
<h3 class="font-headline-xl text-on-surface ds-kpi-zero">0</h3>
</div>"""
    return f"""<div class="max-w-container-max mx-auto flex flex-col gap-lg">
<div>
<h2 class="font-headline-lg text-headline-lg text-on-surface" data-i18n="dash.title">Dashboard</h2>
<p class="font-body-md text-on-surface-variant mt-xs" data-i18n="dash.lead">Vista general de operaciones. Los KPIs se actualizan cuando hay un engagement activo.</p>
</div>
<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-md">{kpi_html}
</div>
<div class="grid grid-cols-1 xl:grid-cols-2 gap-md">
<div class="glass-panel rounded-xl ds-empty min-h-[240px]">
<div class="ds-empty-icon"><i data-lucide="line-chart" class="icon-lg"></i></div>
<p class="font-headline-md text-on-surface" data-i18n="empty.trends">Sin tendencias</p>
<p class="font-body-sm text-on-surface-variant">Los gráficos aparecerán cuando haya hallazgos registrados.</p>
</div>
<div class="glass-panel rounded-xl ds-empty min-h-[240px]">
<div class="ds-empty-icon"><i data-lucide="list" class="icon-lg"></i></div>
<p class="font-headline-md text-on-surface" data-i18n="empty.engagements">Sin engagements</p>
<p class="font-body-sm text-on-surface-variant mb-md">Arranca el motor y la consola desde New Scan.</p>
{CTA}
</div>
</div>
</div>"""

PAGES: dict[str, str] = {
    "index.html": kpi_dashboard(),
    "active-scans.html": empty_block("radar", "scans.title", "Escaneos activos", "scans.lead", "Monitoreo de escaneos en curso e historial."),
    "vulnerabilities.html": empty_block("bug", "vulns.title", "Vulnerabilidades", "vulns.lead", "Inventario consolidado de vulnerabilidades detectadas."),
    "critical-findings.html": empty_block("triangle-alert", "critical.title", "Hallazgos críticos", "critical.lead", "Hallazgos de severidad crítica pendientes de remediación."),
    "assets.html": empty_block("boxes", "assets.title", "Activos", "assets.lead", "Inventario de activos descubiertos durante el engagement."),
    "osint.html": empty_block("binoculars", "osint.title", "OSINT", "osint.lead", "Inteligencia de fuentes abiertas vinculada al target."),
    "remediation-metrics.html": empty_block("gauge", "metrics.title", "Métricas de remediación", "metrics.lead", "SLA, MTTR y progreso de remediación."),
    "attack-graph.html": empty_block("share-2", "graph.title", "Grafo de ataque", "graph.lead", "Visualización de rutas de ataque y pivotes."),
    "graph-evidence.html": empty_block("route", "evidence.title", "Evidencia de grafo", "evidence.lead", "Detalle de evidencia para un nodo o path del grafo."),
    "mitre.html": empty_block("swords", "mitre.title", "MITRE ATT&CK", "mitre.lead", "Cobertura de técnicas observadas en el engagement."),
    "kill-chain.html": empty_block("git-branch", "kill.title", "Kill Chain", "kill.lead", "Cadena de ataque reconstruida a partir de hallazgos."),
    "reporting.html": empty_block("chart-column", "report.title", "Informes", "report.lead", "Genera informes PDF/HTML cuando el engagement esté completo."),
    "comprehensive-report.html": empty_block("file-text", "report.full", "Informe integral", "report.fullLead", "Documento completo del engagement. Abrilo desde Reporting cuando haya datos."),
    "report-preview.html": empty_block("file-search", "report.preview", "Vista previa PDF", "report.previewLead", "Configuración y preview del informe exportable."),
    "executive-summary.html": empty_block("briefcase", "exec.title", "Resumen ejecutivo", "exec.lead", "Síntesis para stakeholders. Se genera desde Reporting."),
    "finding-detail.html": empty_block("search", "finding.title", "Detalle de hallazgo", "finding.lead", "Abre un hallazgo desde Notificaciones o Critical Findings."),
    "findings-summary.html": empty_block("layout-list", "summary.title", "Resumen de hallazgos", "summary.lead", "Matriz y distribución de severidades del engagement."),
    "remediation-plan.html": empty_block("list-checks", "rem.plan", "Plan de remediación", "rem.planLead", "Plan por fases derivado de los hallazgos aceptados."),
    "gdpr-alignment.html": empty_block("scale", "gdpr.title", "Alineación RGPD", "gdpr.lead", "Mapeo de hallazgos contra obligaciones RGPD."),
    "maturity-index.html": empty_block("target", "maturity.title", "Índice de madurez", "maturity.lead", "Evaluación de madurez de seguridad post-auditoría."),
    "remediation-detail.html": empty_block("wrench", "rem.detail", "Detalle de remediación", "rem.detailLead", "Flujo de remediación para un hallazgo. Accede desde Critical Findings."),
    "verification-request.html": empty_block("shield-check", "verify.title", "Solicitud de verificación", "verify.lead", "Modal de verificación post-remediación."),
    "remediation-complete.html": empty_block("circle-check", "rem.done", "Remediación completada", "rem.doneLead", "Confirmación tras enviar evidencia de verificación."),
    "tool-approval.html": empty_block("shield-alert", "tool.approve", "Aprobación de herramienta", "tool.approveLead", "Gate humano para herramientas peligrosas. Se abre desde Active Engagement."),
}

AVATAR_RE = re.compile(
    r'<img[^>]*(?:googleusercontent|aida-public)[^>]*/>',
    re.I,
)
AVATAR_REPLACE = '<div class="w-full h-full flex items-center justify-center bg-primary-container/15 text-primary font-label-md" aria-hidden="true">DS</div>'


def replace_main(html: str, new_main: str) -> str:
    pattern = re.compile(
        r'(<main id="main-content"[^>]*>)(.*?)(</main>)',
        re.DOTALL | re.I,
    )
    m = pattern.search(html)
    if not m:
        return html
    return html[: m.start()] + m.group(1) + "\n" + new_main + "\n" + m.group(3) + html[m.end() :]


def inject_empty_css(html: str) -> str:
    if "empty-state.css" in html:
        return html
    return html.replace(
        '<link href="vendor/tokens.css" rel="stylesheet"/>',
        '<link href="vendor/tokens.css" rel="stylesheet"/>\n<link href="vendor/empty-state.css" rel="stylesheet"/>',
    )


def fix_bell(html: str) -> str:
    html = re.sub(
        r'<button([^>]*?)>\s*<i data-lucide="bell"',
        r'<button\1 type="button" aria-label="Notifications" data-i18n-aria="aria.notifications">\n<i data-lucide="bell"',
        html,
        count=1,
    )
    html = html.replace(
        '<span class="absolute top-2 right-2 w-2 h-2 bg-error rounded-full border border-white"></span>',
        '<span class="absolute top-2 right-2 w-2 h-2 bg-error rounded-full border border-white hidden"></span>',
    )
    return html


def clean_settings(html: str) -> str:
    html = replace_main(
        html,
        empty_block("settings", "settings.title", "Ajustes", "settings.lead", "Apariencia, idioma y preferencias de la organización.")
        + """
<div class="glass-panel rounded-xl p-lg max-w-2xl flex flex-col gap-md mt-lg">
<label class="font-label-md text-on-surface-variant" for="org-name">Organización</label>
<input id="org-name" class="w-full rounded-lg border border-outline-variant/50 px-md py-sm bg-surface-container-lowest" placeholder="—" type="text"/>
<label class="font-label-md text-on-surface-variant" for="org-email">Contacto</label>
<input id="org-email" class="w-full rounded-lg border border-outline-variant/50 px-md py-sm bg-surface-container-lowest" placeholder="—" type="email"/>
</div>""",
    )
    return html


def clean_profile(html: str) -> str:
    html = replace_main(
        html,
        """<div class="max-w-container-max mx-auto flex flex-col gap-lg">
<div>
<h2 class="font-headline-lg text-on-surface" data-i18n="profile.title">Perfil</h2>
<p class="font-body-md text-on-surface-variant mt-xs" data-i18n="profile.lead">Datos del operador en la consola.</p>
</div>
<div class="glass-panel rounded-xl p-xl max-w-xl flex flex-col gap-md">
<div class="w-16 h-16 rounded-full bg-primary-container/15 text-primary flex items-center justify-center font-headline-md">—</div>
<label class="font-label-md text-on-surface-variant" for="profile-name">Nombre</label>
<input id="profile-name" class="w-full rounded-lg border border-outline-variant/50 px-md py-sm" placeholder="—" type="text"/>
<label class="font-label-md text-on-surface-variant" for="profile-email">Email</label>
<input id="profile-email" class="w-full rounded-lg border border-outline-variant/50 px-md py-sm" placeholder="—" type="email"/>
<label class="font-label-md text-on-surface-variant" for="profile-role">Rol</label>
<input id="profile-role" class="w-full rounded-lg border border-outline-variant/50 px-md py-sm" placeholder="—" type="text"/>
</div>
</div>""",
    )
    return html


def main() -> None:
    for path in sorted(PANEL.glob("*.html")):
        name = path.name
        if name in ("engagement.html", "start-engagement.html", "notifications.html", "help-center.html"):
            text = path.read_text(encoding="utf-8")
            text = inject_empty_css(text)
            text = AVATAR_RE.sub(AVATAR_REPLACE, text)
            text = fix_bell(text)
            path.write_text(text, encoding="utf-8")
            print(f"  chrome-only: {name}")
            continue
        if name == "settings.html":
            text = inject_empty_css(clean_settings(path.read_text(encoding="utf-8")))
            text = AVATAR_RE.sub(AVATAR_REPLACE, text)
            text = fix_bell(text)
            path.write_text(text, encoding="utf-8")
            print(f"  cleaned: {name}")
            continue
        if name == "profile.html":
            text = inject_empty_css(clean_profile(path.read_text(encoding="utf-8")))
            text = AVATAR_RE.sub(AVATAR_REPLACE, text)
            text = fix_bell(text)
            path.write_text(text, encoding="utf-8")
            print(f"  cleaned: {name}")
            continue
        if name not in PAGES:
            print(f"  skip: {name}")
            continue
        text = path.read_text(encoding="utf-8")
        text = inject_empty_css(text)
        text = replace_main(text, PAGES[name])
        text = AVATAR_RE.sub(AVATAR_REPLACE, text)
        text = fix_bell(text)
        path.write_text(text, encoding="utf-8")
        print(f"  cleaned: {name}")
    print("Done.")


if __name__ == "__main__":
    main()
