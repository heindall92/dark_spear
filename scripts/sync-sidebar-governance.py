#!/usr/bin/env python3
"""Insert Gobernanza nav block after Informes in all panel shells."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "panel"
MARKER = 'data-i18n="nav.govSection"'

GOV_BLOCK = """
<div class="border-t border-outline-variant/30 mx-sm my-xs pt-sm flex flex-col gap-base">
<p class="px-md pb-xs font-label-md text-label-md text-on-surface-variant uppercase tracking-wide" data-i18n="nav.govSection">Gobernanza</p>
<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-low transition-colors duration-200" href="gdpr-alignment.html" data-nav-page="gdpr-alignment.html">
<i data-lucide="scale"></i>
<span data-i18n="nav.gdpr">Alineación RGPD</span>
</a>
<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-low transition-colors duration-200" href="maturity-index.html" data-nav-page="maturity-index.html">
<i data-lucide="grid-3x3"></i>
<span data-i18n="nav.maturity">Matriz de riesgos</span>
</a>
<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-low transition-colors duration-200" href="remediation-plan.html" data-nav-page="remediation-plan.html">
<i data-lucide="list-checks"></i>
<span data-i18n="nav.remPlan">Plan de remediación</span>
</a>
<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-low transition-colors duration-200" href="kill-chain.html" data-nav-page="kill-chain.html">
<i data-lucide="git-branch"></i>
<span data-i18n="nav.killchain">Kill Chain</span>
</a>
</div>
"""


KILL_MARKER = 'data-i18n="nav.killchain"'
KILL_LINK = """<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-low transition-colors duration-200" href="kill-chain.html" data-nav-page="kill-chain.html">
<i data-lucide="git-branch"></i>
<span data-i18n="nav.killchain">Kill Chain</span>
</a>
"""


def insert_governance(text: str) -> str:
    if MARKER in text:
        return text
    idx = text.find('href="osint.html"')
    if idx < 0:
        return text
    start = text.rfind("<a ", 0, idx)
    if start < 0:
        return text
    return text[:start] + GOV_BLOCK + "\n" + text[start:]


def insert_killchain(text: str) -> str:
    """Kill Chain in the Gobernanza block (after Plan de remediación)."""
    text = re.sub(
        r'<a class="flex items-center gap-md px-md py-sm rounded-lg[^"]*"[^>]*href="kill-chain.html"[^>]*>.*?</a>\s*',
        "",
        text,
        flags=re.DOTALL,
    )
    pattern = re.compile(
        r'(<a class="flex items-center gap-md px-md py-sm rounded-lg[^"]*"[^>]*href="remediation-plan.html"[^>]*>.*?</a>\s*)',
        re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        return text
    return text[: m.end()] + KILL_LINK + text[m.end() :]


def highlight_page(text: str, page: str) -> str:
    """Mark current page in main nav + governance subsection."""
    pages = {
        "index.html",
        "remediation-metrics.html",
        "engagement.html",
        "active-scans.html",
        "vulnerabilities.html",
        "critical-findings.html",
        "reporting.html",
        "gdpr-alignment.html",
        "maturity-index.html",
        "remediation-plan.html",
        "osint.html",
        "attack-graph.html",
        "mitre.html",
        "kill-chain.html",
        "assets.html",
    }
    if page not in pages:
        return text

    def repl(m: re.Match) -> str:
        href = m.group(1)
        is_active = href == page
        data_nav = re.search(r'data-nav-page="[^"]*"', m.group(0))
        data_attr = (" " + data_nav.group(0)) if data_nav else ""
        if is_active:
            return (
                '<a class="flex items-center gap-md px-md py-sm rounded-lg text-primary font-semibold '
                'border-l-4 border-primary bg-primary-container/10 transition-colors duration-200" '
                f'href="{href}" aria-current="page"{data_attr}>'
            )
        return (
            '<a class="flex items-center gap-md px-md py-sm rounded-lg text-on-surface-variant '
            'hover:text-primary hover:bg-surface-container-low transition-colors duration-200" '
            f'href="{href}"{data_attr}>'
        )

    pattern = re.compile(
        r'<a class="flex items-center gap-md px-md py-sm rounded-lg[^"]*"[^>]*href="([^"]+\.html)"[^>]*>',
    )
    return pattern.sub(repl, text)


def dedupe_href(text: str) -> str:
    return re.sub(r'(href="[^"]+")\s+href="[^"]+"', r"\1", text)


def main() -> None:
    updated = 0
    for path in sorted(ROOT.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        if 'data-app-nav' not in text:
            continue
        new = insert_governance(text)
        new = insert_killchain(new)
        new = dedupe_href(new)
        new = highlight_page(new, path.name)
        if new != text:
            path.write_text(new, encoding="utf-8")
            updated += 1
            print("  updated", path.name)
    print(f"Done — {updated} files")


if __name__ == "__main__":
    main()
