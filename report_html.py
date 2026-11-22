# SPDX-License-Identifier: AGPL-3.0-only
"""Self-contained, safe-to-open HTML reports for GitAudit AI.

Never include source lines or matching fragments, and never load remote assets.
All repository-derived text is HTML-escaped and links stay on github.com.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from html import escape
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING
from urllib.parse import quote

from audit_guidance import guidance_for
from version import __version__

if TYPE_CHECKING:
    from gitaudit import AuditResult, Finding


CSS = """
:root { color-scheme: dark; --bg:#090e17; --card:#131c2b; --edge:#2b384d;
--ink:#edf4ff; --muted:#acbbcf; --mint:#65dec0; --blue:#80bfff;
--amber:#ffd184; --rose:#ff9cab; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin:0; font: 16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
background:radial-gradient(circle at 80% -10%,#23344e 0,#090e17 43%) fixed;
color:var(--ink); }
a { color:var(--blue); overflow-wrap:anywhere; }
a:hover { text-decoration-thickness:3px; }
:focus-visible { outline:3px solid var(--mint); outline-offset:3px; }
.skip { position:absolute; transform:translateY(-200%); left:1rem; top:.5rem;
padding:.5rem; background:var(--card); z-index:9; }
.skip:focus { transform:none; }
.container { width:min(1120px,calc(100% - 2rem)); margin:0 auto; }
header { border-bottom:1px solid var(--edge); padding:2.1rem 0 1.5rem; }
.brand { color:var(--mint); letter-spacing:.16em; text-transform:uppercase;
font-size:.76rem; font-weight:750; }
h1 { font-size:clamp(1.65rem,5vw,3.2rem); line-height:1.13;
margin:.6rem 0; overflow-wrap:anywhere; }
h2 { font-size:1.4rem; margin:2rem 0 .75rem; }
h3 { font-size:1.08rem; margin:.1rem 0; }
p { margin:.45rem 0 1rem; }
code { font: .9em/1.5 ui-monospace,monospace; overflow-wrap:anywhere; }
.muted { color:var(--muted); }
.eyebrow { color:var(--mint); font-weight:700; }
.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
gap:.8rem; margin:1.3rem 0 1rem; }
.metric { border:1px solid var(--edge); background:var(--card);
border-radius:12px; padding:1rem; }
.metric strong { display:block; font-size:1.75rem; line-height:1.2; }
.metric span { display:block; color:var(--muted); font-size:.83rem; margin-top:.35rem; }
.note { border-left:4px solid var(--amber); padding:1rem 1.15rem;
background:#26251d; border-radius:6px; }
.note.important { border-left-color:var(--rose); }
.legend { display:flex; flex-wrap:wrap; gap:.7rem; margin:.7rem 0 1rem; }
.pill { font-size:.78rem; font-weight:700; background:#233348;
border:1px solid #425a76; border-radius:999px; padding:.12rem .55rem;
white-space:nowrap; }
.pill.risk { color:var(--rose); }
.pill.review { color:var(--amber); }
.pill.maintenance { color:var(--mint); }
.findings { display:grid; gap:1rem; margin:1rem 0 2rem; }
.rule-card { background:var(--card); border:1px solid var(--edge);
border-radius:13px; padding:1rem 1.2rem; }
.rule-header { display:flex; justify-content:space-between; flex-wrap:wrap;
gap:.8rem; align-items:flex-start; margin-bottom:.5rem; }
.tags { display:flex; flex-wrap:wrap; align-items:center; gap:.4rem; }
.rule-code { font:700 .9em/1.3 ui-monospace,monospace; color:var(--mint); }
.detail { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
gap:.8rem; margin:.9rem 0; }
.detail > div { border-top:1px solid var(--edge); padding-top:.7rem; }
.detail b { display:block; margin-bottom:.25rem; font-size:.85rem; }
summary { cursor:pointer; font-weight:650; }
.locations { margin:.6rem 0; padding-left:1.4rem; }
.locations li { padding:.18rem 0; }
footer { padding:2.5rem 0 3rem; color:var(--muted); border-top:1px solid var(--edge);
font-size:.88rem; }
@media (max-width:600px) { header { padding-top:1.4rem; }
.metric strong { font-size:1.45rem; } .rule-card { padding:.9rem; } }
@media (prefers-reduced-motion:reduce) { html { scroll-behavior:auto; } }
"""


def source_url(repository: str, reference: str | None, path: str, line: int) -> str | None:
    """Build only GitHub source links, refusing untrusted repository or paths."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repository):
        return None
    if not isinstance(line, int) or line <= 0:
        return None
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or any(part in (".", "..") for part in parts):
        return None
    if reference is not None and (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", reference)
        or ".." in reference or "//" in reference
    ):
        return None
    owner, repo = repository.split("/", 1)
    ref = quote(reference or "HEAD", safe="/")
    safe_path = quote(path, safe="/")
    return f"https://github.com/{owner}/{repo}/blob/{ref}/{safe_path}#L{line}"


def render_html(result: "AuditResult") -> str:
    """Offline report: inline CSS only, escaped content, no JavaScript."""
    esc = lambda text: escape(str(text), quote=True)
    categories = Counter(f.category for f in result.findings)
    severities = Counter(f.severity for f in result.findings)
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        by_rule[finding.rule].append(finding)

    rank = {"risk": 0, "review": 1, "maintenance": 2}
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    groups = sorted(
        by_rule.items(),
        key=lambda item: (
            rank.get(item[1][0].category, 9),
            sev_rank.get(item[1][0].severity, 9),
            item[0],
        ),
    )

    chunks = [
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
        f'<title>GitAudit AI v{__version__} — {esc(result.repository)}</title>',
        f'<style>{CSS}</style></head><body>',
        '<a class="skip" href="#main">Aller au rapport</a>',
        f'<header><div class="container"><div class="brand">GitAudit AI v{__version__} / Rapport local</div>',
        f'<h1>{esc(result.repository)}</h1>',
        f'<p class="muted">Référence : <code>{esc(result.reference or "branche par défaut")}</code> '
        '· Analyse statique, sans exécution du dépôt.</p></div></header>',
        '<main id="main" class="container">',
        '<h2>Résumé de l’analyse</h2>',
        '<div class="summary">',
    ]
    metrics = (
        (result.scanned_files, "Fichiers examinés"),
        (result.scanned_lines, "Lignes parcourues"),
        (categories["risk"], "Risques potentiels à vérifier"),
        (categories["review"], "Points de revue"),
        (categories["maintenance"], "Maintenance"),
        (result.skipped_files, "Fichiers ignorés"),
    )
    for value, label in metrics:
        chunks.append(
            f'<div class="metric"><strong>{esc(value)}</strong><span>{esc(label)}</span></div>'
        )
    chunks += [
        '</div>',
        '<p class="muted">Priorités : '
        f'{severities["high"]} élevées, {severities["medium"]} moyennes, '
        f'{severities["low"]} faibles. '
        f'Analyse partielle : {"oui" if result.partial else "non"}.</p>',
        '<p class="note important"><strong>Attention :</strong> chaque résultat est un '
        'indice heuristique et non une vulnérabilité prouvée. Aucun résultat détecté '
        'ne signifie pas que le dépôt est sécurisé. Des faux positifs et des omissions '
        'restent possibles.</p>',
        '<h2>Constats et recommandations</h2>',
        '<p class="muted">Les résultats sont regroupés par règle. Ouvrez les emplacements '
        'pour consulter les fichiers concernés sur GitHub, si un lien sûr est disponible.</p>',
        '<div class="legend"><span class="pill risk">Risque potentiel</span>'
        '<span class="pill review">Revue humaine</span>'
        '<span class="pill maintenance">Maintenance</span></div>',
        '<div class="findings">',
    ]
    if not groups:
        chunks.append(
            '<section class="rule-card"><h3>Aucun indice détecté</h3>'
            '<p>Les règles limitées de cette version n’ont rien relevé. '
            'Ce résultat ne certifie pas la sécurité du projet.</p></section>'
        )
    for rule_id, findings in groups:
        finding = findings[0]
        guidance = guidance_for(rule_id)
        cat = finding.category if finding.category in rank else "risk"
        category_name = {
            "risk": "Risque potentiel", "review": "Revue humaine",
            "maintenance": "Maintenance",
        }[cat]
        chunks += [
            '<section class="rule-card">',
            '<div class="rule-header"><div>',
            f'<span class="rule-code">{esc(rule_id)}</span>',
            f'<h3>{esc(finding.title)}</h3></div>',
            '<div class="tags">',
            f'<span class="pill {cat}">{category_name}</span>',
            f'<span class="pill">Priorité {esc(finding.severity)}</span>',
            f'<span class="pill">{len(findings)} occurrence(s)</span>',
            '</div></div>',
            '<div class="detail">',
            f'<div><b>Pourquoi examiner ?</b><p>{esc(guidance.meaning)}</p></div>',
            f'<div><b>Action conseillée</b><p>{esc(guidance.action)}</p></div>',
            f'<div><b>Comment vérifier ?</b><p>{esc(guidance.verify)}</p></div>',
            '</div>',
            f'<details><summary>Emplacements ({len(findings)})</summary>',
            '<ol class="locations">',
        ]
        for f in findings:
            position = f"{f.path}:{f.line}"
            link = source_url(result.repository, result.reference, f.path, f.line)
            if link:
                chunks.append(
                    f'<li><a href="{esc(link)}" rel="noopener noreferrer">'
                    f'<code>{esc(position)}</code></a></li>'
                )
            else:
                chunks.append(f'<li><code>{esc(position)}</code></li>')
        chunks += ['</ol></details></section>']
    chunks += [
        '</div></main>',
        '<footer><div class="container"><strong>Limites :</strong> analyse statique '
        'heuristique de fichiers sélectionnés, dépendances et configuration en production '
        'non vérifiées. Aucune exécution du dépôt cible. Rapport autonome, sans '
        'JavaScript ni chargement de ressources externes.</div></footer>',
        '</body></html>',
    ]
    return "\n".join(chunks) + "\n"
