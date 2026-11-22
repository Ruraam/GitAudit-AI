# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, read-only metadata checks for GitHub workflows and dependency manifests.

No workflow steps or dependency install commands are executed. This is NOT
a full YAML/TOML parser and does NOT query a vulnerability database.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re


@dataclass(frozen=True)
class MetadataSpec:
    identifier: str
    severity: str
    title: str
    advice: str
    category: str
    meaning: str
    action: str
    verify: str


SPECS: tuple[MetadataSpec, ...] = (
    MetadataSpec(
        "WF001", "medium", "Action GitHub non épinglée à un SHA complet",
        "Évaluer l'épinglage à un SHA complet de 40 caractères pour limiter les changements inattendus.",
        "review",
        "Une action tierce (ou officielle) est appelée via un tag ou une branche mutable.",
        "Envisager un SHA de commit complet, documenter la version et organiser ses mises à jour.",
        "Vérifier la provenance du dépôt d'action et les contrôles de mise à jour.",
    ),
    MetadataSpec(
        "WF002", "high", "GitHub Actions : permissions globales en écriture",
        "Réduire permissions: write-all aux droits nécessaires par tâche.",
        "review",
        "write-all accorde un vaste ensemble de permissions au jeton du workflow.",
        "Définir des permissions minimales au niveau du workflow ou des jobs.",
        "Contrôler chaque usage du GITHUB_TOKEN et les permissions effectives.",
    ),
    MetadataSpec(
        "WF003", "medium", "Événement pull_request_target à examiner",
        "Vérifier la frontière de confiance des contributions non fiables.",
        "review",
        "pull_request_target peut donner accès au contexte de la branche de base et à des secrets.",
        "Éviter d'exécuter du code provenant de PR non fiables avec des permissions élevées.",
        "Tester les scénarios de contributions externes et vérifier la configuration des permissions.",
    ),
    MetadataSpec(
        "WF004", "medium", "Checkout conserve explicitement les identifiants",
        "Examiner persist-credentials: true et privilégier false si inutile.",
        "review",
        "La persistance des identifiants Git peut exposer des jetons aux étapes ultérieures.",
        "Passer persist-credentials: false lorsqu'aucun push authentifié n'est nécessaire.",
        "Confirmer le fonctionnement des étapes sans conservation des identifiants.",
    ),
    MetadataSpec(
        "WF005", "medium", "Workflow : droit contents en écriture",
        "Limiter contents: write aux jobs qui en ont besoin.",
        "review",
        "Un jeton avec contents: write peut modifier le contenu d'un dépôt.",
        "Préférer contents: read par défaut et n'accorder write qu'au job concerné.",
        "Vérifier les permissions réelles et les cas de création de releases.",
    ),
    MetadataSpec(
        "DEP001", "medium", "NPM : version de dépendance non bornée",
        "Remplacer * ou latest par une politique de versions contrôlée et un lockfile.",
        "review",
        "Une dépendance directe utilise un sélecteur totalement flottant.",
        "Définir une version maîtrisée et conserver un lockfile cohérent.",
        "Vérifier l'installation reproductible avec npm ci ou un équivalent adapté.",
    ),
    MetadataSpec(
        "DEP002", "high", "NPM : dépendance téléchargée via HTTP non chiffré",
        "Utiliser HTTPS ou une source authentifiée avec contrôle d'intégrité.",
        "risk",
        "Une dépendance directe référence une URL HTTP non chiffrée.",
        "Migrer vers HTTPS et vérifier la provenance et les sommes d'intégrité.",
        "Tester les installations dans un environnement isolé avec un verrouillage des dépendances.",
    ),
    MetadataSpec(
        "DEP003", "medium", "Python requirements : version non fixée",
        "Envisager un fichier de contraintes et des versions contrôlées.",
        "review",
        "Une dépendance requirements.txt ne fixe pas une version exacte ; c'est parfois volontaire.",
        "Utiliser des contraintes appropriées et un lockfile quand le déploiement exige la reproductibilité.",
        "Vérifier la résolution et les mises à jour des dépendances dans une CI contrôlée.",
    ),
    MetadataSpec(
        "DEP004", "medium", "Cargo : version de dépendance totalement flottante",
        "Éviter la contrainte de version * lorsque possible et maintenir Cargo.lock selon le type de projet.",
        "review",
        "La déclaration Cargo comporte une contrainte * qui accepte de multiples versions.",
        "Adopter une plage de versions réfléchie et maintenir Cargo.lock selon le type de projet.",
        "Tester cargo update et les builds reproductibles dans un environnement isolé autorisé.",
    ),
)

_RULES = {s.identifier: s for s in SPECS}
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$", re.I)
_REQUIREMENTS = re.compile(r"^requirements(?:[-_.][A-Za-z0-9_-]+)?\.txt$", re.I)
_ACTION = re.compile(
    r"""^\s*(?:-\s*)?uses\s*:\s*["']?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#'"]+)""",
    re.I,
)
_REQUIREMENT = re.compile(
    r"""^\s*([A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_,.-]+\])?)
        \s*(?:(?:>=|>|~=|!=)\s*[A-Za-z0-9_.-]+)?
        \s*(?:;[^#\n]+)?\s*(?:\#.*)?$""",
    re.X,
)
_CARGO_WILDCARD = re.compile(
    r"""^\s*["']?[A-Za-z0-9_.-]+["']?\s*=\s*
        (?:["']\*["']|\{[^#\n}]*\bversion\s*=\s*["']\*["'][^}\n]*\})""",
    re.X,
)
_JSON_ENTRY = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]+)"')


def _without_comment(line: str) -> str:
    """A small YAML/TOML comment filter that retains quoted hash characters."""
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == "#":
            return line[:index]
    return line


def _workflow_issues(lines: list[str]):
    for line_number, original in enumerate(lines, 1):
        line = _without_comment(original)
        if not line.strip():
            continue
        found = _ACTION.match(line)
        if found and not re.fullmatch(r"[A-Fa-f0-9]{40}", found.group(2)):
            yield "WF001", line_number
        if re.match(r"^\s*permissions\s*:\s*['\"]?write-all(?:['\"]?\s*)?$", line):
            yield "WF002", line_number
        if re.match(r"^\s*(?:-\s*)?pull_request_target\s*:", line):
            yield "WF003", line_number
        if re.match(r"^\s*persist-credentials\s*:\s*true(?:\s|$)", line):
            yield "WF004", line_number
        if re.match(r"^\s*contents\s*:\s*write(?:\s|$)", line):
            yield "WF005", line_number


def _npm_issues(lines: list[str]):
    try:
        data = json.loads("\n".join(lines))
    except (json.JSONDecodeError, RecursionError):
        return
    if not isinstance(data, dict):
        return

    positions: dict[tuple[str, str], int] = {}
    for line_number, line in enumerate(lines, 1):
        match = _JSON_ENTRY.match(line)
        if match:
            positions.setdefault((match.group(1), match.group(2)), line_number)

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            # Avoid unbounded iteration with a malicious 256-KiB manifest.
            if len(name) > 200 or len(version) > 1000:
                continue
            line_no = positions.get((name, version), 1)
            if version in {"*", "latest"}:
                yield "DEP001", line_no
            elif version.startswith(("http://", "git+http://")):
                yield "DEP002", line_no


def _requirements_issues(lines: list[str]):
    for line_number, original in enumerate(lines, 1):
        line = original.strip()
        if not line or line.startswith(("#", "-", ".")) or "://" in line or " @ " in line:
            continue
        if _REQUIREMENT.fullmatch(line):
            yield "DEP003", line_number


def _cargo_issues(lines: list[str]):
    active = False
    for line_number, original in enumerate(lines, 1):
        line = _without_comment(original).strip()
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            active = (
                section in {"dependencies", "dev-dependencies", "build-dependencies",
                            "workspace.dependencies"}
                or section.endswith((".dependencies", ".dev-dependencies", ".build-dependencies"))
            )
            continue
        if active and _CARGO_WILDCARD.match(line):
            yield "DEP004", line_number


def review_metadata(path: PurePosixPath, lines: list[str]) -> list[tuple[MetadataSpec, int]]:
    """Check only known paths. Never executes code or downloads dependencies."""
    relative = str(path)
    if _WORKFLOW.fullmatch(relative):
        issues = _workflow_issues(lines)
    elif path.name == "package.json":
        issues = _npm_issues(lines)
    elif _REQUIREMENTS.fullmatch(path.name):
        issues = _requirements_issues(lines)
    elif path.name == "Cargo.toml":
        issues = _cargo_issues(lines)
    else:
        return []
    return [(_RULES[identifier], line_number) for identifier, line_number in issues]
