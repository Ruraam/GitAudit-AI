#!/usr/bin/env python3
"""GitAudit AI v0.1: bounded, read-only, heuristic GitHub source audit."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import io
import json
from pathlib import PurePosixPath
import re
import sys
import tarfile
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_UNCOMPRESSED = 150 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 256 * 1024
MAX_FINDINGS = 100

SOURCE_SUFFIXES = frozenset({
    ".py", ".sh", ".bash", ".rs", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".c", ".h", ".cpp", ".hpp", ".java", ".rb", ".php",
    ".kt", ".swift", ".yaml", ".yml", ".toml", ".json", ".html",
})
SOURCE_NAMES = frozenset({"Dockerfile", "Makefile"})
IGNORED_PARTS = frozenset({
    ".git", ".venv", "venv", "node_modules", "vendor", "target",
    "dist", "build", "__pycache__", ".next", ".tox", "coverage",
})
PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx"})
SHELL = frozenset({".sh", ".bash"})


@dataclass(frozen=True)
class Rule:
    identifier: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    suffixes: frozenset[str] | None
    advice: str


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    path: str
    line: int
    advice: str


@dataclass
class AuditResult:
    repository: str
    scanned_files: int
    scanned_lines: int
    skipped_files: int
    findings: list[Finding]
    partial: bool


RULES = (
    Rule("PY001", "medium", "Appel à eval()", re.compile(r"\beval\s*\("), PY,
         "Préférer un analyseur dédié et vérifier les entrées."),
    Rule("PY002", "medium", "shell=True en Python", re.compile(r"\bshell\s*=\s*True\b"), PY,
         "Éviter le shell pour les commandes construites avec des entrées externes."),
    Rule("PY003", "medium", "Désérialisation pickle", re.compile(r"\bpickle\.loads?\s*\("), PY,
         "Ne pas désérialiser de contenu non fiable avec pickle."),
    Rule("PY004", "high", "Vérification TLS désactivée", re.compile(r"\bverify\s*=\s*False\b"), PY,
         "Conserver la validation des certificats TLS."),
    Rule("JS001", "medium", "Appel à eval() en JavaScript", re.compile(r"\beval\s*\("), JS,
         "Éviter d'évaluer du texte comme du code."),
    Rule("SH001", "high", "Script téléchargé exécuté directement",
         re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b"), SHELL,
         "Télécharger, vérifier et examiner le script avant son exécution."),
    Rule("GEN001", "high", "En-tête de clé privée détecté",
         re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), None,
         "Vérifier si la clé est réelle ; la révoquer et la remplacer si elle a été exposée."),
    Rule("GEN002", "low", "Marqueur TODO/FIXME",
         re.compile(r"\b(?:TODO|FIXME)\b"), None,
         "Vérifier si le travail signalé est toujours nécessaire."),
)


def normalize_repository(value: str) -> str:
    """Only owner/repo and HTTPS github.com/owner/repo are accepted."""
    value = value.strip()
    if value.startswith("https://"):
        parsed = urlparse(value)
        if (parsed.hostname or "").lower() != "github.com" or (
            parsed.username or parsed.password or parsed.port or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Seules les URL HTTPS de github.com sont acceptées.")
        value = parsed.path.strip("/")
    elif "://" in value:
        raise ValueError("Seules les URL HTTPS de github.com sont acceptées.")
    parts = value.split("/")
    if len(parts) != 2:
        raise ValueError("Indiquer un dépôt au format owner/repo.")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner):
        raise ValueError("Propriétaire GitHub invalide.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo) or repo in {".", ".."}:
        raise ValueError("Nom de dépôt GitHub invalide.")
    return f"{owner}/{repo}"


def download_archive(repository: str) -> bytes:
    """Get GitHub's default-branch snapshot; never run repository code."""
    url = f"https://api.github.com/repos/{repository}/tarball"
    request = Request(url, headers={
        "User-Agent": "GitAudit-AI/0.1",
        "Accept": "application/vnd.github+json",
    })
    with urlopen(request, timeout=30) as response:
        payload = response.read(MAX_DOWNLOAD + 1)
    if len(payload) > MAX_DOWNLOAD:
        raise ValueError("Archive trop volumineuse (> 20 Mio).")
    return payload


def analyze_archive(payload: bytes, repository: str) -> AuditResult:
    result = AuditResult(repository, 0, 0, 0, [], False)
    unpacked_bytes = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
    except tarfile.TarError as exc:
        raise ValueError("Archive GitHub illisible.") from exc

    with archive:
        for index, member in enumerate(archive):
            if index >= MAX_ARCHIVE_MEMBERS:
                result.partial = True
                break
            if not member.isfile():
                continue
            unpacked_bytes += member.size
            if unpacked_bytes > MAX_ARCHIVE_UNCOMPRESSED:
                result.partial = True
                break
            # GitHub archives prefix every path with a root directory.
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2 or ".." in parts:
                result.skipped_files += 1
                continue
            rel = PurePosixPath(*parts[1:])
            if (
                any(part in IGNORED_PARTS for part in rel.parts)
                or (rel.suffix.lower() not in SOURCE_SUFFIXES and rel.name not in SOURCE_NAMES)
                or member.size > MAX_FILE_BYTES
            ):
                result.skipped_files += 1
                continue
            if result.scanned_files >= MAX_FILES:
                result.partial = True
                break
            stream = archive.extractfile(member)
            if stream is None:
                result.skipped_files += 1
                continue
            with stream:
                source = stream.read(MAX_FILE_BYTES + 1)
            if len(source) > MAX_FILE_BYTES or b"\x00" in source:
                result.skipped_files += 1
                continue
            result.scanned_files += 1
            lines = source.decode("utf-8", errors="replace").splitlines()
            result.scanned_lines += len(lines)
            suffix = rel.suffix.lower()
            for line_number, line in enumerate(lines, 1):
                for rule in RULES:
                    if rule.suffixes is not None and suffix not in rule.suffixes:
                        continue
                    if rule.pattern.search(line):
                        result.findings.append(Finding(
                            rule.identifier, rule.severity, rule.title,
                            str(rel), line_number, rule.advice,
                        ))
                        if len(result.findings) >= MAX_FINDINGS:
                            result.partial = True
                            break
                if result.partial:
                    break
            if result.partial:
                break
    return result


def render_markdown(result: AuditResult) -> str:
    counts = {level: sum(f.severity == level for f in result.findings)
              for level in ("high", "medium", "low")}
    rows = [
        "# Rapport GitAudit AI v0.1",
        "",
        f"**Dépôt :** \`{result.repository}\`",
        "**Périmètre :** branche par défaut, analyse statique sans exécution.",
        "",
        "## Résumé",
        "",
        f"- Fichiers analysés : **{result.scanned_files}**",
        f"- Lignes parcourues : **{result.scanned_lines}**",
        f"- Fichiers ignorés : **{result.skipped_files}**",
        f"- Indices élevés : **{counts['high']}**",
        f"- Indices moyens : **{counts['medium']}**",
        f"- Indices faibles : **{counts['low']}**",
        f"- Analyse partielle / limite atteinte : **{'oui' if result.partial else 'non'}**",
        "",
        "## Constats",
        "",
    ]
    if result.findings:
        rows += ["| Niveau | Règle | Emplacement | Indice | Conseil |",
                 "|---|---|---|---|---|"]
        for finding in result.findings:
            # Never print source lines, matched values, or potential secret material.
            safe_path = re.sub(r"[^A-Za-z0-9_./-]", "_", finding.path)[:200]
            rows.append(
                f"| {finding.severity} | {finding.rule} | "
                f"\`{safe_path}:{finding.line}\` | {finding.title} | {finding.advice} |"
            )
    else:
        rows.append("Aucun indice trouvé par les règles limitées de cette version.")
    rows += [
        "",
        "## Limites importantes",
        "",
        "- Les règles sont heuristiques : faux positifs et faux négatifs possibles.",
        "- Un niveau « high » est une priorité de revue, pas une vulnérabilité prouvée.",
        "- Un résultat vide ne signifie jamais que le dépôt est sécurisé.",
        "- Aucun code du dépôt ciblé n'a été exécuté.",
        "- Dépendances, exécution réelle, configuration déployée et branches secondaires non auditées.",
        "- Taille et nombre de fichiers plafonnés pour limiter les coûts.",
        "",
    ]
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit statique GitHub à budget zéro.")
    parser.add_argument("repository", help="owner/repo ou https://github.com/owner/repo")
    parser.add_argument("--report", help="Chemin de sortie Markdown")
    parser.add_argument("--json", help="Chemin de sortie JSON")
    args = parser.parse_args(argv)
    try:
        repository = normalize_repository(args.repository)
        result = analyze_archive(download_archive(repository), repository)
        markdown = render_markdown(result)
        if args.report:
            from pathlib import Path
            Path(args.report).write_text(markdown, encoding="utf-8")
        else:
            print(markdown)
        if args.json:
            from pathlib import Path
            Path(args.json).write_text(
                json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        print(
            f"Audit terminé : {result.scanned_files} fichiers, "
            f"{len(result.findings)} indices. Partiel : {result.partial}",
            file=sys.stderr,
        )
        return 0
    except (ValueError, tarfile.TarError, URLError, OSError) as exc:
        print(f"Échec de l'audit : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
