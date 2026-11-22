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
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from audit_filters import hash_language_code, python_code_lines, rust_scan_views, shell_without_comments
from audit_guidance import guidance_for
from report_html import render_html
from polyglot_rules import C_STYLE_SUFFIXES, HASH_COMMENT_SUFFIXES, SPECS
from expansion_filters import expansion_views
from expansion_rules import EXPANSION_SPECS

MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_UNCOMPRESSED = 150 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 256 * 1024
MAX_FINDINGS = 100

SOURCE_SUFFIXES = frozenset({
    ".py", ".sh", ".bash", ".rs", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".c", ".h", ".cpp", ".hpp", ".java", ".rb", ".php",
    ".kt", ".swift", ".cs", ".ps1", ".dart", ".lua", ".sql", ".tf", ".tfvars",
    ".hcl", ".dockerfile", ".yaml", ".yml", ".toml", ".json", ".html",
})
SOURCE_NAMES = frozenset({"Dockerfile", "Containerfile", "Makefile"})


def is_dockerfile_name(name: str) -> bool:
    """Dockerfile and Containerfile plus explicit filename variants."""
    return bool(re.fullmatch(r"(?:Dockerfile|Containerfile)(?:\.[A-Za-z0-9_.-]+)?", name))

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
    skip_comments: bool = False
    category: str = "risk"
    path_pattern: re.Pattern[str] | None = None
    preserve_strings: bool = False


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    path: str
    line: int
    advice: str
    category: str = "risk"


@dataclass
class AuditResult:
    repository: str
    scanned_files: int
    scanned_lines: int
    skipped_files: int
    findings: list[Finding]
    partial: bool
    reference: str | None = None


RULES = (
    Rule("PY001", "medium", "Appel à eval()", re.compile(r"\beval\s*\("), PY,
         "Préférer un analyseur dédié et vérifier les entrées."),
    Rule("PY002", "medium", "shell=True en Python", re.compile(r"\bshell\s*=\s*True\b"), PY,
         "Éviter le shell pour les commandes construites avec des entrées externes."),
    Rule("PY003", "medium", "Désérialisation pickle", re.compile(r"\bpickle\.loads?\s*\("), PY,
         "Ne pas désérialiser de contenu non fiable avec pickle."),
    Rule("PY004", "high", "Vérification TLS désactivée", re.compile(r"\bverify\s*=\s*False\b"), PY,
         "Conserver la validation des certificats TLS."),
    Rule("PY005", "medium", "Exécution d'une commande via os.system()",
         re.compile(r"\bos\.system\s*\("), PY,
         "Préférer subprocess avec liste d'arguments et sans shell.",
         skip_comments=True),
    Rule("PY006", "high", "Contexte TLS sans validation de certificat",
         re.compile(r"\bssl\._create_unverified_context\s*\("), PY,
         "Utiliser un contexte TLS vérifiant les certificats.",
         skip_comments=True),
    Rule("PY007", "medium", "Nom temporaire créé sans ouverture atomique",
         re.compile(r"\btempfile\.mktemp\s*\("), PY,
         "Préférer NamedTemporaryFile ou mkstemp pour éviter les courses.",
         skip_comments=True),
    Rule("PY008", "high", "Chargement YAML non sûr",
         re.compile(r"\byaml\.unsafe_load\s*\("), PY,
         "Préférer yaml.safe_load pour les données non fiables.",
         skip_comments=True),
    Rule("RS001", "low", "Bloc unsafe Rust à examiner",
         re.compile(r"\bunsafe\s*\{"), frozenset({".rs"}),
         "Documenter les invariants de sûreté et vérifier leur maintien.",
         skip_comments=True, category="review"),
    Rule("RS002", "medium", "Transmutation Rust à examiner",
         re.compile(r"\b(?:std::mem::)?transmute\s*(?:::\s*<[^>]+>)?\s*\("),
         frozenset({".rs"}),
         "Vérifier les tailles, alignements, représentations et invariants.",
         skip_comments=True, category="review"),
    Rule("RS003", "high", "Validation TLS désactivée en Rust",
         re.compile(r"\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)"),
         frozenset({".rs"}),
         "Ne pas désactiver la vérification TLS en production.",
         skip_comments=True),
    Rule("RS004", "medium", "Interpréteur shell lancé avec -c en Rust",
         re.compile(r"\b(?:std::process::)?Command::new\s*\(\s*[\"'](?:sh|bash)[\"']\s*\)\s*\.arg\s*\(\s*[\"']-c[\"']"),
         frozenset({".rs"}),
         "Préférer des commandes directes ; traiter les paramètres externes comme non fiables.",
         skip_comments=True),
    Rule("JS001", "medium", "Appel à eval() en JavaScript", re.compile(r"\beval\s*\("), JS,
         "Éviter d'évaluer du texte comme du code."),
    Rule("SH001", "high", "Script téléchargé exécuté directement",
         re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:sh|bash)\b"), SHELL,
         "Télécharger, vérifier et examiner le script avant son exécution."),
    Rule("SH002", "medium", "Évaluation dynamique d'une variable shell",
         re.compile(r"\beval\s+\"?\s*\$(?:[A-Za-z_][A-Za-z_0-9]*|\{[A-Za-z_][A-Za-z_0-9]*\})"),
         SHELL,
         "Éviter eval avec des valeurs externes ; employer des tableaux d'arguments.",
         skip_comments=True),
    Rule("SH003", "medium", "Nom temporaire obtenu avec mktemp -u",
         re.compile(r"\bmktemp\s+(?:-u|--dry-run)\b"), SHELL,
         "Créer le fichier temporaire atomiquement avec mktemp sans -u.",
         skip_comments=True),
    Rule("SH004", "medium", "Permissions excessivement ouvertes",
         re.compile(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b"), SHELL,
         "Réduire les permissions au minimum nécessaire.",
         skip_comments=True),
    Rule("SH005", "low", "Arrêt sur erreur désactivé dans un script",
         re.compile(r"\bset\s+\+e(?:\s|$)"), SHELL,
         "Vérifier que la désactivation temporaire du contrôle des erreurs est justifiée.",
         skip_comments=True, category="review"),
    Rule("GEN001", "high", "En-tête de clé privée détecté",
         re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), None,
         "Vérifier si la clé est réelle ; la révoquer et la remplacer si elle a été exposée."),
    Rule("GEN002", "low", "Marqueur TODO/FIXME",
         re.compile(r"\b(?:TODO|FIXME)\b"), None,
         "Vérifier si le travail signalé est toujours nécessaire.",
         category="maintenance"),
) + tuple(
    Rule(
        spec.identifier, spec.severity, spec.title, re.compile(spec.pattern),
        frozenset(spec.suffixes), spec.advice, True, spec.category,
    ) for spec in SPECS
) + tuple(
    Rule(
        spec.identifier, spec.severity, spec.title, re.compile(spec.pattern),
        frozenset(spec.suffixes) if spec.suffixes is not None else None,
        spec.advice, True, spec.category,
        re.compile(spec.path_pattern) if spec.path_pattern else None,
        spec.preserve_strings,
    ) for spec in EXPANSION_SPECS
)


def is_comment_line(line: str, suffix: str) -> bool:
    """Skip obvious comment-only lines for the new heuristic rules."""
    content = line.lstrip()
    if suffix in PY or suffix in SHELL:
        return content.startswith("#")
    if suffix == ".rs":
        return content.startswith(("//", "/*", "*"))
    return False


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


def normalize_ref(value: str) -> str:
    """Accept a bounded Git branch, tag, or SHA without control characters."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value):
        raise ValueError("Référence Git invalide.")
    if (
        "//" in value or ".." in value or "/." in value
        or value.endswith(("/", ".", ".lock"))
    ):
        raise ValueError("Référence Git invalide.")
    return value


def download_archive(repository: str, ref: str | None = None) -> bytes:
    """Get a GitHub tarball snapshot; never run repository code."""
    url = f"https://api.github.com/repos/{repository}/tarball"
    if ref is not None:
        url += "/" + quote(normalize_ref(ref), safe="/")
    request = Request(url, headers={
        "User-Agent": "GitAudit-AI/0.1",
        "Accept": "application/vnd.github+json",
    })
    with urlopen(request, timeout=30) as response:
        payload = response.read(MAX_DOWNLOAD + 1)
    if len(payload) > MAX_DOWNLOAD:
        raise ValueError("Archive trop volumineuse (> 20 Mio).")
    return payload


def analyze_archive(payload: bytes, repository: str, reference: str | None = None) -> AuditResult:
    result = AuditResult(repository, 0, 0, 0, [], False, reference)
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
            path = PurePosixPath(member.name)
            parts = path.parts
            if path.is_absolute() or len(parts) < 2 or ".." in parts:
                result.skipped_files += 1
                continue
            rel = PurePosixPath(*parts[1:])
            if (
                any(part in IGNORED_PARTS for part in rel.parts)
                or (rel.suffix.lower() not in SOURCE_SUFFIXES and rel.name not in SOURCE_NAMES
                    and not is_dockerfile_name(rel.name))
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
            python_code = python_code_lines(lines) if suffix in PY else None
            rust_views = rust_scan_views(lines) if suffix == ".rs" else None
            c_views = rust_scan_views(lines) if suffix in C_STYLE_SUFFIXES or suffix == ".dart" else None
            dialect = (
                "lua" if suffix == ".lua" else
                "sql" if suffix == ".sql" else
                "hcl" if suffix in {".tf", ".tfvars", ".hcl"} else
                "compose" if suffix in {".yaml", ".yml"} else
                "docker" if is_dockerfile_name(rel.name) or suffix == ".dockerfile" else
                None
            )
            expansion_code = expansion_views(lines, dialect) if dialect else None
            for line_number, line in enumerate(lines, 1):
                for rule in RULES:
                    if rule.suffixes is not None and suffix not in rule.suffixes:
                        continue
                    if rule.path_pattern is not None and not rule.path_pattern.search(str(rel)):
                        continue
                    candidate = line
                    if rule.skip_comments:
                        if python_code is not None:
                            candidate = python_code[line_number - 1]
                        elif rust_views is not None:
                            without_comments, only_code = rust_views[line_number - 1]
                            candidate = (
                                without_comments if rule.identifier == "RS004"
                                else only_code
                            )
                        elif c_views is not None:
                            no_comments, code_only = c_views[line_number - 1]
                            candidate = (
                                no_comments if rule.identifier == "GO002"
                                else code_only
                            )
                            if suffix == ".php":
                                candidate = shell_without_comments(candidate)
                        elif expansion_code is not None:
                            no_comments, code_only = expansion_code[line_number - 1]
                            candidate = no_comments if rule.preserve_strings else code_only
                        elif suffix in HASH_COMMENT_SUFFIXES:
                            candidate = hash_language_code(
                                line, powershell=(suffix == ".ps1")
                            )
                        elif suffix in SHELL:
                            candidate = shell_without_comments(line)
                        elif is_comment_line(line, suffix):
                            continue
                    if rule.pattern.search(candidate):
                        result.findings.append(Finding(
                            rule.identifier, rule.severity, rule.title,
                            str(rel), line_number, rule.advice, rule.category,
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
    categories = {
        category: sum(f.category == category for f in result.findings)
        for category in ("risk", "review", "maintenance")
    }
    rows = [
        "# Rapport GitAudit AI v0.1",
        "",
        f"**Dépôt :** `{result.repository}`",
        f"**Périmètre :** {result.reference or 'branche par défaut'}, analyse statique sans exécution.",
        "",
        "## Résumé",
        "",
        f"- Fichiers analysés : **{result.scanned_files}**",
        f"- Lignes parcourues : **{result.scanned_lines}**",
        f"- Fichiers ignorés : **{result.skipped_files}**",
        f"- Indices élevés : **{counts['high']}**",
        f"- Indices moyens : **{counts['medium']}**",
        f"- Indices faibles : **{counts['low']}**",
        f"- Risques potentiels à vérifier : **{categories['risk']}**",
        f"- Points de revue : **{categories['review']}**",
        f"- Maintenance : **{categories['maintenance']}**",
        f"- Analyse partielle / limite atteinte : **{'oui' if result.partial else 'non'}**",
        "",
        "## Constats",
        "",
    ]
    if result.findings:
        rows += ["| Niveau | Nature | Règle | Emplacement | Indice | Conseil |",
                 "|---|---|---|---|---|---|"]
        for finding in result.findings:
            # Never print source lines, matched values, or potential secret material.
            safe_path = re.sub(r"[^A-Za-z0-9_./-]", "_", finding.path)[:200]
            rows.append(
                f"| {finding.severity} | {finding.category} | {finding.rule} | "
                f"`{safe_path}:{finding.line}` | {finding.title} | {finding.advice} |"
            )
    else:
        rows.append("Aucun indice trouvé par les règles limitées de cette version.")
    rows += [
        "",
        "## Recommandations par règle",
        "",
    ]
    if result.findings:
        for rule_id in sorted({finding.rule for finding in result.findings}):
            guidance = guidance_for(rule_id)
            rows.extend([
                f"### {rule_id}",
                "",
                f"**À vérifier :** {guidance.meaning}",
                "",
                f"**Action recommandée :** {guidance.action}",
                "",
                f"**Validation :** {guidance.verify}",
                "",
            ])
    else:
        rows += ["Aucune recommandation particulière : poursuivre les autres vérifications.", ""]
    rows += [
        "## Limites importantes",
        "",
        "- Les catégories « risk », « review » et « maintenance » sont des aides au tri.",
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
    parser.add_argument("--html", help="Chemin de sortie du rapport HTML autonome")
    parser.add_argument("--ref", help="Branche, tag ou SHA Git (défaut : branche principale)")
    args = parser.parse_args(argv)
    try:
        repository = normalize_repository(args.repository)
        reference = normalize_ref(args.ref) if args.ref is not None else None
        payload = download_archive(repository, reference) if reference is not None else download_archive(repository)
        result = analyze_archive(payload, repository, reference)
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
        if args.html:
            from pathlib import Path
            Path(args.html).write_text(render_html(result), encoding="utf-8")
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
