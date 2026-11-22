"""Additional language families for GitAudit AI's bounded static heuristics.

These are review hints, not vulnerability proofs. Keep every rule scoped to
actual source suffixes. No dependency or execution of target projects.
"""
from __future__ import annotations

from dataclasses import dataclass

# C-family line-comment and quoted-string filtering reuses our lightweight
# stateful scanner; this is not a language-accurate lexer or AST.
C_STYLE_SUFFIXES = frozenset({
    ".go", ".java", ".kt", ".c", ".h", ".cpp", ".hpp",
    ".js", ".jsx", ".ts", ".tsx", ".swift", ".cs", ".php",
})
HASH_COMMENT_SUFFIXES = frozenset({".rb", ".ps1"})


@dataclass(frozen=True)
class Spec:
    identifier: str
    severity: str
    title: str
    pattern: str
    suffixes: tuple[str, ...]
    advice: str
    category: str
    meaning: str
    action: str
    verify: str


SPECS: tuple[Spec, ...] = (
    Spec(
        "GO001", "high", "Go : validation TLS désactivée",
        r"\bInsecureSkipVerify\s*:\s*true\b", (".go",),
        "Conserver la vérification TLS et préciser les autorités de confiance.",
        "risk",
        "Dans tls.Config, InsecureSkipVerify: true désactive certaines vérifications de certificats.",
        "Supprimer ce réglage et configurer un pool de certificats adapté, sauf besoin exceptionnel documenté.",
        "Tester que le client refuse un certificat inconnu ou un nom d'hôte incorrect.",
    ),
    Spec(
        "GO002", "medium", "Go : shell lancé avec -c",
        r'\bexec\.Command(?:Context)?\s*\(\s*"(?:/bin/)?(?:sh|bash)"\s*,\s*"-c"\s*,',
        (".go",),
        "Préférer exec.Command avec le programme et ses arguments séparés.",
        "risk",
        "Un shell lancé avec -c interprète des expressions et métacaractères.",
        "Passer les arguments au processus directement lorsque c'est possible et valider les données externes.",
        "Tester la gestion des guillemets, espaces et métacaractères.",
    ),
    Spec(
        "GO003", "low", "Go : pointeur unsafe à examiner",
        r"\bunsafe\.Pointer\b", (".go",),
        "Vérifier les règles de durée de vie, d'alignement et de pointeurs Go.",
        "review",
        "unsafe.Pointer est parfois nécessaire, mais contourne certaines vérifications du langage.",
        "Documenter les invariants de durée de vie, d'alignement et de conversions des pointeurs.",
        "Ajouter des tests de limites et utiliser les analyseurs spécialisés lorsque possible.",
    ),
    Spec(
        "JV001", "medium", "JVM : Runtime.exec à examiner",
        r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(", (".java", ".kt"),
        "Examiner la provenance des arguments et préférer une liste explicite.",
        "review",
        "Runtime.exec lance un processus : la présence de l'appel seule ne prouve pas une injection.",
        "Éviter de composer les commandes depuis des entrées non fiables et passer des arguments distincts.",
        "Tester les arguments avec espaces et caractères spéciaux.",
    ),
    Spec(
        "JV002", "medium", "Java : ObjectInputStream à examiner",
        r"\bnew\s+ObjectInputStream\s*\(", (".java",),
        "Restreindre les types désérialisables et identifier la provenance des données.",
        "review",
        "La désérialisation d'objets Java requiert des données et des types de confiance.",
        "Vérifier les filtres de désérialisation et préférer des formats de données simples si possible.",
        "Tester le rejet des objets inattendus avec des données de test inoffensives.",
    ),
    Spec(
        "CC001", "high", "C/C++ : fonction gets non bornée",
        r"\bgets\s*\(", (".c", ".h", ".cpp", ".hpp"),
        "Utiliser fgets ou une lecture bornée avec contrôle de taille.",
        "risk",
        "gets ne permet pas de limiter le nombre d'octets lus.",
        "Remplacer par une fonction de lecture avec taille explicite et vérifier les erreurs.",
        "Tester des entrées plus longues que le tampon avec des outils mémoire appropriés.",
    ),
    Spec(
        "CC002", "medium", "C/C++ : strcpy à examiner",
        r"\bstrcpy\s*\(", (".c", ".h", ".cpp", ".hpp"),
        "Contrôler les tailles et préférer des copies bornées adaptées.",
        "review",
        "strcpy ne connaît pas la capacité réelle du tampon de destination.",
        "Vérifier la taille des buffers et employer une API sûre avec gestion des terminaisons.",
        "Tester les entrées très longues et les cas limites du tampon.",
    ),
    Spec(
        "CC003", "medium", "C/C++ : sprintf à examiner",
        r"\bsprintf\s*\(", (".c", ".h", ".cpp", ".hpp"),
        "Préférer snprintf avec capacité et contrôle du résultat.",
        "review",
        "sprintf n'a pas de paramètre explicite limitant l'écriture dans le tampon.",
        "Employer snprintf ou une abstraction bornée et vérifier les valeurs de retour.",
        "Tester la troncature et les longueurs de sortie aux bornes.",
    ),
    Spec(
        "PHP001", "medium", "PHP : unserialize à examiner",
        r"\bunserialize\s*\(", (".php",),
        "Éviter unserialize pour des entrées externes ; préférer JSON.",
        "risk",
        "unserialize peut reconstruire des objets PHP et déclencher des comportements inattendus.",
        "Préférer json_decode pour les données externes et revoir les types permis.",
        "Tester que les objets inattendus ne sont pas reconstruits.",
    ),
    Spec(
        "PHP002", "high", "PHP : eval dynamique",
        r"\beval\s*\(", (".php",),
        "Éviter d'interpréter des chaînes comme du code PHP.",
        "risk",
        "eval interprète une chaîne comme une expression ou instruction PHP.",
        "Utiliser une structure de données ou un mécanisme de dispatch explicite.",
        "Tester des valeurs externes malformées et confirmer l'absence d'exécution dynamique.",
    ),
    Spec(
        "PHP003", "medium", "PHP : shell_exec à examiner",
        r"\bshell_exec\s*\(", (".php",),
        "Éviter les commandes shell construites avec des entrées non fiables.",
        "review",
        "shell_exec passe une commande à l'interpréteur shell.",
        "Préférer des interfaces de processus paramétrées et valider strictement les paramètres.",
        "Tester les guillemets, espaces et métacaractères.",
    ),
    Spec(
        "RB001", "medium", "Ruby : Marshal.load à examiner",
        r"\bMarshal\.load\s*\(", (".rb",),
        "Éviter Marshal.load pour du contenu non fiable.",
        "risk",
        "La désérialisation Ruby Marshal peut reconstruire des objets dangereux.",
        "Utiliser un format de données non exécutable et valider le schéma.",
        "Tester des entrées inattendues et les sources de confiance.",
    ),
    Spec(
        "RB002", "medium", "Ruby : eval dynamique",
        r"\beval\s*\(", (".rb",),
        "Préférer des structures explicites plutôt que eval.",
        "risk",
        "eval exécute du code Ruby fourni sous forme de texte.",
        "Ne pas interpréter de données externes comme du code ; utiliser des parseurs dédiés.",
        "Tester les valeurs provenant d'utilisateurs et les chemins d'erreur.",
    ),
    Spec(
        "JS002", "medium", "JavaScript/TypeScript : new Function",
        r"\bnew\s+Function\s*\(", (".js", ".jsx", ".ts", ".tsx"),
        "Éviter la compilation dynamique de texte en code.",
        "risk",
        "Le constructeur Function crée une fonction à partir d'une chaîne.",
        "Employer des fonctions explicites ou un parseur de données contrôlé.",
        "Tester que des entrées externes ne peuvent pas devenir du code exécutable.",
    ),
    Spec(
        "JS003", "medium", "JavaScript/TypeScript : innerHTML à examiner",
        r"\.innerHTML\s*=", (".js", ".jsx", ".ts", ".tsx"),
        "Examiner les données injectées ; préférer textContent pour du texte.",
        "review",
        "innerHTML interprète du HTML ; le risque dépend de la provenance de la valeur.",
        "Employer textContent pour le texte ou une méthode de sanitisation éprouvée.",
        "Tester avec des caractères spéciaux et vérifier l'absence de contenu actif.",
    ),
    Spec(
        "SW001", "low", "Swift : try! à examiner",
        r"\btry!\s+", (".swift",),
        "Préférer do/catch ou une gestion d'erreur explicite.",
        "review",
        "try! provoque un arrêt si l'expression produit une erreur.",
        "Gérer explicitement l'erreur ou justifier pourquoi l'échec est impossible.",
        "Tester les conditions d'erreur du chemin concerné.",
    ),
    Spec(
        "CS001", "high", "C# : BinaryFormatter à examiner",
        r"\bBinaryFormatter\s*\(", (".cs",),
        "Éviter BinaryFormatter pour les données de sérialisation.",
        "risk",
        "BinaryFormatter est une technologie de sérialisation non adaptée aux données non fiables.",
        "Migrer vers une sérialisation de données avec des types et un schéma explicites.",
        "Vérifier que les entrées non fiables ne peuvent pas instancier de types arbitraires.",
    ),
    Spec(
        "CS002", "medium", "C# : Process.Start à examiner",
        r"\bProcess\.Start\s*\(", (".cs",),
        "Contrôler les arguments de création de processus et éviter le shell.",
        "review",
        "Process.Start peut lancer une commande ou un programme externe.",
        "Utiliser ProcessStartInfo.ArgumentList et valider la provenance des paramètres.",
        "Tester les paramètres comportant des espaces et caractères spéciaux.",
    ),
    Spec(
        "PS001", "medium", "PowerShell : Invoke-Expression",
        r"(?i)\b(?:Invoke-Expression|iex)\b", (".ps1",),
        "Éviter l'exécution de texte comme commande PowerShell.",
        "risk",
        "Invoke-Expression interprète du texte en commandes PowerShell.",
        "Préférer un appel direct à une commande avec ses paramètres.",
        "Tester les entrées externes et les arguments spéciaux.",
    ),
    Spec(
        "PS002", "high", "PowerShell : certificat non vérifié",
        r"(?i)(?<!\w)-SkipCertificateCheck\b", (".ps1",),
        "Éviter -SkipCertificateCheck et configurer la confiance TLS.",
        "risk",
        "L'option -SkipCertificateCheck désactive la validation TLS de la requête.",
        "Retirer ce drapeau et configurer les certificats de confiance attendus.",
        "Vérifier qu'un certificat invalide est rejeté en test.",
    ),
)
