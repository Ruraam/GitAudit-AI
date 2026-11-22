"""GitAudit AI v0.5: focused Dart/Lua/SQL/Terraform/Docker review signals.

A match is a lead for human review, not a proven vulnerability.
Language and filename scopes are explicitly bounded.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExpansionSpec:
    identifier: str
    severity: str
    title: str
    pattern: str
    suffixes: tuple[str, ...] | None
    advice: str
    category: str
    meaning: str
    action: str
    verify: str
    path_pattern: str | None = None
    preserve_strings: bool = False


DOCKERFILE_PATTERN = r"(?i)(?:^|/)(?:Dockerfile|Containerfile)(?:\.[^/]+)?$"
COMPOSE_PATTERN = r"(?i)(?:^|/)(?:docker-compose|compose)(?:\.[^/]+)?\.ya?ml$"

EXPANSION_SPECS: tuple[ExpansionSpec, ...] = (
    ExpansionSpec(
        "DA001", "high", "Dart : certificat TLS accepté sans validation",
        r"\bbadCertificateCallback\s*=\s*(?:\([^)]*\)\s*)?=>\s*true\b",
        (".dart",), "Ne pas accepter systématiquement les certificats invalides.", "risk",
        "Un callback qui renvoie toujours true peut laisser passer des certificats invalides.",
        "Supprimer ce contournement ou le limiter à un environnement de test isolé.",
        "Vérifier que les certificats invalides sont refusés en production.",
    ),
    ExpansionSpec(
        "DA002", "medium", "Dart/Flutter : JavaScript WebView sans restriction",
        r"\bJavaScriptMode\.unrestricted\b", (".dart",),
        "Vérifier la confiance accordée aux pages affichées et aux ponts JavaScript.", "review",
        "Le JavaScript est entièrement autorisé dans cette WebView ; l'impact dépend du contenu chargé.",
        "Restreindre les URL autorisées, éviter les ponts vers des API sensibles et limiter le JavaScript si inutile.",
        "Tester le chargement d'URL non autorisées et les permissions de l'application.",
    ),
    ExpansionSpec(
        "DA003", "low", "Dart : processus externe à examiner",
        r"\bProcess\.(?:run|start|runSync|startSync)\s*\(", (".dart",),
        "Contrôler les programmes et arguments externes avant l'exécution.", "review",
        "Un processus externe est lancé ; cet appel est souvent légitime mais sensible aux entrées.",
        "Valider le nom du programme et séparer les arguments plutôt que construire une commande shell.",
        "Tester les entrées non fiables et les erreurs de processus.",
    ),
    ExpansionSpec(
        "LU001", "medium", "Lua : loadstring dynamique",
        r"\bloadstring\s*\(", (".lua",),
        "Éviter d'interpréter des entrées non fiables comme du code Lua.", "risk",
        "loadstring interprète du texte en programme Lua (dans les versions qui l'exposent).",
        "Employer un format de données et un parseur adaptés plutôt que compiler du texte externe.",
        "Tester le rejet d'entrées malformées et les chemins d'erreur.",
    ),
    ExpansionSpec(
        "LU002", "medium", "Lua : chargement dynamique de code",
        r"\bload\s*\(", (".lua",),
        "Examiner la provenance et l'environnement d'exécution du texte chargé.", "review",
        "load peut charger du code Lua ; son usage n'indique pas à lui seul une vulnérabilité.",
        "Limiter les sources de code et l'environnement accessible aux scripts chargés.",
        "Vérifier le comportement avec des entrées non fiables dans un environnement isolé.",
    ),
    ExpansionSpec(
        "LU003", "medium", "Lua : commande shell",
        r"\bos\.execute\s*\(", (".lua",),
        "Éviter les commandes shell construites à partir de données non fiables.", "review",
        "os.execute exécute une commande ; le risque dépend de la provenance des paramètres.",
        "Remplacer l'interpréteur shell par une API paramétrée si disponible.",
        "Tester les caractères spéciaux et les erreurs de la commande.",
    ),
    ExpansionSpec(
        "LU004", "medium", "Lua : io.popen à examiner",
        r"\bio\.popen\s*\(", (".lua",),
        "Examiner les commandes passées à io.popen et les données externes.", "review",
        "io.popen lance un processus ; son utilisation peut être légitime.",
        "Éviter toute composition de commandes depuis des données non fiables.",
        "Tester la validation des arguments et les échecs de processus.",
    ),
    ExpansionSpec(
        "SQL001", "high", "SQL : privilèges globaux à PUBLIC",
        r"(?i)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b.*\bTO\s+PUBLIC\b",
        (".sql",), "Appliquer le principe du moindre privilège aux rôles SQL.", "review",
        "GRANT ALL à PUBLIC peut accorder des droits très larges selon le moteur SQL.",
        "Limiter les privilèges aux rôles et ressources nécessaires ; revoir le modèle d'autorisations.",
        "Vérifier les privilèges effectifs sur une base de test.",
    ),
    ExpansionSpec(
        "SQL002", "medium", "SQL : exécution dynamique d'instruction",
        r"(?i)\bEXECUTE\s+IMMEDIATE\b", (".sql",),
        "Examiner la construction des requêtes et la validation des paramètres.", "review",
        "EXECUTE IMMEDIATE exécute du SQL construit dynamiquement ; ce n'est pas toujours dangereux.",
        "Préférer des paramètres bindés et éviter la concaténation de données externes.",
        "Tester avec des entrées comportant guillemets et métacaractères.",
    ),
    ExpansionSpec(
        "SQL003", "high", "SQL Server : xp_cmdshell",
        r"(?i)\bxp_cmdshell\b", (".sql",),
        "Examiner et désactiver l'exécution de commandes système si inutile.", "review",
        "xp_cmdshell permet d'exécuter des commandes système depuis SQL Server.",
        "Réduire les permissions et désactiver cette fonction si aucun usage contrôlé ne la justifie.",
        "Contrôler les droits d'appel et l'audit des usages en environnement de test.",
    ),
    ExpansionSpec(
        "TF001", "high", "Terraform : ressource potentiellement publique",
        r"(?i)\bpublicly_accessible\s*=\s*true\b", (".tf", ".tfvars"),
        "Contrôler les restrictions réseau et les besoins réels d'accès public.", "review",
        "Une ressource est configurée comme publiquement accessible ; cela peut être intentionnel.",
        "Revoir les règles réseau, la finalité et les contrôles d'identité de la ressource.",
        "Vérifier l'accès effectif depuis un réseau non autorisé.",
    ),
    ExpansionSpec(
        "TF002", "medium", "Terraform : plage IPv4 ouverte à tous",
        r"(?i)\bcidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]",
        (".tf", ".tfvars"), "Vérifier les ports, les protocoles et la justification de cette ouverture.", "review",
        "La plage 0.0.0.0/0 inclut toutes les adresses IPv4 et peut être volontaire.",
        "Restreindre le réseau lorsque l'exposition publique n'est pas nécessaire.",
        "Vérifier les règles effectives, surtout pour les ports administratifs.",
        preserve_strings=True,
    ),
    ExpansionSpec(
        "TF003", "high", "Terraform : ACL de stockage publique",
        r"(?i)\bacl\s*=\s*['\"]public-read(?:-write)?['\"]",
        (".tf", ".tfvars"), "Revoir les autorisations publiques de ce stockage.", "review",
        "Une ACL de stockage publique peut rendre des données accessibles à tous.",
        "Préférer des ACL privées et des politiques d'accès explicites.",
        "Tester l'accès anonyme aux ressources concernées dans un environnement prévu.",
        preserve_strings=True,
    ),
    ExpansionSpec(
        "TF004", "medium", "Terraform : destruction forcée activée",
        r"(?i)\bforce_destroy\s*=\s*true\b", (".tf", ".tfvars"),
        "Examiner les risques de suppression involontaire de données.", "review",
        "force_destroy peut autoriser la suppression de ressources contenant encore des données.",
        "Utiliser la protection contre la suppression et des stratégies de sauvegarde adaptées.",
        "Tester le plan Terraform et les politiques de rétention sans appliquer de destruction.",
    ),
    ExpansionSpec(
        "TF005", "medium", "Terraform : snapshot final désactivé",
        r"(?i)\bskip_final_snapshot\s*=\s*true\b", (".tf", ".tfvars"),
        "Vérifier la restauration et les politiques de sauvegarde avant suppression.", "review",
        "Certaines bases de données risquent d'être supprimées sans snapshot final.",
        "Activer les snapshots finaux là où une conservation est requise.",
        "Contrôler les exigences de reprise et les sauvegardes existantes.",
    ),
    ExpansionSpec(
        "TF006", "medium", "Terraform : chiffrement explicitement désactivé",
        r"(?i)\bencrypted\s*=\s*false\b", (".tf", ".tfvars"),
        "Vérifier les contraintes de chiffrement applicables à cette ressource.", "review",
        "La configuration mentionne un chiffrement désactivé ; sa portée dépend du fournisseur.",
        "Activer le chiffrement adapté à la classification des données.",
        "Vérifier les propriétés de chiffrement après provisionnement en environnement de test.",
    ),
    ExpansionSpec(
        "DK001", "low", "Dockerfile : image de base mutable latest",
        r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?\S+:latest(?:\s+AS\s+\w+)?\s*$",
        None, "Épingler l'image de base par digest pour la reproductibilité.", "review",
        "Le tag latest peut pointer vers un contenu différent au fil du temps.",
        "Utiliser une version fixée, idéalement par digest, avec une politique de mises à jour.",
        "Vérifier la reproductibilité et la provenance de l'image de base.",
        path_pattern=DOCKERFILE_PATTERN,
    ),
    ExpansionSpec(
        "DK002", "high", "Dockerfile : script distant exécuté dans RUN",
        r"(?i)^\s*RUN\b.*\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b",
        None, "Éviter l'exécution directe de scripts distants non vérifiés.", "risk",
        "Une instruction RUN semble télécharger puis exécuter un script directement.",
        "Télécharger, épingler la version, vérifier l'intégrité et examiner le script avant exécution.",
        "Tester les erreurs réseau et la vérification des sommes de contrôle.",
        path_pattern=DOCKERFILE_PATTERN,
    ),
    ExpansionSpec(
        "DK003", "low", "Dockerfile : exécution en root",
        r"(?i)^\s*USER\s+(?:root|0)(?:\s|$)",
        None, "Évaluer la possibilité d'exécuter le conteneur sans privilèges root.", "review",
        "L'utilisateur root est sélectionné ; cela peut être nécessaire pendant une étape de build.",
        "Utiliser un utilisateur non privilégié dans l'étape d'exécution finale lorsque possible.",
        "Vérifier l'identité effective du processus dans le conteneur final.",
        path_pattern=DOCKERFILE_PATTERN,
    ),
    ExpansionSpec(
        "DK004", "medium", "Dockerfile : téléchargement distant via ADD",
        r"(?i)^\s*ADD\s+https?://\S+", None,
        "Préférer un téléchargement dont l'intégrité est vérifiée.", "review",
        "ADD accepte ici une URL distante : la reproductibilité et la provenance sont à vérifier.",
        "Utiliser une source versionnée, contrôler son intégrité et limiter les accès réseau du build.",
        "Vérifier que le contenu téléchargé correspond à un digest attendu.",
        path_pattern=DOCKERFILE_PATTERN,
        preserve_strings=True,
    ),
    ExpansionSpec(
        "DC001", "high", "Docker Compose : mode privilégié",
        r"(?i)^\s*privileged\s*:\s*true(?:\s|$)", (".yml", ".yaml"),
        "Limiter les privilèges des services Compose.", "review",
        "Le mode privileged donne au conteneur des capacités étendues sur l'hôte.",
        "Retirer privileged ou accorder uniquement les capacités strictement nécessaires.",
        "Vérifier les permissions effectives dans un environnement isolé.",
        path_pattern=COMPOSE_PATTERN,
    ),
    ExpansionSpec(
        "DC002", "medium", "Docker Compose : réseau hôte",
        r"(?i)^\s*network_mode\s*:\s*['\"]?host['\"]?(?:\s|$)", (".yml", ".yaml"),
        "Vérifier la nécessité de partager le réseau de l'hôte.", "review",
        "network_mode: host supprime l'isolation réseau habituelle du conteneur.",
        "Préférer un réseau de services dédié et publier uniquement les ports requis.",
        "Tester l'exposition effective des services et les règles de filtrage.",
        path_pattern=COMPOSE_PATTERN,
        preserve_strings=True,
    ),
)
