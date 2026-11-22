"""Actionable, bounded and conservative advice for heuristic scan findings.

Every entry suggests a human review, not an automatic patch or an assertion
that the scanned code is vulnerable. No third-party dependencies or model APIs.
"""
from __future__ import annotations

from dataclasses import dataclass

from polyglot_rules import SPECS
from expansion_rules import EXPANSION_SPECS
from metadata_rules import SPECS as METADATA_SPECS


@dataclass(frozen=True)
class Guidance:
    meaning: str
    action: str
    verify: str


GUIDANCE: dict[str, Guidance] = {
    "PY001": Guidance(
        "Un appel à eval() peut interpréter des expressions Python.",
        "Si la donnée vient de l'extérieur, remplacer par un format dédié : JSON pour les données ou ast.literal_eval uniquement pour des littéraux pris en charge.",
        "Contrôler la provenance des expressions et tester des entrées malformées ou malveillantes.",
    ),
    "PY002": Guidance(
        "shell=True demande à un interpréteur shell de traiter une commande.",
        "Employer subprocess.run avec une liste d'arguments et shell=False lorsque c'est possible. Ne jamais assembler une commande shell à partir d'une entrée non fiable.",
        "Tester les arguments avec espaces, guillemets et métacaractères ; vérifier le comportement attendu.",
    ),
    "PY003": Guidance(
        "pickle peut reconstruire des objets à effets de bord lors de la désérialisation.",
        "Ne pas accepter de pickle venant d'une source non fiable. Préférer un format de données non exécutable et vérifier le schéma.",
        "Identifier qui produit le fichier et qui peut le modifier avant de choisir une migration.",
    ),
    "PY004": Guidance(
        "verify=False désactive certaines vérifications de certificats TLS.",
        "Supprimer cette option ou rétablir une autorité de certification appropriée plutôt que désactiver la validation.",
        "Vérifier qu'un certificat invalide est refusé et qu'un certificat légitime est accepté.",
    ),
    "PY005": Guidance(
        "os.system() exécute une commande par l'intermédiaire du shell.",
        "Préférer subprocess avec des arguments séparés et sans shell ; refuser ou traiter explicitement les entrées externes.",
        "Tester des arguments contenant des espaces, guillemets et caractères spéciaux.",
    ),
    "PY006": Guidance(
        "ssl._create_unverified_context() ne vérifie pas correctement l'identité du serveur.",
        "Employer ssl.create_default_context() avec les autorités de confiance adaptées.",
        "Tester les certificats inconnus et expirés dans un environnement de test.",
    ),
    "PY007": Guidance(
        "tempfile.mktemp() renvoie un nom pouvant être réutilisé par un tiers avant création du fichier.",
        "Utiliser tempfile.NamedTemporaryFile, mkstemp ou TemporaryDirectory avec gestion de durée de vie.",
        "Tester les permissions du fichier temporaire et le nettoyage après interruption.",
    ),
    "PY008": Guidance(
        "yaml.unsafe_load() peut reconstruire des objets Python non destinés à des données externes.",
        "Pour les entrées non fiables, remplacer par yaml.safe_load et valider la structure attendue.",
        "Tester les documents comportant des balises d'objets non autorisées.",
    ),
    "RS001": Guidance(
        "Un bloc unsafe Rust est un mécanisme légitime ; sa présence ne démontre aucune faille.",
        "Vérifier les invariants de sûreté, les durées de vie, les pointeurs et les alias ; documenter les préconditions du bloc.",
        "Ajouter des tests ciblés et, quand c'est possible, comparer le comportement avec Miri ou des vérifications spécialisées.",
    ),
    "RS002": Guidance(
        "transmute doit satisfaire des contraintes strictes sur les types et les représentations.",
        "Vérifier l'initialisation, la validité des valeurs, la taille et l'alignement ; préférer des conversions sûres lorsque disponibles.",
        "Ajouter des tests aux frontières et documenter précisément les invariants nécessaires.",
    ),
    "RS003": Guidance(
        "danger_accept_invalid_* avec true peut désactiver la validation TLS.",
        "Éviter ce réglage en production ; configurer des certificats racines adaptés aux besoins du service.",
        "Vérifier le rejet des certificats invalides en intégration.",
    ),
    "RS004": Guidance(
        "L'appel à sh ou bash avec -c peut interpréter des valeurs comme du code shell.",
        "Préférer Command::new(programme).args([...]) plutôt que la construction d'une chaîne à interpréter.",
        "Tester les arguments contenant des caractères spéciaux et la validation des entrées.",
    ),
    "JS001": Guidance(
        "eval() interprète une chaîne en code JavaScript.",
        "Utiliser JSON.parse pour des données JSON ou une API dédiée plutôt qu'une exécution dynamique.",
        "Tester que les données externes ne peuvent pas introduire du code exécutable.",
    ),
    "SH001": Guidance(
        "Un script téléchargé est directement transmis à un interpréteur shell.",
        "Télécharger séparément, vérifier l'origine et l'intégrité, examiner le script et choisir une version fixée.",
        "Tester le cas d'une erreur de téléchargement et vérifier que le script ne s'exécute pas malgré l'échec.",
    ),
    "SH002": Guidance(
        "eval peut réinterpréter une variable comme du code shell.",
        "Utiliser des tableaux Bash et des paramètres correctement quotés ; éviter eval sur des valeurs externes.",
        "Tester avec des espaces, retours à la ligne et métacaractères.",
    ),
    "SH003": Guidance(
        "mktemp -u ne crée pas la ressource temporaire, ce qui permet une course.",
        "Créer la ressource atomiquement avec mktemp ou mktemp -d, puis gérer sa suppression.",
        "Vérifier les permissions et le nettoyage en cas d'interruption.",
    ),
    "SH004": Guidance(
        "chmod 777 ou a+rwx ouvre fortement les accès à une ressource.",
        "Définir les droits minimaux nécessaires et documenter les accès requis par chaque utilisateur.",
        "Tester le bon fonctionnement avec des droits restreints et plusieurs utilisateurs.",
    ),
    "SH005": Guidance(
        "set +e désactive temporairement l'arrêt automatique sur erreur.",
        "Vérifier que chaque code de retour important est traité explicitement dans cette portion de script.",
        "Tester les commandes qui échouent et la restauration de la politique d'erreur.",
    ),
    "GEN001": Guidance(
        "Un en-tête de clé privée apparaît dans le code ; il peut aussi s'agir d'un exemple fictif.",
        "Si la clé est réelle, la considérer potentiellement exposée, la révoquer puis la remplacer et retirer la fuite à sa source.",
        "Faire une revue sans recopier la valeur de la clé dans les tickets ou les rapports.",
    ),
    "GEN003": Guidance(
        "Un identifiant ressemblant à une clé d'accès AWS a été trouvé.",
        "Vérifier s'il est réel, désactiver les identifiants exposés et auditer les journaux associés.",
        "Confirmer la rotation sans transmettre l'identifiant dans un ticket.",
    ),
    "GEN004": Guidance(
        "Un motif ressemblant à un jeton GitHub a été détecté.",
        "Vérifier les autorisations et révoquer le jeton s'il est actif.",
        "Confirmer la rotation et la suppression du secret des sources exposées.",
    ),
    "GEN005": Guidance(
        "Un motif ressemblant à un jeton Slack a été détecté.",
        "Révoquer les jetons actifs exposés et vérifier leurs autorisations.",
        "Confirmer la rotation et l'absence de copie dans les rapports.",
    ),
    "GEN006": Guidance(
        "Un motif ressemblant à une clé Stripe secrète de production a été détecté.",
        "Vérifier et remplacer immédiatement toute clé active exposée.",
        "Contrôler les accès et l'absence de secret dans les traces ou rapports.",
    ),
    "GEN002": Guidance(
        "Un TODO ou FIXME signale une tâche ou une dette de maintenance.",
        "Vérifier que la note est encore pertinente et ouvrir une tâche seulement si elle reste nécessaire.",
        "Confirmer l'état du code et les tests associés ; ce n'est pas automatiquement un risque de sécurité.",
    ),
}

# Keep guidance coverage exact as more source languages are introduced.
GUIDANCE.update({
    spec.identifier: Guidance(spec.meaning, spec.action, spec.verify)
    for spec in (*SPECS, *EXPANSION_SPECS, *METADATA_SPECS)
})

def guidance_for(rule_id: str) -> Guidance:
    """Fallback for unknown future rules without repeating untrusted content."""
    return GUIDANCE.get(
        rule_id,
        Guidance(
            "Un motif a été signalé par une règle heuristique.",
            "Examiner le contexte exact avant de décider d'une correction.",
            "Vérifier les hypothèses par des tests reproductibles.",
        ),
    )
