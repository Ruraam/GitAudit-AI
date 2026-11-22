# GitAudit AI

GitAudit AI est un **prototype d'analyse statique de dépôts GitHub publics**, lancé avec **0 € de budget initial**. Il ne nécessite ni IA payante ni compte serveur.

> ⚠️ Ce n'est **pas** un audit de sécurité complet. Les résultats sont des indices heuristiques à vérifier : il existe des faux positifs et des faux négatifs.

## Fonctionnement du prototype (v0.5 en développement)

- Accepte uniquement une adresse `owner/repo` ou `https://github.com/owner/repo`.
- Télécharge un instantané de la **branche par défaut ou d'une référence choisie** (branche, tag ou SHA) via l'API GitHub.
- Inspecte des fichiers source **sans exécuter le code cible** et **sans extraire l'archive sur disque**.
- Repère **62 motifs heuristiques** en Python, Rust, Bash, JavaScript/TypeScript, Go, Java, Kotlin, C/C++, PHP, Ruby, Swift, C#, PowerShell, **Dart/Flutter, Lua, SQL, Terraform et Docker/Compose**. Les alertes sont des points à examiner, pas une preuve de faille.
- Génère des rapports **Markdown**, **JSON** et **HTML autonome** lisible dans un navigateur, sans recopier les lignes de source ni les valeurs qui pourraient être des secrets.
- Classe chaque résultat en **`risk` (risque potentiel)**, **`review` (revue manuelle)** ou **`maintenance`**. Un niveau de gravité exprime une **priorité de vérification**, pas une vulnérabilité confirmée.
- Chaque règle propose : *pourquoi examiner*, *action recommandée* et *validation*. Les conseils figurent dans le Markdown et l'HTML.
- Les règles ciblées masquent certains commentaires et chaînes en Python, Rust, langages de style C, Ruby et PowerShell pour réduire les faux positifs. **Ces filtres heuristiques ne remplacent pas un parseur de chaque langage.**
- Limite la taille des archives, des fichiers et des rapports, et signale si une analyse est partielle.

## Lancer un audit en local

Avec Python 3.10+ et une connexion Internet :

```bash
python3 -m unittest discover -s tests -v
python3 gitaudit.py Ruraam/BubbleWM --report report.md --json report.json --html report.html
python3 gitaudit.py Ruraam/BubbleWM --ref feature/wlr-layer-shell --report report-dev.md --json report-dev.json --html report-dev.html
```

Les fichiers demandés seront créés dans le répertoire courant. Ouvrir `report.html` ou `report-dev.html` dans **un navigateur**, y compris sur téléphone après téléchargement. Ces pages sont autonomes : **pas besoin de serveur, de JavaScript, de compte tiers ni d'accès Internet pour les lire** (les liens GitHub nécessitent Internet).

## Lancer un audit depuis GitHub (sans PC)

Après fusion de la branche de développement :

1. Ouvrir l'onglet **Actions** du dépôt GitAudit-AI.
2. Choisir **Audit a public GitHub repository** puis **Run workflow**.
3. Entrer le nom du dépôt public, par exemple `Ruraam/BubbleWM` ; renseigner facultativement la branche (`feature/wlr-layer-shell`), le tag ou le SHA.
4. Télécharger l'artefact **gitaudit-report** de l'exécution, décompresser le ZIP, puis ouvrir **`report.html`** dans le navigateur. Le ZIP contient aussi `report.md` et `report.json`.

## Vitrine statique (GitHub Pages)

Le fichier `docs/index.html` fournit une **page de présentation**, sans JavaScript ni backend : elle explique le projet, les résultats d'un test daté, les limites de l'analyse et le moyen de consulter des rapports. **Cette page n'est pas un formulaire d'audit public** et ne reçoit ni code ni paiement.

Pour la publier **après validation et fusion des PR empilées** : dans le dépôt GitHub, ouvrir **Settings → Pages → Build and deployment → Deploy from a branch**, sélectionner **`main`** puis **`/docs`** et enregistrer. Le lien public apparaîtra dans les paramètres Pages seulement une fois le déploiement réussi. La disponibilité et l'éventuelle facturation restent soumises aux conditions du compte GitHub ; ne pas activer d'option payante.

Les validations automatiques (tests Python, versions 3.10 à 3.14) tournent à chaque changement. Le workflow **Live smoke test - BubbleWM** exécute des audits réels et limités sur ses branches `main` et `feature/wlr-layer-shell` dans certaines branches de développement autorisées. Les audits libres de tout dépôt restent **manuels**.

## Sécurité et limites de coûts

- Aucun script ni aucune dépendance du dépôt analysé n'est exécuté.
- Aucun accès en écriture aux dépôts analysés.
- Pas d'identifiants bancaires, d'API de modèle payant ni de paiements.
- Les Actions sont soumises aux quotas et aux règles de facturation GitHub : ne pas supposer un usage illimité.
- V0.4 étend les règles heuristiques à d'autres langages, mais **absence de détection ≠ absence de faille**. Les constructions Rust `unsafe {}` sont classées comme **points de revue faibles**, pas comme des vulnérabilités prouvées.
- Les nouvelles règles de langage utilisent des filtres légers pour supprimer les commentaires et les chaînes pertinentes dans leurs recherches. Ces filtres ne couvrent **pas toutes les syntaxes ni tous les langages** : des faux positifs et négatifs restent possibles, notamment dans les macros Rust, les chaînes shell et les f-strings Python.
- Les règles anciennes (ex. détection d'en-tête de clé privée) continuent d'examiner le texte brut pour éviter de masquer les secrets dans des littéraux.
- La catégorie `review` est utilisée pour les blocs Rust `unsafe` et les transmutations, car leur présence seule ne démontre pas un problème de sécurité.
- L'HTML utilise **des styles intégrés uniquement**, aucune ressource externe et une politique de sécurité restrictive (CSP) ; les contenus issus des dépôts sont échappés pour limiter l'injection HTML.
- Les archives dépassant 20 Mio sont refusées ; les analyses trop volumineuses sont signalées comme partielles.
- Une référence Git demandée est strictement validée avant téléchargement ; seules des références de caractères simples sont acceptées.
- L'analyseur vérifie des motifs dans les fichiers, pas les problèmes de logique métier ni l'ensemble des dépendances.

## Feuille de route

1. **V0.1** : prototype statique et rapports, CI et exécution manuelle.
2. **V0.2 (en cours)** : 20 règles ciblées en Rust/Bash/Python/JS ; tests positifs et négatifs, audits de branches actives, **catégorisation des constats** et filtrage de sources pour améliorer la précision.
3. **V0.3 (en cours)** : rapports HTML autonomes, recommandations humaines par règle et vitrine statique. **Ce n'est pas encore un site public d'audit automatisé**.
4. **V0.4** : 40 règles et couverture de 13 familles de langages, tests positifs/négatifs.
5. **V0.5 (en cours)** : 22 nouvelles règles pour Dart/Flutter, Lua, SQL, Terraform, Dockerfile et Docker Compose ; couverture par nom et extension, tests de non-régression. Voir [Matrice de couverture](docs/COVERAGE.md).
6. **À suivre** : parseurs/AST dédiés, autres formats d'infrastructure, analyse de dépendances et de supply chain ; compilation, lint et tests d'intégration uniquement avec consentement explicite et isolation adaptés.
7. **Plus tard seulement** : envisager la vente de rapports, après validation de leur fiabilité et de l'intérêt réel des utilisateurs.

Ce projet est indépendant de BubbleOS et n'y apporte aucune modification.
