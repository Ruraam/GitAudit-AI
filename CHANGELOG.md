# Historique des changements — GitAudit AI

Ce fichier décrit les développements. **Aucune version stable n'a encore été
publiée** depuis cette branche et aucune des PR empilées n'a été fusionnée
automatiquement.

## [0.7.0.dev0] — En développement, non publié

- Licence **GNU AGPL-3.0-only** incluse intégralement dans la branche de
  consolidation, avec mentions dans le README, les contributions et la vitrine.
- Préparation d'une PR de consolidation unique vers `main` regroupant
  les changements des PR #2 à #10, sans fusion automatique.

- Version centralisée dans `version.py`, option CLI `--version`, titre de rapport
  et User-Agent cohérents.
- Réduction des faux positifs des anciennes règles Python et JavaScript/TS
  dans les commentaires et certaines chaînes (filtrage lexical simplifié).
- Détection limitée de motifs de secrets dans les fichiers non-code sensibles
  (`.env*`, `.pem`, `.key`, `id_rsa`, `README.md`, etc.).
- Quatre motifs supplémentaires de jetons potentiels AWS, GitHub, Slack et
  Stripe, et en-têtes de clés privées chiffrées ou PGP.
- Les fichiers de tests, docs, fixtures et exemples ne produisent plus les
  alertes de code ordinaires par défaut. Ils restent examinés pour les secrets.
- Page de présentation : chiffres historiques corrigés et sourcés ; distinctions
  explicites entre règles, constats, IA et licence.
- `SECURITY.md`, `CONTRIBUTING.md`, et mise à jour automatisée proposée
  des GitHub Actions via Dependabot.
- Actions officielles épinglées aux SHA complets vérifiés ; checkout sans
  persistance de jeton et annulation des CI obsolètes.
- Tests de non-régression sur ces cas et exemple JSON historique vérifiable.

## [0.6] — En attente de consolidation

- 71 règles de détection et 646 tests distincts, sur branches de développement
  empilées ; **ce chiffre ne décrit pas encore le code de** `main`.
- Rapports Markdown, JSON, HTML ; analyses réelles en lecture seule sur BubbleWM.

## Restrictions de publication

La licence AGPL-3.0-only est choisie et incluse sur la branche de revue,
mais **n'est pas encore intégrée à `main`**. Vérifier les droits sur les
contributions/éléments tiers, effectuer la revue de la consolidation, vérifier
la CI finale puis demander une autorisation explicite avant toute fusion,
publication d'un tag, release ou activation de GitHub Pages.
