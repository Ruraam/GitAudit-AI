# GitAudit AI — revue et préparation de la consolidation AGPL-3.0

> **Statut : préparation, pas une publication.** Branches #2 à #10 encore ouvertes,
> `main` inchangée. La licence AGPL-3.0-only se trouve pour l'instant sur la
> branche de consolidation uniquement.

## Portée et méthode

- Branche source : `release/agpl-v0.7-consolidation`, issue du HEAD de la PR #10
  (`fix/audit-credibility-p0`). Elle contient l'historique de #2 → #3 → #4 →
  #5 → #6 → #7 → #8 → #9 → #10.
- Branche cible : `main`. **Une seule PR consolidée, sans fusion automatique.**
- Une revue de diff et de provenance complète est requise. La CI verte est
  nécessaire mais **ne remplace pas** une revue humaine indépendante.
- La branche peut être intégrée au moyen d'un squash **après autorisation explicite**
  et vérification de son SHA de tête, sans fusionner les neuf PR une à une.
- Après la fusion de la consolidation, vérifier que les anciennes PR ne
  contiennent plus de changements manquants avant de les fermer. **Ne pas les
  fermer automatiquement**.

## Licence et propriété intellectuelle (P0)

- [x] Ajouter le texte canonique intégral de la licence **GNU AGPL version 3**,
  identifiant SPDX **`AGPL-3.0-only`**, sans le modifier.
- [x] Ajouter la mention SPDX aux modules Python du moteur.
- [x] Mettre en cohérence `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`
  et la vitrine, en distinguant branche de revue et publication effective.
- [ ] Vérifier les droits sur **toutes les contributions et tous les fichiers
  tiers** (code, logos, images, fixtures, éventuels extraits provenant d'autres
  projets) et leur compatibilité avec l'AGPL-3.0-only.
- [ ] Vérifier l'accord des titulaires de droits concernés lorsqu'un composant
  ne peut pas légalement être placé sous cette licence.
- [ ] Facultatif : ajouter les mentions de copyright précises, après vérification
  de l'identité des ayants droit et des années de création.

## Revue technique et sécurité (P0)

- [ ] Examiner les écarts `main...release/agpl-v0.7-consolidation` et la
  liste complète des fichiers ajoutés ou modifiés.
- [ ] Confirmer que la branche n'exécute **jamais** le code analysé ; revoir la
  gestion des archives, quotas, secrets, chemins relatifs et sorties HTML.
- [ ] Vérifier les alertes réelles et le taux de faux positifs sur des fixtures
  supplémentaires ; aucune revendication d'audit exhaustif.
- [ ] Vérifier que `main` n'a pas reçu de nouveaux commits depuis la revue.
- [ ] Exiger la CI Python 3.10 → 3.14 verte **sur le SHA final exact**, plus le
  smoke test BubbleWM sur les deux branches.
- [ ] Contrôler la source et l'intégrité des GitHub Actions épinglées.
- [ ] Obtenir une **revue humaine indépendante** et l'accord explicite du
  propriétaire avant la fusion.

## Publication du site et politique CSP

- [ ] Vérifier que la vitrine sépare bien l'exemple historique **v0.6**
  (13/30 fichiers, 10/42 points de revue) des audits **v0.7-dev**
  (15/33 fichiers au dernier contrôle).
- [ ] Vérifier que le lien de licence pointe vers un commit réel qui
  contient le fichier, puis décider d'un lien stable vers la version publiée.
- [ ] Si une protection anti-iframe est requise, configurer une **réponse HTTP**
  avec `Content-Security-Policy: frame-ancestors 'none'` ou une politique
  équivalente sur un hébergement qui permet de définir les en-têtes. La
  directive `frame-ancestors` n'est **pas opérante** dans une balise
  `<meta http-equiv="Content-Security-Policy">`; ne pas promettre cette
  protection sur une page statique sans contrôle des en-têtes.

## Après la fusion (pas maintenant)

- [ ] Vérifier que GitHub détecte `AGPL-3.0-only` sur `main`, et que
  `LICENSE`, les tests et le README public sont présents.
- [ ] Mettre à jour la version stable (`0.7.0`) uniquement après une nouvelle
  validation, puis créer un tag/release **avec accord explicite**.
- [ ] Publier un rapport de démonstration durable ; vérifier le lien et les
  données affichées sur la vitrine.
- [ ] Activer manuellement GitHub Pages à partir de `main:/docs` ; vérifier
  la politique GitHub et les quotas avant toute option pouvant être payante.
- [ ] Renseigner l'About, les topics, la page Web, la description et les
  paramètres de sécurité du dépôt via un accès administrateur autorisé.
- [ ] Revoir les anciennes PR empilées, et les fermer uniquement après avoir
  vérifié que rien ne manque à la branche fusionnée.

**Aucune release, mise en ligne, fusion ou fermeture de PR n'est déclenchée
par cette checklist.**
