# Contribuer à GitAudit AI

GitAudit AI est actuellement un prototype en développement. La branche de
consolidation contient le texte intégral de la licence **GNU AGPL-3.0-only**
([LICENSE](LICENSE)) ; elle ne sera la licence de la branche `main` que lorsque
la proposition aura été revue et fusionnée.

Les contributions proposées doivent être originales ou assorties des
autorisations nécessaires pour être distribuées sous AGPL-3.0-only. Les auteurs
conservent les droits sur leurs contributions. N'incluez pas de code ou
d'images tiers dont les termes sont incompatibles ; signalez toute provenance
ou obligation particulière dans la PR.

## Proposer une amélioration

1. Ouvrez une issue non sensible précisant le besoin ou la fausse alerte.
2. Travaillez sur une branche spécifique. Utilisez la PR de consolidation pour la prochaine release ; n'effectuez aucune fusion automatique des PR empilées.
3. Ajoutez au moins un test positif, un test négatif et un test de portée
   pour toute nouvelle règle de détection.
4. Vérifiez que les nouveaux constats ne reproduisent **jamais** de secrets
   ou d'extraits de code concernés dans les rapports.
5. Exécutez les tests et fournissez des résultats reproductibles.
6. Conservez les mentions de licence existantes et ajoutez `SPDX-License-Identifier: AGPL-3.0-only` dans les nouveaux modules sources lorsque cela s'applique.

## Vérifications locales

Python 3.10 ou plus récent, sans dépendance tierce ni droits administrateur :

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q gitaudit.py tests
```

Les CI testent les versions Python 3.10 à 3.14. L'analyse d'un dépôt externe
ne doit ni installer ses paquets, ni exécuter son code, ni écrire dans le dépôt.

## Signalements de sécurité

Voir [SECURITY.md](SECURITY.md). Ne joignez pas de jetons réels aux tickets.
