# Contribuer à GitAudit AI

GitAudit AI est actuellement un prototype en développement. Le dépôt public
ne dispose pas encore d'une licence de réutilisation ; demandez l'accord du
titulaire des droits avant de réutiliser ou redistribuer du code.

## Proposer une amélioration

1. Ouvrez une issue non sensible précisant le besoin ou la fausse alerte.
2. Travaillez sur une branche spécifique, sans fusion automatique des PR empilées.
3. Ajoutez au moins un test positif, un test négatif et un test de portée
   pour toute nouvelle règle de détection.
4. Vérifiez que les nouveaux constats ne reproduisent **jamais** de secrets
   ou d'extraits de code concernés dans les rapports.
5. Exécutez les tests et fournissez des résultats reproductibles.

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
