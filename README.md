# GitAudit AI

GitAudit AI est un **prototype d'analyse statique de dépôts GitHub publics**, lancé avec **0 € de budget initial**. Il ne nécessite ni IA payante ni compte serveur.

> ⚠️ Ce n'est **pas** un audit de sécurité complet. Les résultats sont des indices heuristiques à vérifier : il existe des faux positifs et des faux négatifs.

## Fonctionnement de la version 0.1

- Accepte uniquement une adresse `owner/repo` ou `https://github.com/owner/repo`.
- Télécharge un instantané de la **branche par défaut** du dépôt via l'API GitHub.
- Inspecte des fichiers source **sans exécuter le code cible** et **sans extraire l'archive sur disque**.
- Repère plusieurs motifs suspects : `eval()`, `shell=True`, `pickle.loads()`, TLS désactivé, `curl | sh`, en-têtes de clés privées et marqueurs TODO/FIXME.
- Génère des rapports **Markdown** et **JSON**, sans recopier les lignes de source ni les valeurs qui pourraient être des secrets.
- Limite la taille des archives, des fichiers et des rapports, et signale si une analyse est partielle.

## Lancer un audit en local

Avec Python 3.10+ et une connexion Internet :

```bash
python3 -m unittest discover -s tests -v
python3 gitaudit.py Ruraam/BubbleWM --report report.md --json report.json
```

Les rapports `report.md` et `report.json` seront créés dans le répertoire courant.

## Lancer un audit depuis GitHub (sans PC)

Après fusion de la branche de développement :

1. Ouvrir l'onglet **Actions** du dépôt GitAudit-AI.
2. Choisir **Audit a public GitHub repository** puis **Run workflow**.
3. Entrer le nom du dépôt public, par exemple `Ruraam/BubbleWM`.
4. Télécharger les rapports depuis l'artefact **gitaudit-report** de l'exécution.

Les validations automatiques (tests Python) tournent à chaque changement via GitHub Actions. Les audits de dépôts externes ne sont déclenchés **que manuellement**.

## Sécurité et limites de coûts

- Aucun script ni aucune dépendance du dépôt analysé n'est exécuté.
- Aucun accès en écriture aux dépôts analysés.
- Pas d'identifiants bancaires, d'API de modèle payant ni de paiements.
- Les Actions sont soumises aux quotas et aux règles de facturation GitHub : ne pas supposer un usage illimité.
- V0.1 inspecte des motifs textuels : **absence de détection ≠ absence de faille**.
- Les archives dépassant 20 Mio sont refusées ; les analyses trop volumineuses sont signalées comme partielles.

## Feuille de route

1. **V0.1** : prototype statique et rapports, CI et exécution manuelle.
2. **V0.2** : contrôles par langage plus précis, réduction des faux positifs, tests d'intégration.
3. **V0.3** : interface web de démonstration, sans service commercial activé.
4. **Plus tard seulement** : envisager la vente de rapports, après validation de leur fiabilité et de l'intérêt réel des utilisateurs.

Ce projet est indépendant de BubbleOS et n'y apporte aucune modification.
