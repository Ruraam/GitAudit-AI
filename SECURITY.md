# Politique de sécurité — GitAudit AI

GitAudit AI est un **prototype expérimental d'analyse heuristique**, pas une
certification de sécurité ni un outil garantissant l'absence de vulnérabilités.

## Signaler un problème

**Ne publiez jamais de secrets, de jetons, de clés privées ou de détails
d'exploitation sensibles dans une issue publique.**

Si le dépôt GitHub affiche l'option **Security → Report a vulnerability**,
utilisez-la pour un signalement privé. Sinon, créez uniquement une issue publique
demandant une **méthode de contact privée**, sans inclure les détails sensibles ;
une adresse dédiée n'est pas encore publiée.

Merci de préciser en privé le composant, la version/branche, la portée du
problème, les étapes minimales de reproduction et les mesures de protection
proposées. Utilisez des secrets synthétiques pour vos exemples.

Ce projet n'offre pas encore de programme de bug bounty, de délai de réponse
garanti ni de correctif garanti. Aucun signalement ne doit viser des dépôts
tiers sans autorisation.

## Frontières de sécurité

- Le moteur lit des instantanés GitHub et **n'exécute jamais le code audité**.
- Les rapports ne recopient pas le texte des lignes ayant déclenché une règle.
- Les téléchargements, les fichiers et les constats sont plafonnés ; les
  analyses partielles doivent rester clairement identifiées.
- Les règles sont heuristiques : faux positifs et faux négatifs sont possibles.
- L'analyse ne couvre pas l'historique Git, l'intégralité des dépendances ni
  la configuration réelle des systèmes déployés.

## Maintenance

Pour un bug non sensible, utilisez une issue ordinaire. Ne divulguez pas
d'informations privées dans les rapports et captures d'écran.
