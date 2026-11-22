# GitAudit AI — couverture et limites

**État du prototype : v0.4 (branche de développement)**. GitAudit AI lit statiquement des fichiers texte sélectionnés. Les règles produisent des **indices heuristiques à vérifier**, jamais des vulnérabilités confirmées. Aucun code du dépôt cible n'est exécuté.

## Langages ciblés et familles de règles

| Langage / famille | Fichiers | Exemples de règles |
|---|---|---|
| Python | `.py` | `eval`, `shell=True`, `pickle`, TLS, YAML, fichiers temporaires |
| Rust | `.rs` | blocs `unsafe`, transmutation, TLS, lancement de shell |
| Bash | `.sh`, `.bash` | `curl/wget | sh`, `eval`, `mktemp -u`, permissions |
| JavaScript / TypeScript | `.js`, `.jsx`, `.ts`, `.tsx` | `eval`, `new Function`, `innerHTML` |
| Go | `.go` | TLS sans validation, shell `-c`, `unsafe.Pointer` |
| Java | `.java` | `Runtime.exec`, `ObjectInputStream` |
| Kotlin | `.kt` | `Runtime.exec` JVM |
| C / C++ | `.c`, `.h`, `.cpp`, `.hpp` | `gets`, `strcpy`, `sprintf` |
| PHP | `.php` | `unserialize`, `eval`, `shell_exec` |
| Ruby | `.rb` | `Marshal.load`, `eval` |
| Swift | `.swift` | `try!` |
| C# | `.cs` | `BinaryFormatter`, `Process.Start` |
| PowerShell | `.ps1` | `Invoke-Expression`, `-SkipCertificateCheck` |

**40 règles au total**, dont 20 nouvelles en v0.4. Les fichiers YAML, JSON, TOML, HTML, Makefile et Dockerfile peuvent être examinés par certaines règles génériques mais **ne bénéficient pas d'une analyse de sécurité spécifique à leur format**.

## Les types de tests réellement automatisés

- Tests unitaires et de non-régression des expressions de détection : exemples qui déclenchent une règle et exemples qui ne doivent pas la déclencher.
- Tests de portée par extension pour ne pas appliquer une règle au mauvais langage.
- Tests d'archives non fiables : limites de taille, dossiers ignorés, liens symboliques, chemins dangereux, scans partiels.
- Tests de validation des URL et références Git, sans requêtes réseau.
- Tests de confidentialité et d'échappement Markdown / JSON / HTML, y compris charges de test hostiles.
- Tests de rapports : recommandations, catégories, compatibilité des sorties et liens GitHub.
- CI multi-versions Python et audits réels **en lecture seule** sur des dépôts publics de test.

La génération de rapports et les règles sont testées, mais cela ne signifie pas que **chaque langage bénéficie de tests de compilation et d'exécution**.

## Ce qui n'est PAS couvert (à développer par phases)

1. **Parseurs spécifiques et précision** : analyse syntaxique / AST par langage, prise en charge des chaînes complexes, fichiers multilignes, macros et faux négatifs.
2. **Dépendances / supply chain** : SBOM, versions vulnérables, signature des artefacts, provenance et licences.
3. **Configurations** : GitHub Actions, Docker, IaC, Kubernetes, permissions CI, infrastructure cloud, secrets dans l'historique Git.
4. **Tests de projet en environnement isolé** : lint, compilation, tests unitaires et d'intégration. Cela **nécessite un consentement explicite**, une isolation forte, des quotas, et ne doit jamais exécuter automatiquement le code non fiable d'un dépôt public.
5. **Fuzzing / mutation / propriétés** : générer des variations déterministes et mesurer si nos règles résistent aux changements de syntaxe et détectent les anomalies introduites.
6. **Langages et écosystèmes à venir** : Dart / Flutter, Lua, R, Scala, Elixir, Haskell, Objective-C, Perl, SQL, Terraform, Docker Compose et autres.

## Garde-fous

- Aucun langage n'est audité exhaustivement, même si son extension est reconnue.
- Les catégories `risk`, `review` et `maintenance` sont destinées au tri ; `high` ne signifie pas « faille prouvée ».
- Le moteur n'exécute ni compilateur, ni installateur, ni tests contenus dans le dépôt analysé.
- Les archives ont une taille maximale ; les résultats partiels sont signalés.
- Les rapports n'incluent pas le texte correspondant aux règles afin de limiter les fuites de secrets.
- GitHub Actions est soumis aux règles, limites et quotas de GitHub : **pas d'utilisation illimitée garantie à 0 €**.

Notre objectif est une **couverture progressive, vérifiable et honnête**, plutôt qu'une promesse impossible de détecter tous les problèmes de tous les langages.
