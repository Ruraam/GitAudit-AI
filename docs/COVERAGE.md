# GitAudit AI — couverture et limites

**État du prototype : v0.6 (branche de développement)**. GitAudit AI lit statiquement des fichiers texte sélectionnés. Les règles produisent des **indices heuristiques à vérifier**, jamais des vulnérabilités confirmées. Aucun code du dépôt cible n'est exécuté.

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
| Dart / Flutter | `.dart` | certificat TLS non vérifié, WebView JavaScript non restreint, processus externes |
| Lua | `.lua` | `loadstring`, `load`, `os.execute`, `io.popen` |
| SQL (selon le dialecte) | `.sql` | `GRANT ALL ... TO PUBLIC`, `EXECUTE IMMEDIATE`, `xp_cmdshell` |
| Terraform / HCL | `.tf`, `.tfvars` | accès public, ACL de stockage, IPv4 ouvert, chiffrement, destruction et snapshot |
| Dockerfile / Containerfile | `Dockerfile*`, `Containerfile*` | tag `latest`, scripts distants, `USER root`, `ADD` distant |
| Docker Compose | `compose*.yml/.yaml`, `docker-compose*.yml/.yaml` | `privileged: true`, `network_mode: host` |

**71 règles au total**, dont 9 règles supplémentaires en v0.6 portant sur les workflows et les manifestes. Les 62 règles précédentes restent actives. Les fichiers YAML, JSON, TOML, HTML et Makefile bénéficient de quelques règles génériques ; seuls les **fichiers Compose nommés explicitement** reçoivent les deux règles Docker Compose. Les fichiers HCL génériques `.hcl` sont lus, mais **pas couverts par les règles Terraform limitées à `.tf` / `.tfvars`**. Les fichiers `.dockerfile` sont lus, mais les règles Docker ciblent les noms Dockerfile/Containerfile habituels.

## Workflows CI et dépendances : contrôle v0.6

| Format ciblé | Portée | Exemples de constats |
|---|---|---|
| `.github/workflows/*.yml/.yaml` | Lignes YAML ciblées uniquement | actions à ref mutable, `permissions: write-all`, `contents: write`, `pull_request_target`, `persist-credentials: true` |
| `package.json` | `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies` (JSON valide) | versions `*`/`latest`, URL de dépendance HTTP non chiffrée |
| `requirements*.txt` | Déclarations simples | nom de paquet ou intervalle de versions non fixé (revue, pas une vulnérabilité) |
| `Cargo.toml` | Sections de dépendances courantes | version `*` |

Les contrôles YAML et TOML ne sont **pas** des parseurs complets. Les tests ne récupèrent pas les paquets et n'interrogent **aucune base de vulnérabilités**. Les versions non fixées peuvent être des choix intentionnels, en particulier dans les bibliothèques.

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
2. **Dépendances / supply chain** : au-delà des nouveaux indices statiques, SBOM, vérification des versions réellement vulnérables, lockfiles, signatures d'artefacts, provenance et licences restent à développer.
3. **Configurations** : les nouveaux indices GitHub Actions ne remplacent pas l'analyse structurelle YAML, des flux de confiance, des permissions effectives, de Kubernetes, du cloud ou des secrets dans l'historique Git.
4. **Tests de projet en environnement isolé** : lint, compilation, tests unitaires et d'intégration. Cela **nécessite un consentement explicite**, une isolation forte, des quotas, et ne doit jamais exécuter automatiquement le code non fiable d'un dépôt public.
5. **Fuzzing / mutation / propriétés** : générer des variations déterministes et mesurer si nos règles résistent aux changements de syntaxe et détectent les anomalies introduites.
6. **Langages et écosystèmes à venir** : R, Scala, Elixir, Haskell, Objective-C, Perl, Zig, Nix, Kubernetes, Helm et autres ; approfondir Dart, Lua, SQL, Terraform et Docker avec de vrais parseurs et règles contextuelles.

## Garde-fous

- Aucun langage ni format d'infrastructure n'est audité exhaustivement, même si son extension est reconnue. Les recherches sont principalement **monolignes** : elles peuvent manquer des déclarations multilignes et les valeurs interpolées.
- Les accès publics Terraform ou Docker peuvent être intentionnels. Le rapport les signale comme **points de revue**, pas comme failles confirmées.
- Les filtres de commentaires / chaînes sont volontairement simplifiés ; ils ne comprennent pas toutes les chaînes Lua longues, syntaxes SQL, interpolations HCL et Dockerfile multiligne.
- Les catégories `risk`, `review` et `maintenance` sont destinées au tri ; `high` ne signifie pas « faille prouvée ».
- Le moteur n'exécute ni compilateur, ni installateur, ni tests contenus dans le dépôt analysé.
- Les archives ont une taille maximale ; les résultats partiels sont signalés.
- Les rapports n'incluent pas le texte correspondant aux règles afin de limiter les fuites de secrets.
- GitHub Actions est soumis aux règles, limites et quotas de GitHub : **pas d'utilisation illimitée garantie à 0 €**.

Notre objectif est une **couverture progressive, vérifiable et honnête**, plutôt qu'une promesse impossible de détecter tous les problèmes de tous les langages.
