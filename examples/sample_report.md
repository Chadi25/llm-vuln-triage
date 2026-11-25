# Rapport de triage — `target_app`

Mode : **rules (déterministe)** · rapports d'entrée **synthétiques** (fixtures)

## Avant / après

| Étape | Alertes |
|---|---|
| Brutes (Semgrep + Trivy + Grype) | 25 |
| Après dédoublonnage | 20 (−5) |
| Faux positifs écartés | 5 |
| **À traiter** | **15** (40.0 % de bruit en moins) |

| Priorité | P1 | P2 | P3 | P4 |
|---|---|---|---|---|
| Nombre | 5 | 5 | 4 | 1 |

## Qualité du filtre de faux positifs

- Précision : **1.0** · rappel : **1.0**
- 5 FP correctement écartés, 0 vraie(s) faille(s) écartée(s) à tort, 0 FP manqué(s) (20/20 entrées annotées)

## Alertes à traiter

| Prio | Score | Emplacement | Faiblesse | Outils | Justification | Remédiation |
|---|---|---|---|---|---|---|
| P1 | 10.0 | `app.py:31` | CWE-89 | semgrep ×2 | L'argument de `execute` dérive d'un paramètre HTTP (request.*) dans `user_lookup()` sans neutralisation. (route HTTP) | Utiliser une requête paramétrée. |
| P1 | 10.0 | `app.py:47` | CWE-78 | semgrep ×2 | L'argument de `check_output` dérive d'un paramètre HTTP (request.*) dans `ping()` sans neutralisation. (route HTTP) | Supprimer shell=True et passer une liste d'arguments ; valider l'hôte (ipaddress / regex DNS). |
| P1 | 10.0 | `app.py:64` | CWE-502 | semgrep | Donnée issue de la requête HTTP atteignant le point sensible dans `load_config()`. (route HTTP) | Ne jamais désérialiser une donnée non fiable : yaml.safe_load, JSON signé à la place de pickle. |
| P1 | 10.0 | `app.py:76` | CWE-502 | semgrep | Donnée issue de la requête HTTP atteignant le point sensible dans `restore_session()`. (route HTTP) | Ne jamais désérialiser une donnée non fiable : yaml.safe_load, JSON signé à la place de pickle. |
| P1 | 10.0 | `pyyaml==5.3.1` | CVE-2020-14343 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `pyyaml` 5.3.1 → ≥ 5.4. |
| P2 | 8.5 | `app.py:59` | CWE-22 | semgrep | Donnée issue de la requête HTTP atteignant le point sensible dans `download()`. (route HTTP) | Résoudre le chemin et vérifier qu'il reste sous le répertoire de base (ou flask.safe_join). |
| P2 | 8.0 | `flask==0.12.2` | CVE-2018-1000656 | trivy | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `flask` 0.12.2 → ≥ 0.12.3. |
| P2 | 7.6 | `jinja2==2.10` | CVE-2019-10906 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 2.10.1. |
| P2 | 7.0 | `app.py:85` | CWE-327 | semgrep | Algorithme de hachage rapide appliqué à un mot de passe/secret (cassable hors ligne). | Mot de passe : utiliser un KDF lent (argon2id, scrypt, bcrypt) avec sel. |
| P2 | 7.0 | `app.py:89` | CWE-489 | semgrep | Mode debug actif dans le point d'entrée : console Werkzeug exposée. | Désactiver le debug hors développement et servir via un serveur WSGI (gunicorn). |
| P3 | 6.5 | `werkzeug==0.14.1` | CVE-2019-14806 | grype | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 0.15.3. |
| P3 | 5.5 | `app.py:17` | CWE-798 | semgrep | Littéral affecté à une clé de configuration sensible dans du code déployé. | Sortir le secret du code (variable d'environnement / coffre de secrets) puis le faire tourner. |
| P3 | 5.0 | `requests==2.19.1` | CVE-2018-18074 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.20.0. |
| P3 | 5.0 | `urllib3==1.24.1` | CVE-2019-11324 | trivy | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.24.2. |
| P4 | 3.6 | `urllib3==1.24.1` | CVE-2019-11236 | grype | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.24.3. |

## Faux positifs écartés (à confirmer)

| Emplacement | Justification |
|---|---|
| `app.py:40` | Requête SQL entièrement constante et valeurs passées en paramètres liés (`execute(query, params)`) : pas d'injection possible. |
| `app.py:53` | Commande shell littérale, aucune donnée externe n'atteint `shell=True`. |
| `app.py:70` | `yaml.load` appelé avec `Loader=SafeLoader` (chargeur sûr). |
| `tests/test_app.py:2` | Fichier de test (`tests/test_app.py`) : non déployé, valeurs factices. |
| `app.py:81` | Hachage déclaré `usedforsecurity=False` (usage non cryptographique, ex. clé de cache). |
