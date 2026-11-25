# Rapport de triage — `target_app`

Mode : **rules (déterministe)**

## Avant / après

| Étape | Alertes |
|---|---|
| Brutes (Semgrep + Trivy + Grype) | 86 |
| Après dédoublonnage | 45 (−41) |
| Faux positifs écartés | 0 |
| **À traiter** | **45** (47.7 % de bruit en moins) |

| Priorité | P1 | P2 | P3 | P4 |
|---|---|---|---|---|
| Nombre | 6 | 6 | 24 | 9 |

## Alertes à traiter

| Prio | Score | Emplacement | Faiblesse | Outils | Justification | Remédiation |
|---|---|---|---|---|---|---|
| P1 | 10.0 | `app.py:29` | CWE-89 | semgrep | L'argument de `execute` dérive d'un paramètre HTTP (request.*) dans `user_lookup()` sans neutralisation. (route HTTP) | Utiliser une requête paramétrée. |
| P1 | 10.0 | `app.py:47` | CWE-78 | semgrep ×3 | L'argument de `check_output` dérive d'un paramètre HTTP (request.*) dans `ping()` sans neutralisation. (route HTTP) | Supprimer shell=True et passer une liste d'arguments ; valider l'hôte (ipaddress / regex DNS). |
| P1 | 10.0 | `pyyaml==5.3.1` | CVE-2020-14343 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `pyyaml` 5.3.1 → ≥ 5.4. |
| P1 | 9.2 | `flask==0.12.2` | CVE-2018-1000656 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `flask` 0.12.2 → ≥ 0.12.3. |
| P1 | 9.2 | `flask==0.12.2` | CVE-2019-1010083 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `flask` 0.12.2 → ≥ 1.0. |
| P1 | 9.2 | `flask==0.12.2` | CVE-2023-30861 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `flask` 0.12.2 → ≥ 2.3.2, 2.2.5. |
| P2 | 8.5 | `app.py:31` | CWE-704 | semgrep | Donnée issue de la requête HTTP atteignant le point sensible dans `user_lookup()`. (route HTTP) | Revue manuelle requise. |
| P2 | 8.0 | `jinja2==2.10` | CVE-2019-10906 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 2.10.1. |
| P2 | 7.8 | `jinja2==2.10` | CVE-2025-27516 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 3.1.6. |
| P2 | 7.7 | `werkzeug==0.14.1` | CVE-2019-14806 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 0.15.3. |
| P2 | 7.0 | `app.py:85` | CWE-327 | semgrep | Algorithme de hachage rapide appliqué à un mot de passe/secret (cassable hors ligne). | Mot de passe : utiliser un KDF lent (argon2id, scrypt, bcrypt) avec sel. |
| P2 | 7.0 | `app.py:89` | CWE-489 | semgrep | Mode debug actif dans le point d'entrée : console Werkzeug exposée. | Désactiver le debug hors développement et servir via un serveur WSGI (gunicorn). |
| P3 | 6.8 | `jinja2==2.10` | CVE-2024-56326 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 3.1.5. |
| P3 | 6.5 | `jinja2==2.10` | CVE-2020-28493 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 2.11.3. |
| P3 | 6.5 | `werkzeug==0.14.1` | CVE-2019-14322 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 0.15.5. |
| P3 | 6.5 | `werkzeug==0.14.1` | CVE-2023-25577 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 2.2.3. |
| P3 | 6.5 | `werkzeug==0.14.1` | CVE-2024-34069 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.0.3. |
| P3 | 6.4 | `urllib3==1.24.1` | CVE-2025-66418 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.6.0. |
| P3 | 6.4 | `urllib3==1.24.1` | CVE-2025-66471 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.6.0. |
| P3 | 6.4 | `urllib3==1.24.1` | CVE-2026-21441 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.6.3. |
| P3 | 6.4 | `urllib3==1.24.1` | CVE-2026-97689 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.8.0. |
| P3 | 6.2 | `urllib3==1.24.1` | CVE-2019-11324 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.24.2. |
| P3 | 5.7 | `urllib3==1.24.1` | CVE-2026-44431 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.7.0. |
| P3 | 5.6 | `urllib3==1.24.1` | CVE-2023-43804 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.0.6, 1.26.17. |
| P3 | 5.3 | `werkzeug==0.14.1` | CVE-2024-49766 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.0.6. |
| P3 | 5.3 | `werkzeug==0.14.1` | CVE-2025-66221 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.1.4. |
| P3 | 5.3 | `werkzeug==0.14.1` | CVE-2026-102598 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.1.9. |
| P3 | 5.3 | `werkzeug==0.14.1` | CVE-2026-21860 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.1.5. |
| P3 | 5.3 | `werkzeug==0.14.1` | CVE-2026-27199 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 3.1.6. |
| P3 | 5.1 | `jinja2==2.10` | CVE-2024-22195 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 3.1.3. |
| P3 | 5.0 | `requests==2.19.1` | CVE-2018-18074 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.20.0. |
| P3 | 4.8 | `flask==0.12.2` | CVE-2026-27205 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : direct) | Mettre à jour `flask` 0.12.2 → ≥ 3.1.3. |
| P3 | 4.4 | `jinja2==2.10` | CVE-2024-34064 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `jinja2` 2.10 → ≥ 3.1.4. |
| P3 | 4.4 | `urllib3==1.24.1` | CVE-2020-26137 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.25.9. |
| P3 | 4.0 | `urllib3==1.24.1` | CVE-2019-11236 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.24.3. |
| P3 | 4.0 | `urllib3==1.24.1` | CVE-2024-37891 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.26.19, 2.2.2. |
| P4 | 3.6 | `requests==2.19.1` | CVE-2023-32681 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.31.0. |
| P4 | 3.6 | `urllib3==1.24.1` | CVE-2018-25091 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 1.24.2. |
| P4 | 3.6 | `urllib3==1.24.1` | CVE-2025-50181 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.5.0. |
| P4 | 3.5 | `app.py:89` | CWE-668 | semgrep | Aucun élément de contexte ne permet d'écarter l'alerte. | Revue manuelle requise. |
| P4 | 3.2 | `urllib3==1.24.1` | CVE-2023-45803 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `urllib3` 1.24.1 → ≥ 2.0.7, 1.26.18. |
| P4 | 3.1 | `requests==2.19.1` | CVE-2024-35195 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.32.0. |
| P4 | 3.0 | `requests==2.19.1` | CVE-2026-25645 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.33.0. |
| P4 | 2.8 | `requests==2.19.1` | CVE-2024-47081 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : unused) | Mettre à jour `requests` 2.19.1 → ≥ 2.32.4. |
| P4 | 2.5 | `werkzeug==0.14.1` | CVE-2023-23934 | grype, trivy ×2 | Version installée dans la plage vulnérable déclarée par la base de l'outil. (atteignabilité : transitive) | Mettre à jour `werkzeug` 0.14.1 → ≥ 2.2.3. |

## Faux positifs écartés (à confirmer)

| Emplacement | Justification |
|---|---|
