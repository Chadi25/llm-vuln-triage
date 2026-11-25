"""Priorisation : score de base (CVSS pour le SCA, estimation par classe CWE pour
le SAST) ajusté par le contexte (exposition HTTP, taint, atteignabilité)."""
from __future__ import annotations

from .context import CodeIndex
from .models import Finding

# Estimation de gravité par classe CWE (le SAST ne fournit pas de CVSS).
CWE_BASE = {"CWE-89": 9.0, "CWE-78": 9.0, "CWE-502": 9.0, "CWE-94": 9.0, "CWE-22": 7.5,
            "CWE-798": 7.0, "CWE-489": 6.5, "CWE-327": 5.0, "CWE-328": 5.0}
SEV_BASE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}

# nom de distribution -> nom d'import ; dépendances transitives connues
IMPORT_NAME = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn"}
TRANSITIVE = {"flask": {"werkzeug", "jinja2", "itsdangerous", "click", "markupsafe"},
              "requests": {"urllib3", "idna", "chardet", "certifi"}}


def reachability(pkg: str, index: CodeIndex) -> str:
    imports = {i.lower() for i in index.imports}
    if IMPORT_NAME.get(pkg, pkg).lower() in imports:
        return "direct"
    for parent, children in TRANSITIVE.items():
        if pkg in children and parent in imports:
            return "transitive"
    return "unused"


def bucket(score: float) -> str:
    return "P1" if score >= 9 else "P2" if score >= 7 else "P3" if score >= 4 else "P4"


def prioritize(f: Finding, index: CodeIndex) -> None:
    if f.kind == "sca":
        base = f.cvss if f.cvss is not None else SEV_BASE.get(f.severity, 5.0)
        f.reachability = reachability(f.package or "", index)
        adj = {"direct": 0.5, "transitive": -1.0, "unused": -2.5}[f.reachability]
    else:
        base = CWE_BASE.get(f.cwe or "", SEV_BASE.get(f.severity, 5.0))
        adj = 0.0
        if f.cwe == "CWE-489":
            adj += 0.5          # debug + host 0.0.0.0 : console interactive exposée
        elif f.cwe in ("CWE-327", "CWE-328") and f.tainted:
            adj += 2.0          # hachage faible sur mot de passe
        elif f.exposed_http and f.tainted:
            adj += 1.0          # source HTTP -> sink : exploitable à distance
        elif not f.exposed_http and not f.tainted:
            adj -= 1.5          # pas de chemin depuis une entrée externe identifié
    if f.llm_advice:
        adj += 0.5 * f.llm_advice.get("priority_adjustment", 0)
    f.score = round(max(0.0, min(10.0, base + adj)), 1)
    f.priority = bucket(f.score) if f.verdict != "FP" else "-"
