"""Dédoublonnage : empreinte exacte puis rapprochement flou (même fichier, même
CWE, lignes proches, messages similaires) pour fusionner les alertes de
règles/outils différents qui pointent la même faille."""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Dict, List

from .models import Finding

SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _merge(into: Finding, other: Finding) -> None:
    into.tools = sorted(set(into.tools) | set(other.tools))
    into.rules = sorted(set(into.rules) | set(other.rules))
    into.raw_count += other.raw_count
    if SEV_ORDER.index(other.severity if other.severity in SEV_ORDER else "INFO") > \
       SEV_ORDER.index(into.severity if into.severity in SEV_ORDER else "INFO"):
        into.severity = other.severity
    if other.cvss is not None and (into.cvss is None or other.cvss > into.cvss):
        into.cvss = other.cvss
    into.fixed_version = into.fixed_version or other.fixed_version
    if other.message and len(other.message) > len(into.message or ""):
        into.message = other.message


def similar(a: Finding, b: Finding, line_window: int = 2, threshold: float = 0.55) -> bool:
    if a.kind != "sast" or b.kind != "sast" or a.file != b.file or a.cwe != b.cwe or a.cwe is None:
        return False
    if a.line is None or b.line is None or abs(a.line - b.line) > line_window:
        return False
    if a.snippet and b.snippet and a.snippet == b.snippet:
        return True
    return SequenceMatcher(None, a.message.lower(), b.message.lower()).ratio() >= threshold and a.line == b.line


def deduplicate(findings: List[Finding]) -> List[Finding]:
    exact: Dict[str, Finding] = {}
    for f in findings:
        if f.key in exact:
            _merge(exact[f.key], f)
        else:
            exact[f.key] = f
    merged: List[Finding] = []
    for f in exact.values():
        for m in merged:
            if similar(m, f):
                _merge(m, f)
                break
        else:
            merged.append(f)
    return merged
