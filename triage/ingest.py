"""Normalisation des rapports Semgrep (SARIF), Trivy (JSON) et Grype (JSON)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from .models import Finding

CWE_RE = re.compile(r"CWE-(\d+)")
SARIF_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}


def _strip_root(uri: str, src_prefix: str) -> str:
    # Semgrep sous Windows écrit des chemins avec "\\" : on normalise en "/"
    uri = uri.replace("file://", "").replace("\\", "/").lstrip("./")
    if src_prefix and uri.startswith(src_prefix.rstrip("/") + "/"):
        uri = uri[len(src_prefix.rstrip("/")) + 1:]
    return uri


def parse_sarif(data: dict, src_prefix: str = "target_app") -> List[Finding]:
    out: List[Finding] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "sarif").split()[0].lower()
        rules = {r["id"]: r for r in driver.get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "unknown")
            rule = rules.get(rid, {})
            tags = " ".join(rule.get("properties", {}).get("tags", []))
            m = CWE_RE.search(tags) or CWE_RE.search(res.get("message", {}).get("text", ""))
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            out.append(Finding(
                kind="sast", rule_id=rid, rules=[rid], tools=[tool],
                message=res.get("message", {}).get("text", ""),
                severity=SARIF_LEVEL.get(level, "MEDIUM"),
                cwe=f"CWE-{m.group(1)}" if m else None,
                file=_strip_root(loc.get("artifactLocation", {}).get("uri", ""), src_prefix),
                line=region.get("startLine"),
                end_line=region.get("endLine"),
                snippet=region.get("snippet", {}).get("text"),
            ))
    return out


def _best_cvss(cvss: dict):
    scores = [v.get("V3Score") for v in (cvss or {}).values() if v.get("V3Score") is not None]
    return max(scores) if scores else None


def parse_trivy(data: dict) -> List[Finding]:
    out: List[Finding] = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.append(Finding(
                kind="sca", rule_id=v["VulnerabilityID"], rules=[v["VulnerabilityID"]], tools=["trivy"],
                message=v.get("Title", ""), severity=v.get("Severity", "UNKNOWN").upper(),
                package=v.get("PkgName", "").lower(), version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion") or None, cvss=_best_cvss(v.get("CVSS")),
                file=res.get("Target"),
            ))
    return out


def parse_grype(data: dict) -> List[Finding]:
    out: List[Finding] = []
    for mt in data.get("matches", []):
        v, a = mt.get("vulnerability", {}), mt.get("artifact", {})
        related = mt.get("relatedVulnerabilities", []) or []
        # Grype rapporte souvent l'avis GitHub (GHSA-...) et met le CVE dans relatedVulnerabilities :
        # on retient le CVE comme identifiant canonique pour dédoublonner avec Trivy.
        ids = [v.get("id")] + [r.get("id") for r in related]
        cve = next((i for i in ids if i and i.startswith("CVE-")), v.get("id"))
        scores = [c.get("metrics", {}).get("baseScore")
                  for src in [v] + related for c in src.get("cvss", []) if c.get("metrics")]
        desc = v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
        fixes = v.get("fix", {}).get("versions") or []
        out.append(Finding(
            kind="sca", rule_id=cve, rules=[i for i in dict.fromkeys(ids) if i], tools=["grype"],
            message=desc, severity=str(v.get("severity", "Unknown")).upper(),
            package=a.get("name", "").lower(), version=a.get("version"),
            fixed_version=fixes[0] if fixes else None,
            cvss=max([s for s in scores if s is not None], default=None),
            file=(a.get("locations") or [{}])[0].get("path"),
        ))
    return out


def load_report(path: str | Path, src_prefix: str = "target_app") -> List[Finding]:
    """Détecte automatiquement le format du rapport."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "runs" in data and "version" in data:
        return parse_sarif(data, src_prefix)
    if "Results" in data or data.get("SchemaVersion"):
        return parse_trivy(data)
    if "matches" in data:
        return parse_grype(data)
    raise ValueError(f"format de rapport non reconnu : {path}")
