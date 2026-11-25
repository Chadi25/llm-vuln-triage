"""Orchestration : ingestion → dédoublonnage → faux positifs → priorisation → remédiation → (LLM)."""
from __future__ import annotations

from collections import Counter
from typing import Iterable, List, Optional

from .context import CodeIndex
from .dedup import deduplicate
from .fp_filter import classify
from .ingest import load_report
from .llm import LLMAdvisor
from .models import Finding
from .prioritize import prioritize
from .remediation import suggest

PRIO_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "-": 9}


def triage(findings: List[Finding], index: CodeIndex, advisor: Optional[LLMAdvisor] = None) -> dict:
    raw = len(findings)
    raw_by_tool = Counter(t for f in findings for t in f.tools)
    deduped = deduplicate(findings)
    for f in deduped:
        f.verdict, f.justification = classify(f, index)
        suggest(f)
        if advisor is not None:
            advisor.apply(f)
        prioritize(f, index)
    deduped.sort(key=lambda f: (f.verdict == "FP", PRIO_ORDER.get(f.priority, 9), -f.score))
    kept = [f for f in deduped if f.verdict != "FP"]
    stats = {
        "raw": raw,
        "raw_by_tool": dict(raw_by_tool),
        "raw_sast": sum(1 for f in findings if f.kind == "sast"),
        "raw_sca": sum(1 for f in findings if f.kind == "sca"),
        "deduplicated": len(deduped),
        "duplicates_removed": raw - len(deduped),
        "false_positives": sum(1 for f in deduped if f.verdict == "FP"),
        "review": sum(1 for f in deduped if f.verdict == "REVIEW"),
        "kept": len(kept),
        "by_priority": {p: sum(1 for f in kept if f.priority == p) for p in ("P1", "P2", "P3", "P4")},
        "reduction_pct": round(100 * (1 - len(kept) / raw), 1) if raw else 0.0,
    }
    if advisor is not None:
        stats["llm"] = dict(advisor.stats, backend=advisor.name, context=advisor.context.mode)
    return {"stats": stats, "findings": deduped}


def run(reports: Iterable[str], src_root: str, src_prefix: str = "target_app",
        advisor: Optional[LLMAdvisor] = None, index: Optional[CodeIndex] = None) -> dict:
    findings: List[Finding] = []
    for r in reports:
        findings.extend(load_report(r, src_prefix))
    return triage(findings, index or CodeIndex(src_root), advisor)
