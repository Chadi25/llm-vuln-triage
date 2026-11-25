"""Évaluation du filtre de faux positifs contre la vérité terrain annotée à la main.
Classe positive = « faux positif écarté »."""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from .models import Finding


def load_truth(path: str | Path, src_root: str | Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    truth = {}
    for e in data.get("sast", []):
        lines = (Path(src_root) / e["file"]).read_text(encoding="utf-8").splitlines()
        line = next(i for i, l in enumerate(lines, 1) if e["match"] in l)
        truth[f"{e['file']}:{line}:{e['cwe']}"] = e["label"]
    for e in data.get("sca", []):
        truth[f"{e['package'].lower()}:{e['id']}"] = e["label"]
    return truth


def evaluate(findings: List[Finding], truth: dict) -> dict:
    tp = fp = fn = tn = 0
    errors, unmatched = [], []
    seen = set()
    for f in findings:
        label = truth.get(f.key)
        if label is None:
            unmatched.append(f.key)
            continue
        seen.add(f.key)
        pred_fp = f.verdict == "FP"
        if pred_fp and label == "FP":
            tp += 1
        elif pred_fp and label == "TP":
            fp += 1; errors.append(f"{f.key} : vraie faille écartée à tort")
        elif not pred_fp and label == "FP":
            fn += 1; errors.append(f"{f.key} : faux positif non détecté")
        else:
            tn += 1
    missing = sorted(set(truth) - seen)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"labelled": len(truth), "matched": len(seen), "fp_filtered_correct": tp,
            "real_vulns_dropped": fp, "fp_missed": fn, "real_vulns_kept": tn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "errors": errors, "unmatched_findings": unmatched, "missing_from_scan": missing}
