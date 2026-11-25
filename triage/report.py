"""Rendu des résultats : JSON, Markdown et HTML (jinja2)."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Optional

TEMPLATES = Path(__file__).parent / "templates"


def to_markdown(result: dict, ev: Optional[dict], target: str, mode: str, synthetic: bool) -> str:
    s = result["stats"]
    kept = [f for f in result["findings"] if f.verdict != "FP"]
    fps = [f for f in result["findings"] if f.verdict == "FP"]
    L = [f"# Rapport de triage — `{target}`", "",
         f"Mode : **{mode}**" + (" · rapports d'entrée **synthétiques** (fixtures)" if synthetic else ""), "",
         "## Avant / après", "", "| Étape | Alertes |", "|---|---|",
         f"| Brutes (Semgrep + Trivy + Grype) | {s['raw']} |",
         f"| Après dédoublonnage | {s['deduplicated']} (−{s['duplicates_removed']}) |",
         f"| Faux positifs écartés | {s['false_positives']} |",
         f"| **À traiter** | **{s['kept']}** ({s['reduction_pct']} % de bruit en moins) |", "",
         "| Priorité | " + " | ".join(s["by_priority"]) + " |",
         "|---" * (len(s["by_priority"]) + 1) + "|",
         "| Nombre | " + " | ".join(str(v) for v in s["by_priority"].values()) + " |", ""]
    if ev:
        L += ["## Qualité du filtre de faux positifs", "",
              f"- Précision : **{ev['precision']}** · rappel : **{ev['recall']}**",
              f"- {ev['fp_filtered_correct']} FP correctement écartés, {ev['real_vulns_dropped']} vraie(s) faille(s) "
              f"écartée(s) à tort, {ev['fp_missed']} FP manqué(s) ({ev['matched']}/{ev['labelled']} entrées annotées)", ""]
        L += [f"- ⚠ {e}" for e in ev["errors"]] + ([""] if ev["errors"] else [])
    L += ["## Alertes à traiter", "", "| Prio | Score | Emplacement | Faiblesse | Outils | Justification | Remédiation |",
          "|---|---|---|---|---|---|---|"]
    for f in kept:
        ctx = f" (atteignabilité : {f.reachability})" if f.kind == "sca" else (" (route HTTP)" if f.exposed_http else "")
        L.append(f"| {f.priority}{' REVIEW' if f.verdict == 'REVIEW' else ''} | {f.score} | `{f.location}` | "
                 f"{f.cwe or f.rule_id} | {', '.join(f.tools)}{f' ×{f.raw_count}' if f.raw_count > 1 else ''} | "
                 f"{f.justification}{ctx} | {f.remediation} |")
    L += ["", "## Faux positifs écartés (à confirmer)", "", "| Emplacement | Justification |", "|---|---|"]
    L += [f"| `{f.location}` | {f.justification} |" for f in fps]
    return "\n".join(L) + "\n"


def write_reports(result: dict, out_dir: str | Path, ev: Optional[dict] = None, target: str = "target_app",
                  mode: str = "rules", synthetic: bool = False) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = {"stats": result["stats"], "evaluation": ev, "mode": mode, "synthetic_inputs": synthetic,
               "findings": [f.to_dict() for f in result["findings"]]}
    (out / "triage.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "triage.md").write_text(to_markdown(result, ev, target, mode, synthetic), encoding="utf-8")
    paths = {"json": str(out / "triage.json"), "md": str(out / "triage.md")}
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
        html = env.get_template("report.html.j2").render(
            s=result["stats"], ev=ev, target=target, mode=mode, synthetic=synthetic,
            date=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
            kept=[f for f in result["findings"] if f.verdict != "FP"],
            fps=[f for f in result["findings"] if f.verdict == "FP"])
        (out / "triage.html").write_text(html, encoding="utf-8")
        paths["html"] = str(out / "triage.html")
    except ImportError:
        pass
    return paths
