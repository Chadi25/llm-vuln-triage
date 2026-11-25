"""Interface en ligne de commande.

  python -m triage run --report fixtures/semgrep.sarif --report fixtures/trivy.json \
      --report fixtures/grype.json --src target_app --truth fixtures/ground_truth.yaml
  python -m triage run ... --llm ollama --model qwen2.5-coder:7b
"""
from __future__ import annotations

import argparse
import sys

from .context import CodeIndex
from .evaluate import evaluate, load_truth
from .llm import ContextProvider, LLMAdvisor, ollama_client
from .pipeline import run
from .report import write_reports


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage", description="Triage SAST/SCA assisté par LLM local")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--report", action="append", required=True, help="SARIF Semgrep, JSON Trivy ou Grype (répétable)")
    r.add_argument("--src", default="target_app", help="racine du code analysé")
    r.add_argument("--src-prefix", default=None, help="préfixe à retirer des chemins SARIF (défaut : --src)")
    r.add_argument("--out", default="out")
    r.add_argument("--truth", help="vérité terrain YAML pour mesurer le filtre FP")
    r.add_argument("--llm", choices=["none", "ollama"], default="none")
    r.add_argument("--model", default="qwen2.5-coder:7b")
    r.add_argument("--ollama-url", default="http://localhost:11434")
    r.add_argument("--no-llamaindex", action="store_true")
    r.add_argument("--synthetic", action="store_true", help="signale dans le rapport des entrées synthétiques")
    r.add_argument("--fail-on", choices=["P1", "P2", "P3", "P4"], help="code retour 1 si une alerte ≥ ce niveau")
    a = ap.parse_args(argv)

    index = CodeIndex(a.src)
    advisor, mode = None, "rules (déterministe)"
    if a.llm == "ollama":
        ctx = ContextProvider(index, use_llamaindex=not a.no_llamaindex)
        advisor = LLMAdvisor(ollama_client(a.model, a.ollama_url), f"ollama:{a.model}", ctx)
        mode = f"rules + ollama:{a.model} (contexte {ctx.mode})"
    result = run(a.report, a.src, a.src_prefix or a.src.rstrip("/").split("/")[-1], advisor, index)
    ev = evaluate(result["findings"], load_truth(a.truth, a.src)) if a.truth else None
    paths = write_reports(result, a.out, ev, a.src, mode, a.synthetic)

    s = result["stats"]
    print(f"Alertes brutes          : {s['raw']}  {s['raw_by_tool']}")
    print(f"Après dédoublonnage     : {s['deduplicated']}  (−{s['duplicates_removed']})")
    print(f"Faux positifs écartés   : {s['false_positives']}")
    print(f"À traiter               : {s['kept']}  {s['by_priority']}  (−{s['reduction_pct']} % de bruit)")
    if ev:
        print(f"Filtre FP               : précision {ev['precision']} · rappel {ev['recall']} "
              f"({ev['matched']}/{ev['labelled']} annotées)")
        for e in ev["errors"]:
            print("  !", e)
    if "llm" in s:
        print("LLM                     :", s["llm"])
    print("Rapports                :", ", ".join(paths.values()))
    if a.fail_on:
        order = ["P1", "P2", "P3", "P4"]
        lim = order.index(a.fail_on)
        if any(p in order[:lim + 1] and n for p, n in s["by_priority"].items()):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
