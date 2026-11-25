import json
from pathlib import Path

import pytest

from triage.cli import main
from triage.context import CodeIndex
from triage.dedup import deduplicate
from triage.evaluate import evaluate, load_truth
from triage.fp_filter import classify
from triage.ingest import load_report
from triage.llm import ContextProvider, LLMAdvisor
from triage.models import Finding, validate_advice
from triage.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
SRC = ROOT / "target_app"
REPORTS = [FIX / "semgrep.sarif", FIX / "trivy.json", FIX / "grype.json"]


def test_ingest_formats():
    sarif, trivy, grype = (load_report(p) for p in REPORTS)
    assert len(sarif) == 15 and all(f.kind == "sast" and f.cwe for f in sarif)
    assert {f.file for f in sarif} == {"app.py", "tests/test_app.py"}
    assert len(trivy) == 5 and len(grype) == 5
    assert all(f.package == f.package.lower() for f in trivy + grype)


def test_dedup_merges_rules_and_tools():
    out = deduplicate([f for p in REPORTS for f in load_report(p)])
    assert len(out) == 20
    sqli = next(f for f in out if f.key == "app.py:31:CWE-89")
    assert sqli.raw_count == 2 and len(sqli.rules) == 2
    yaml_cve = next(f for f in out if f.rule_id == "CVE-2020-14343")
    assert yaml_cve.tools == ["grype", "trivy"]


def test_end_to_end_against_ground_truth():
    res = run(REPORTS, SRC)
    ev = evaluate(res["findings"], load_truth(FIX / "ground_truth.yaml", SRC))
    assert ev["matched"] == ev["labelled"] == 20
    assert ev["real_vulns_dropped"] == 0          # exigence : ne jamais perdre une vraie faille
    assert ev["precision"] == 1.0 and ev["recall"] == 1.0
    s = res["stats"]
    assert (s["raw"], s["deduplicated"], s["false_positives"], s["kept"]) == (25, 20, 5, 15)


def test_priorities_use_context():
    by = {f.key: f for f in run(REPORTS, SRC)["findings"]}
    assert by["app.py:31:CWE-89"].priority == "P1" and by["app.py:31:CWE-89"].exposed_http
    assert by["pyyaml:CVE-2020-14343"].reachability == "direct"
    assert by["jinja2:CVE-2019-10906"].reachability == "transitive"
    assert by["requests:CVE-2018-18074"].reachability == "unused"
    assert by["requests:CVE-2018-18074"].score < by["pyyaml:CVE-2020-14343"].score


# --- généralisation : motifs absents de la cible de démo --------------------------------
UNSEEN = '''
import os, sqlite3, subprocess, yaml
from flask import Flask, request
app = Flask(__name__)

@app.post("/run")
def run_job():
    job = request.json["job"]
    cmd = "backup " + job
    os.system(cmd)

def nightly():
    os.system("backup --all")

@app.get("/q")
def q():
    term = request.args["t"]
    sqlite3.connect("x").executescript(f"SELECT * FROM t WHERE a='{term}'")

def conf(path):
    return yaml.safe_load(open(path))
'''


@pytest.fixture
def unseen_index(tmp_path):
    (tmp_path / "svc.py").write_text(UNSEEN)
    return CodeIndex(tmp_path)


def _line(snippet):
    return next(i for i, l in enumerate(UNSEEN.splitlines(), 1) if snippet in l)


@pytest.mark.parametrize("snippet,cwe,expected", [
    ("os.system(cmd)", "CWE-78", "TP"),            # taint propagé via une variable intermédiaire
    ('os.system("backup --all")', "CWE-78", "FP"),
    ("executescript(f", "CWE-89", "TP"),
    ("yaml.safe_load", "CWE-502", "FP"),
])
def test_rules_generalise(unseen_index, snippet, cwe, expected):
    f = Finding(kind="sast", rule_id="x", message="m", severity="HIGH", cwe=cwe, file="svc.py", line=_line(snippet))
    verdict, why = classify(f, unseen_index)
    assert verdict == expected, why


# --- couche LLM : conseil uniquement, sortie validée ---------------------------------------
def _advisor(reply):
    return LLMAdvisor(lambda prompt: reply, "fake", ContextProvider(CodeIndex(SRC), use_llamaindex=False))


def test_llm_invalid_output_falls_back_to_rules():
    adv = _advisor("je pense que c'est grave")             # pas du JSON
    res = run(REPORTS, SRC, advisor=adv)
    assert adv.stats["invalid"] == 20 and adv.stats["valid"] == 0
    assert res["stats"]["false_positives"] == 5 and res["stats"]["review"] == 0


def test_llm_disagreement_goes_to_human_review():
    reply = json.dumps({"verdict": "FP", "justification": "Le modèle estime ceci inoffensif.",
                        "confidence": 0.9, "priority_adjustment": 0, "fix": ""})
    adv = _advisor(reply)
    res = run(REPORTS, SRC, advisor=adv)
    # le LLM ne peut rien supprimer : chaque désaccord passe en REVIEW
    assert res["stats"]["review"] == 15 and res["stats"]["false_positives"] == 5
    assert res["stats"]["kept"] == 15


@pytest.mark.parametrize("bad", [
    {"verdict": "MAYBE", "justification": "xxxxxxxxxxxx", "confidence": 0.5},
    {"verdict": "TP", "justification": "court", "confidence": 0.5},
    {"verdict": "TP", "justification": "assez longue ici", "confidence": 3},
    {"verdict": "TP", "justification": "assez longue ici", "confidence": 0.5, "priority_adjustment": 9},
])
def test_advice_schema_rejects(bad):
    with pytest.raises(ValueError):
        validate_advice(bad)


def test_cli_fail_on(tmp_path):
    args = ["run", "--src", str(SRC), "--out", str(tmp_path)] + sum((["--report", str(p)] for p in REPORTS), [])
    assert main(args + ["--fail-on", "P1"]) == 1
    assert (tmp_path / "triage.html").exists() and (tmp_path / "triage.md").exists()


def test_multiline_region_real_sqli_not_dismissed():
    """Régression trouvée sur un vrai scan Semgrep : la région commence sur
    `request.args.get("id", "")` (2 arguments constants) et le vrai puits `execute(f"...")`
    est 2 lignes plus bas. Le filtre ne doit pas y voir une requête paramétrée."""
    root = Path(__file__).resolve().parents[1] / "target_app"
    lines = (root / "app.py").read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines, 1) if 'request.args.get("id", "")' in l)
    end = next(i for i, l in enumerate(lines, 1) if i > start and "cur.execute(f" in l)
    f = Finding(kind="sast", rule_id="sql-injection-db-cursor-execute", rules=["x"], tools=["semgrep"], message="SQLi",
                cwe="CWE-89", file="app.py", line=start, end_line=end, severity="MEDIUM")
    verdict, why = classify(f, CodeIndex(root))
    assert verdict == "TP", why
