#!/usr/bin/env python3
"""Génère les rapports d'EXEMPLE dans fixtures/ (Semgrep SARIF, Trivy JSON, Grype JSON).

Ces rapports sont SYNTHÉTIQUES : ils reproduisent le format de sortie réel des
outils (SARIF 2.1.0 de `semgrep --sarif`, `trivy fs -f json`, `grype -o json`)
pour que le pipeline soit démontrable sans les outils installés. Les numéros de
ligne sont recalculés à partir du code de target_app/ (recherche du snippet).
Pour de vrais rapports : scripts/run_scanners.sh.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "target_app"

# (rule_id, cwe, level, fichier, snippet recherché, message)
SAST = [
    ("python.flask.security.injection.tainted-sql-string.tainted-sql-string", "CWE-89", "error",
     "app.py", "cur.execute(f\"SELECT", "Detected user input used to manually construct a SQL string."),
    ("python.lang.security.audit.formatted-sql-query.formatted-sql-query", "CWE-89", "warning",
     "app.py", "cur.execute(f\"SELECT", "Detected possible formatted SQL query. Use parameterized queries instead."),
    ("python.lang.security.audit.formatted-sql-query.formatted-sql-query", "CWE-89", "warning",
     "app.py", "cur.execute(query, (user_id,))", "Detected possible formatted SQL query. Use parameterized queries instead."),
    ("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "CWE-78", "error",
     "app.py", "subprocess.check_output(\"ping", "Found 'subprocess' function with 'shell=True'. This is dangerous."),
    ("python.flask.security.injection.subprocess-injection.subprocess-injection", "CWE-78", "error",
     "app.py", "subprocess.check_output(\"ping", "Detected user input entering a subprocess call unsafely."),
    ("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "CWE-78", "error",
     "app.py", "subprocess.run(\"ls -la", "Found 'subprocess' function with 'shell=True'. This is dangerous."),
    ("python.flask.security.injection.path-traversal-open.path-traversal-open", "CWE-22", "error",
     "app.py", "send_file(os.path.join(BASE_DIR, name))", "Found request data in a call to a file path function."),
    ("python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load", "CWE-502", "error",
     "app.py", "cfg = yaml.load(request.data)", "Avoid using insecure deserialization library, backed by `pickle`, `_pickle`, `cpickle`, `dill`, `shelve`, or `yaml`."),
    ("python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load", "CWE-502", "error",
     "app.py", "yaml.load(f, Loader=yaml.SafeLoader)", "Avoid using insecure deserialization library, backed by `pickle`, `_pickle`, `cpickle`, `dill`, `shelve`, or `yaml`."),
    ("python.lang.security.deserialization.pickle.avoid-pickle", "CWE-502", "warning",
     "app.py", "pickle.loads(bytes.fromhex(blob))", "Avoid using `pickle`, which is known to lead to code execution vulnerabilities."),
    ("python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5", "CWE-327", "warning",
     "app.py", "hashlib.md5(payload, usedforsecurity=False)", "Detected MD5 hash algorithm which is considered insecure."),
    ("python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5", "CWE-327", "warning",
     "app.py", "hashlib.md5(pwd.encode())", "Detected MD5 hash algorithm which is considered insecure."),
    ("python.flask.security.audit.debug-enabled.debug-enabled", "CWE-489", "warning",
     "app.py", "app.run(host=\"0.0.0.0\", debug=True)", "Detected Flask app with debug=True. Do not deploy to production with this flag enabled."),
    ("generic.secrets.security.detected-generic-secret.detected-generic-secret", "CWE-798", "error",
     "app.py", "app.config[\"SECRET_KEY\"] =", "Hardcoded secret detected."),
    ("generic.secrets.security.detected-generic-secret.detected-generic-secret", "CWE-798", "error",
     "tests/test_app.py", "TEST_PASSWORD = ", "Hardcoded secret detected."),
]

# (pkg, version, cve, cvss, vecteur, sévérité, fixed, titre, trivy?, grype?)
SCA = [
    ("PyYAML", "5.3.1", "CVE-2020-14343", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "5.4",
     "PyYAML: incomplete fix for CVE-2020-1747 (arbitrary code execution via full_load)", True, True),
    ("Jinja2", "2.10", "CVE-2019-10906", 8.6, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "HIGH", "2.10.1",
     "Jinja2: sandbox escape via str.format", True, True),
    ("Flask", "0.12.2", "CVE-2018-1000656", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HIGH", "0.12.3",
     "Flask: denial of service via crafted JSON data (incorrect encoding)", True, False),
    ("requests", "2.19.1", "CVE-2018-18074", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "2.20.0",
     "requests: Authorization header sent on HTTPS to HTTP redirect", True, True),
    ("urllib3", "1.24.1", "CVE-2019-11324", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "HIGH", "1.24.2",
     "urllib3: certificate validation issue with custom CA certificates", True, False),
    ("urllib3", "1.24.1", "CVE-2019-11236", 6.1, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM", "1.24.3",
     "urllib3: CRLF injection in the request parameter", False, True),
    ("Werkzeug", "0.14.1", "CVE-2019-14806", 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH", "0.15.3",
     "Werkzeug: insufficient randomness of the debugger PIN in Docker containers", False, True),
]


def find_line(rel: str, snippet: str):
    for i, line in enumerate((APP / rel).read_text(encoding="utf-8").splitlines(), 1):
        if snippet in line:
            return i, line.strip()
    raise SystemExit(f"snippet introuvable: {rel}: {snippet}")


def sarif():
    rules, seen, results = [], set(), []
    for rid, cwe, level, rel, snip, msg in SAST:
        if rid not in seen:
            seen.add(rid)
            rules.append({
                "id": rid, "name": rid,
                "shortDescription": {"text": msg},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": [f"{cwe}: see MITRE CWE", "security"], "precision": "very-high"},
            })
        line, text = find_line(rel, snip)
        results.append({
            "ruleId": rid, "level": level, "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f"target_app/{rel}", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line, "endLine": line, "startColumn": 5, "snippet": {"text": text}},
            }}],
        })
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "SYNTHETIC-FIXTURE", "rules": rules}},
                  "results": results}],
    }


def trivy():
    vulns = [{
        "VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": ver, "FixedVersion": fixed,
        "Severity": sev, "Title": title, "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
        "CVSS": {"nvd": {"V3Vector": vec, "V3Score": score}},
    } for pkg, ver, cve, score, vec, sev, fixed, title, t, _ in SCA if t]
    return {"SchemaVersion": 2, "ArtifactName": "target_app", "ArtifactType": "filesystem",
            "Metadata": {"_comment": "SYNTHETIC FIXTURE - format trivy fs -f json"},
            "Results": [{"Target": "target_app/requirements.txt", "Class": "lang-pkgs", "Type": "pip",
                         "Vulnerabilities": vulns}]}


def grype():
    matches = [{
        "vulnerability": {"id": cve, "dataSource": f"https://nvd.nist.gov/vuln/detail/{cve}",
                          "severity": sev.capitalize(), "description": title,
                          "cvss": [{"version": vec.split('/')[0].split(':')[1], "vector": vec,
                                    "metrics": {"baseScore": score}}],
                          "fix": {"versions": [fixed], "state": "fixed"}},
        "artifact": {"name": pkg.lower() if pkg != "PyYAML" else "pyyaml", "version": ver, "type": "python",
                     "language": "python", "locations": [{"path": "/target_app/requirements.txt"}]},
        "matchDetails": [{"type": "exact-direct-match", "matcher": "python-matcher"}],
    } for pkg, ver, cve, score, vec, sev, fixed, title, _, g in SCA if g]
    return {"matches": matches, "source": {"type": "directory", "target": "target_app"},
            "descriptor": {"name": "grype", "version": "SYNTHETIC-FIXTURE"}}


if __name__ == "__main__":
    out = ROOT / "fixtures"
    (out / "semgrep.sarif").write_text(json.dumps(sarif(), indent=2), encoding="utf-8")
    (out / "trivy.json").write_text(json.dumps(trivy(), indent=2), encoding="utf-8")
    (out / "grype.json").write_text(json.dumps(grype(), indent=2), encoding="utf-8")
    print("fixtures écrites :", len(SAST), "SAST,", sum(t for *_, t, _ in SCA), "Trivy,", sum(g for *_, g in SCA), "Grype")
