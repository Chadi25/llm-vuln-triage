#!/usr/bin/env bash
# Lance les VRAIS scanners sur target_app/ (si installés) puis le triage.
#   pip install semgrep ; trivy et grype : binaires officiels (Aqua Security / Anchore)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports
ARGS=()
if command -v semgrep >/dev/null; then
  semgrep scan --config p/python --config p/flask --config p/secrets --sarif -o reports/semgrep.sarif target_app || true
  ARGS+=(--report reports/semgrep.sarif)
else echo "[skip] semgrep absent"; fi
if command -v trivy >/dev/null; then
  trivy fs --scanners vuln -f json -o reports/trivy.json target_app
  ARGS+=(--report reports/trivy.json)
else echo "[skip] trivy absent"; fi
if command -v grype >/dev/null; then
  grype dir:target_app -o json > reports/grype.json
  ARGS+=(--report reports/grype.json)
else echo "[skip] grype absent"; fi
if [ ${#ARGS[@]} -eq 0 ]; then
  echo "Aucun scanner installé : utilisez 'make demo' (rapports d'exemple)."; exit 1
fi
python3 -m triage run "${ARGS[@]}" --src target_app --out out-real ${LLM_ARGS:-}
