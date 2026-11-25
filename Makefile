PY ?= python3
REPORTS = --report fixtures/semgrep.sarif --report fixtures/trivy.json --report fixtures/grype.json
MODEL ?= qwen2.5-coder:7b

.PHONY: demo demo-llm scan test fixtures clean

demo:            ## triage déterministe sur les rapports d'exemple + évaluation
	$(PY) -m triage run $(REPORTS) --src target_app --truth fixtures/ground_truth.yaml --synthetic --out out

demo-llm:        ## même chose avec un LLM local via Ollama (ollama serve + ollama pull $(MODEL))
	$(PY) -m triage run $(REPORTS) --src target_app --truth fixtures/ground_truth.yaml --synthetic --out out-llm --llm ollama --model $(MODEL)

scan:            ## vrais scanners (semgrep / trivy / grype) puis triage
	./scripts/run_scanners.sh

fixtures:        ## régénère les rapports d'exemple (lignes recalculées depuis target_app/)
	$(PY) scripts/make_sample_reports.py

test:
	$(PY) -m pytest -q

clean:
	rm -rf out out-llm out-real reports .pytest_cache
