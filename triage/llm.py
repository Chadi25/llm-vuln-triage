"""Couche LLM pluggable. Le LLM CONSEILLE seulement :
- sa sortie doit être un JSON valide conforme au schéma `Advice` (pydantic) ;
- le verdict déterministe reste la référence ; en cas de désaccord, l'alerte
  passe en « REVIEW » (validation humaine), elle n'est jamais supprimée par le LLM.

Backends : `rules` (défaut, aucun modèle), `ollama` (HTTP local). Si LlamaIndex
est installé, le contexte de code est récupéré via un index vectoriel du dépôt ;
sinon une fenêtre de lignes autour de l'alerte est utilisée."""
from __future__ import annotations

import json
import urllib.request
from typing import Callable, Optional

from .context import CodeIndex
from .models import Finding, validate_advice

PROMPT = """Tu es analyste AppSec. Évalue l'alerte ci-dessous.
Réponds UNIQUEMENT avec un objet JSON :
{{"verdict": "TP"|"FP", "justification": str, "confidence": float 0-1,
  "priority_adjustment": int -2..2, "fix": str}}

Outil(s): {tools} | Règle: {rule} | {cwe}
Message: {message}
Emplacement: {location}
Contexte de code:
```python
{context}
```
"""


class ContextProvider:
    def __init__(self, index: CodeIndex, use_llamaindex: bool = True, embed_model: str = "nomic-embed-text"):
        self.index, self._retriever = index, None
        if use_llamaindex:
            try:  # pragma: no cover - dépendance optionnelle
                from llama_index.core import Document, Settings, VectorStoreIndex
                from llama_index.embeddings.ollama import OllamaEmbedding
                Settings.embed_model = OllamaEmbedding(model_name=embed_model)
                docs = [Document(text=fc.source, metadata={"file": rel}) for rel, fc in index.files.items()]
                self._retriever = VectorStoreIndex.from_documents(docs).as_retriever(similarity_top_k=2)
            except Exception:
                self._retriever = None

    @property
    def mode(self) -> str:
        return "llamaindex" if self._retriever else "window"

    def get(self, f: Finding) -> str:
        fc = self.index.get(f.file)
        local = fc.window(f.line) if fc and f.line else ""
        if self._retriever is None:
            return local or "(dépendance tierce, pas de code local)"
        nodes = self._retriever.retrieve(f"{f.message} {f.snippet or ''} {f.package or ''}")  # pragma: no cover
        extra = "\n# ---\n".join(n.get_content()[:1500] for n in nodes)                      # pragma: no cover
        return f"{local}\n# --- extraits liés (LlamaIndex) ---\n{extra}"                        # pragma: no cover


def ollama_client(model: str, url: str = "http://localhost:11434", timeout: int = 120) -> Callable[[str], str]:
    def call(prompt: str) -> str:  # pragma: no cover - nécessite un serveur Ollama
        body = json.dumps({"model": model, "prompt": prompt, "format": "json", "stream": False,
                           "options": {"temperature": 0}}).encode()
        req = urllib.request.Request(f"{url}/api/generate", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["response"]
    return call


class LLMAdvisor:
    def __init__(self, client: Callable[[str], str], name: str, context: ContextProvider):
        self.client, self.name, self.context = client, name, context
        self.stats = {"calls": 0, "valid": 0, "invalid": 0, "disagree": 0}

    def advise(self, f: Finding) -> Optional[dict]:
        prompt = PROMPT.format(tools=",".join(f.tools), rule=f.rule_id, cwe=f.cwe or "", message=f.message,
                               location=f.location, context=self.context.get(f))
        self.stats["calls"] += 1
        try:
            advice = validate_advice(json.loads(self.client(prompt)))
        except Exception:
            self.stats["invalid"] += 1
            return None
        self.stats["valid"] += 1
        return advice

    def apply(self, f: Finding) -> None:
        advice = self.advise(f)
        if advice is None:
            return                          # sortie invalide -> verdict déterministe conservé
        f.llm_advice, f.advisor = advice, f"rules+{self.name}"
        if advice["fix"]:
            f.remediation = f"{f.remediation} | Suggestion LLM : {advice['fix']}"
        if advice["verdict"] != f.verdict:
            self.stats["disagree"] += 1
            f.justification += f" | LLM ({advice['confidence']:.2f}) : {advice['verdict']} — {advice['justification']}"
            f.verdict = "REVIEW"
