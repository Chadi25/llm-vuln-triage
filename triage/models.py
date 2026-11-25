"""Modèles de données. pydantic est utilisé s'il est installé (validation stricte
de la sortie du LLM), sinon un validateur minimal équivalent prend le relais."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional

VERDICTS = ("TP", "FP")


@dataclass
class Finding:
    kind: str                      # "sast" | "sca"
    rule_id: str                   # règle SAST ou identifiant CVE/GHSA
    message: str
    severity: str                  # sévérité déclarée par l'outil
    tools: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    fixed_version: Optional[str] = None
    cvss: Optional[float] = None
    rules: List[str] = field(default_factory=list)   # toutes les règles fusionnées
    raw_count: int = 1                               # nb d'alertes brutes fusionnées
    # --- triage ---
    verdict: str = "TP"            # TP | FP | REVIEW
    justification: str = ""
    exposed_http: bool = False
    tainted: bool = False
    reachability: Optional[str] = None   # SCA : direct | transitive | unused
    score: float = 0.0
    priority: str = "P4"
    remediation: str = ""
    patch: str = ""
    advisor: str = "rules"
    llm_advice: Optional[dict] = None

    @property
    def key(self) -> str:
        if self.kind == "sca":
            return f"{(self.package or '').lower()}:{self.rule_id}"
        return f"{self.file}:{self.line}:{self.cwe}"

    @property
    def location(self) -> str:
        if self.kind == "sca":
            return f"{self.package}=={self.version}"
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        d["location"] = self.location
        return d


# ---------------------------------------------------------------- avis LLM
try:  # pragma: no cover - dépend de l'environnement
    from pydantic import BaseModel, Field, ValidationError, field_validator

    class Advice(BaseModel):
        verdict: str = Field(description="TP ou FP")
        justification: str = Field(min_length=10, max_length=1200)
        confidence: float = Field(ge=0.0, le=1.0)
        priority_adjustment: int = Field(default=0, ge=-2, le=2)
        fix: str = Field(default="", max_length=2000)

        @field_validator("verdict")
        @classmethod
        def _v(cls, v: str) -> str:
            v = v.strip().upper()
            if v not in VERDICTS:
                raise ValueError("verdict doit être TP ou FP")
            return v

    def validate_advice(data: dict) -> dict:
        try:
            return Advice.model_validate(data).model_dump()
        except ValidationError as e:
            raise ValueError(str(e)) from e

    VALIDATOR = "pydantic"
except Exception:  # fallback sans pydantic
    def validate_advice(data: dict) -> dict:
        if not isinstance(data, dict):
            raise ValueError("avis LLM : objet JSON attendu")
        v = str(data.get("verdict", "")).strip().upper()
        if v not in VERDICTS:
            raise ValueError("verdict doit être TP ou FP")
        j = str(data.get("justification", ""))
        if not 10 <= len(j) <= 1200:
            raise ValueError("justification : 10 à 1200 caractères")
        c = float(data.get("confidence", -1))
        if not 0.0 <= c <= 1.0:
            raise ValueError("confidence hors [0,1]")
        adj = int(data.get("priority_adjustment", 0))
        if not -2 <= adj <= 2:
            raise ValueError("priority_adjustment hors [-2,2]")
        fix = str(data.get("fix", ""))[:2000]
        return {"verdict": v, "justification": j, "confidence": c,
                "priority_adjustment": adj, "fix": fix}

    VALIDATOR = "builtin"
