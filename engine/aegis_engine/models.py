from __future__ import annotations
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "info"]
_WEIGHT = {"critical": 100, "high": 40, "medium": 15, "low": 5, "info": 0}


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    location: str
    source: str           # "slither:<detector>" or "llm"
    description: str
    recommendation: str


class Target(BaseModel):
    address: str | None
    network: str
    compiler: str


class Report(BaseModel):
    agent: str = "Aegis"
    version: str = "1.0"
    target: Target
    status: Literal["ok", "cannot_analyze"] = "ok"
    reason: str | None = None
    risk_score: int = 0
    summary: str = ""
    findings: list[Finding] = []
    confidence: Literal["high", "low"] = "high"
    generated_at: str = ""

    @classmethod
    def build(cls, *, target_address, network, compiler, summary, findings,
              confidence="high") -> "Report":
        score = min(100, sum(_WEIGHT[f.severity] for f in findings))
        return cls(
            target=Target(address=target_address, network=network, compiler=compiler),
            status="ok", risk_score=score, summary=summary, findings=findings,
            confidence=confidence,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def cannot_analyze(cls, *, target_address, network, reason) -> "Report":
        return cls(
            target=Target(address=target_address, network=network, compiler="unknown"),
            status="cannot_analyze", reason=reason,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
