from __future__ import annotations
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
Verdict = Literal["critical_risk", "high_risk", "caution", "looks_ok"]

# Legacy weights, used only by the original single pass build below, which the
# CROO provider still calls. The paid audit scores through scoring.py instead,
# where the weights are capped per band so quantity cannot fake severity.
_WEIGHT = {"critical": 100, "high": 40, "medium": 15, "low": 5, "info": 0}


class CodeExcerpt(BaseModel):
    """The few lines of source around a finding, so a report can show the code."""
    file: str
    start_line: int
    focus_line: int
    lines: list[str]


class Refutation(BaseModel):
    """What the adversarial pass decided about a finding.

    kept means a skeptic tried to argue it away and could not. demoted means
    something real is there but weaker than claimed. not_checked means the
    finding was info level and not worth a challenge.
    """
    verdict: Literal["kept", "demoted", "not_checked"]
    reason: str = ""


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    location: str
    source: str           # "slither:<detector>" or "lens:<name>"
    description: str
    recommendation: str
    category: str = "unspecified"
    impact: str = ""
    exploit_scenario: str = ""
    provenance: list[str] = []
    # The other angle, when a second lens flagged the same line for a different
    # reason. Kept short on purpose, the winning text stays the finding.
    also_flagged: list[dict] = []
    refutation: Refutation | None = None
    code_excerpt: CodeExcerpt | None = None
    confidence: Confidence = "medium"


class PrivilegedPower(BaseModel):
    """One thing a privileged caller can do, in plain words a buyer can read."""
    function: str
    file: str
    line: int
    visibility: str
    modifiers: list[str] = []
    capability: str
    can_move_funds: bool = False
    confidence: Confidence = "medium"


class Coverage(BaseModel):
    """What actually ran, and what was not looked at.

    Naming the limits is what makes the rest of the report credible, so this
    ships with every audit rather than only when something went wrong.
    """
    lenses_run: list[str] = []
    lenses_skipped: list[dict] = []
    dropped: list[dict] = []
    detectors_run: int = 0
    not_checked: list[str] = []


class Target(BaseModel):
    address: str | None
    network: str
    compiler: str
    chain: str = "base"
    chain_id: int = 8453
    contract_name: str = "unknown"
    source_verified: bool = False


class Report(BaseModel):
    agent: str = "Aegis"
    version: str = "2.0"
    tier: Literal["scan", "audit"] = "audit"
    target: Target
    status: Literal["ok", "cannot_analyze", "degraded"] = "ok"
    reason: str | None = None
    verdict: Verdict = "looks_ok"
    risk_score: int = 0
    summary: str = ""
    findings: list[Finding] = []
    privileged_powers: list[PrivilegedPower] = []
    coverage: Coverage = Coverage()
    confidence: Confidence = "medium"
    generated_at: str = ""
    duration_ms: int = 0
    report_hash: str = ""
    report_signature: str = ""
    signer: str = ""

    @classmethod
    def build(cls, *, target_address, network, compiler, summary, findings,
              confidence="high") -> "Report":
        """The original single pass report, still used by the CROO provider."""
        score = min(100, sum(_WEIGHT[f.severity] for f in findings))
        return cls(
            version="1.0",
            target=Target(address=target_address, network=network, compiler=compiler,
                          chain=network, source_verified=target_address is not None),
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

    @classmethod
    def build_v2(cls, *, tier, target_address, chain, chain_id, contract_name, compiler,
                 source_verified, verdict, risk_score, confidence, summary, findings,
                 privileged_powers, coverage, duration_ms) -> "Report":
        """The paid audit report. Scoring and verdict are decided in scoring.py."""
        return cls(
            tier=tier,
            target=Target(address=target_address, network=chain, compiler=compiler,
                          chain=chain, chain_id=chain_id, contract_name=contract_name,
                          source_verified=source_verified),
            status="ok", verdict=verdict, risk_score=risk_score, confidence=confidence,
            summary=summary, findings=findings, privileged_powers=privileged_powers,
            coverage=coverage, duration_ms=duration_ms,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
