from aegis_engine.audit import audit
from aegis_engine.llm import ReasonResult
from aegis_engine.models import Finding


def fake_slither(source, solc_version="0.8.25"):
    return [{"check": "reentrancy-eth", "impact": "High", "description": "d", "line": 8}]


def fake_reason(*, source, slither, llm=None):
    return ReasonResult(
        summary="s",
        findings=[
            Finding(
                id="F-1",
                severity="critical",
                title="reentrancy",
                location="Target.sol:8",
                source="slither:reentrancy-eth",
                description="d",
                recommendation="use checks-effects",
            )
        ],
        confidence="high",
    )


def test_audit_ok_path():
    r = audit(
        source="contract V{}",
        address=None,
        slither_fn=fake_slither,
        reason_fn=fake_reason,
    )
    assert r.status == "ok"
    assert r.risk_score == 100
    assert r.findings[0].title == "reentrancy"


def test_audit_cannot_analyze_on_compile_error():
    def boom(source, solc_version="0.8.25"):
        raise RuntimeError("no compile")

    r = audit(
        source="garbage", address=None, slither_fn=boom, reason_fn=fake_reason
    )
    assert r.status == "cannot_analyze"
    assert "no compile" in (r.reason or "")
