from aegis_engine.models import Finding, Report


def test_report_risk_score_from_severities():
    findings = [
        Finding(id="F-1", severity="critical", title="reentrancy",
                location="V.sol:20", source="slither:reentrancy-eth",
                description="x", recommendation="y"),
        Finding(id="F-2", severity="low", title="naming",
                location="V.sol:5", source="llm", description="x", recommendation="y"),
    ]
    r = Report.build(target_address=None, network="base", compiler="0.8.25",
                     summary="s", findings=findings, confidence="high")
    assert r.status == "ok"
    assert r.risk_score == 100  # any critical caps at 100
    assert len(r.findings) == 2
