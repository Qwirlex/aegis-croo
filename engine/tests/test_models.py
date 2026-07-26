from aegis_engine.models import Finding, Report, Target


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


def test_finding_v2_fields_default_so_old_callers_keep_working():
    f = Finding(id="F-1", severity="high", title="t", location="A.sol:1",
                source="llm", description="d", recommendation="r")
    assert f.provenance == []
    assert f.also_flagged == []
    assert f.refutation is None
    assert f.category == "unspecified"
    assert f.code_excerpt is None
    assert f.confidence == "medium"


def test_report_v2_carries_tier_verdict_powers_and_coverage():
    from aegis_engine.models import Coverage, PrivilegedPower

    r = Report.build_v2(
        tier="audit",
        target_address="0xabc",
        chain="base",
        chain_id=8453,
        contract_name="Vault",
        compiler="0.8.25",
        source_verified=True,
        verdict="high_risk",
        risk_score=40,
        confidence="high",
        summary="s",
        findings=[Finding(id="F-1", severity="high", title="t", location="A.sol:1",
                          source="lens:access_control", description="d", recommendation="r")],
        privileged_powers=[PrivilegedPower(function="mint", file="A.sol", line=3,
                                           visibility="external", modifiers=["onlyOwner"],
                                           capability="mint new supply", can_move_funds=True)],
        coverage=Coverage(lenses_run=["access_control"], lenses_skipped=[],
                          detectors_run=12, not_checked=["formal invariants"]),
        duration_ms=1234,
    )
    assert r.tier == "audit"
    assert r.version == "2.0"
    assert r.verdict == "high_risk"
    assert r.target.chain_id == 8453
    assert r.target.network == "base"          # legacy field kept for the CROO consumer
    assert r.privileged_powers[0].can_move_funds is True
    assert r.coverage.detectors_run == 12
    assert r.duration_ms == 1234
    assert r.status == "ok"
    assert r.report_hash == ""                 # integrity is stamped separately


def test_the_legacy_builder_still_says_version_one():
    r = Report.build(target_address=None, network="base", compiler="0.8.25",
                     summary="s", findings=[], confidence="low")
    assert r.version == "1.0"
    assert r.tier == "audit"
    assert r.confidence == "low"


def test_two_reports_do_not_share_one_coverage_object():
    a = Report(target=Target(address=None, network="base", compiler="x"))
    b = Report(target=Target(address=None, network="base", compiler="x"))
    a.coverage.lenses_run.append("access_control")
    assert b.coverage.lenses_run == []
