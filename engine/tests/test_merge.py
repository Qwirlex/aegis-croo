from aegis_engine.merge import merge_findings, slither_as_findings


def test_two_lenses_on_the_same_line_become_one_finding_with_both_sources():
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:10",
         "category": "access_control", "provenance": ["lens:access_control"], "description": "d"}
    b = {"severity": "high", "title": "Unbounded mint", "location": "A.sol:10",
         "category": "erc20_rug", "provenance": ["lens:erc20_rug"], "description": "d2"}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert out[0]["severity"] == "high"          # highest severity wins
    assert out[0]["title"] == "Unbounded mint"    # the winning finding keeps its text
    assert sorted(out[0]["provenance"]) == ["lens:access_control", "lens:erc20_rug"]


def test_different_lines_stay_separate_and_are_sorted_by_severity():
    out = merge_findings([
        {"severity": "low", "title": "x", "location": "A.sol:2", "provenance": ["lens:a"]},
        {"severity": "critical", "title": "y", "location": "A.sol:3", "provenance": ["lens:b"]},
    ])
    assert [f["severity"] for f in out] == ["critical", "low"]
    assert [f["id"] for f in out] == ["F-1", "F-2"]


def test_slither_hits_become_findings_with_detector_provenance():
    out = slither_as_findings([
        {"check": "reentrancy-eth", "impact": "High", "description": "bad", "line": 12, "file": "A.sol"},
    ])
    assert out[0]["location"] == "A.sol:12"
    assert out[0]["provenance"] == ["slither:reentrancy-eth"]
    assert out[0]["severity"] == "high"
    assert out[0]["category"] == "static_analysis"


def test_slither_informational_maps_to_info():
    out = slither_as_findings([{"check": "naming", "impact": "Informational", "line": 1, "file": "A.sol"}])
    assert out[0]["severity"] == "info"
