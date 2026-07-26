import json

from aegis_engine.deep_audit import (
    MAX_PROMPT_SOURCE_CHARS,
    prepare_target,
    run_deep_audit,
    run_quick_scan,
)
from aegis_engine.source import ResolvedSource

SOURCE = """
pragma solidity ^0.8.20;
contract Tok {
    function totalSupply() public view returns (uint256) { return 1; }
    function transfer(address to, uint256 a) public returns (bool) { return true; }
    function approve(address s, uint256 a) public returns (bool) { return true; }
    function mint(address to, uint256 a) external onlyOwner { }
}
"""

SLITHER_HITS = [{"check": "arbitrary-send", "impact": "High", "description": "d", "line": 7,
                 "file": "Target.sol"}]

TEST_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def _prepared(source=SOURCE, hits=None, address=None, chain="base"):
    return prepare_target(
        source=source, address=address, chain=chain,
        resolve=lambda **kw: ResolvedSource(source=source, address=address, compiler="0.8.20",
                                            chain=chain, contract_name="Tok",
                                            verified=address is not None),
        slither=lambda *a, **k: SLITHER_HITS if hits is None else hits,
    )


class LensThenRefuteLlm:
    """Answers a lens prompt with findings and a refutation prompt with a verdict."""

    def __init__(self, findings, refute="stands"):
        self._findings = findings
        self._refute = refute

    def generate(self, prompt):
        if "REFUTE" in prompt:
            title = prompt.split("title: ")[1].split("\n")[0]
            verdict = "refuted" if title == "noise" else self._refute
            return json.dumps({"verdict": verdict, "reason": "r"})
        if "LENS: access_control" in prompt:
            return json.dumps({"findings": self._findings})
        if "LENS:" in prompt:
            return json.dumps({"findings": []})
        return "plain summary"


def test_prepare_returns_the_slither_hits_inventory_and_files():
    p = _prepared()
    assert p.slither == SLITHER_HITS
    assert p.inventory["is_erc20"] is True
    assert "Target.sol" in p.files
    assert p.chain == "base"
    assert p.chain_id == 8453
    assert p.truncated_chars == 0


def test_prepare_caps_a_huge_source_and_says_by_how_much():
    big = "// pad\n" * (MAX_PROMPT_SOURCE_CHARS // 4)
    p = _prepared(source=big)
    assert len(p.flat) < len(big)
    assert p.truncated_chars > 0
    assert p.flat.startswith("// pad")
    assert "truncated" in p.flat.lower()


def test_prepare_rejects_an_unsupported_chain_before_any_work():
    try:
        prepare_target(source=SOURCE, address="0xabc", chain="solana",
                       resolve=lambda **kw: (_ for _ in ()).throw(AssertionError("no resolve")),
                       slither=lambda *a, **k: [])
        raise AssertionError("should have raised")
    except ValueError as e:
        assert "chain not supported" in str(e)


def test_deep_audit_produces_a_signed_report_with_kept_findings_only():
    llm = LensThenRefuteLlm([
        {"severity": "high", "title": "Owner can mint freely", "location": "Target.sol:7",
         "description": "d", "impact": "i", "exploit_scenario": "s", "recommendation": "r"},
        {"severity": "medium", "title": "noise", "location": "Target.sol:4", "description": "d"},
    ])
    r = run_deep_audit(_prepared(), llm=llm, summarize=lambda **kw: "plain summary",
                       signing_key=TEST_KEY)
    titles = [f.title for f in r.findings]
    assert "Owner can mint freely" in titles
    assert "noise" not in titles
    assert r.tier == "audit"
    assert r.verdict in ("high_risk", "critical_risk")
    assert r.report_hash.startswith("0x")
    assert r.signer.startswith("0x")
    assert r.coverage.lenses_run
    assert any(p.function == "mint" for p in r.privileged_powers)


def test_deep_audit_runs_the_rug_lens_for_a_token_and_not_for_a_vault():
    seen = []

    class Llm:
        def generate(self, prompt):
            if "REFUTE" in prompt:
                return json.dumps({"verdict": "refuted", "reason": "r"})
            if "LENS:" in prompt:
                seen.append(prompt.split("LENS: ")[1].split("\n")[0])
            return json.dumps({"findings": []})

    run_deep_audit(_prepared(), llm=Llm(), summarize=lambda **kw: "s", signing_key="")
    assert "erc20_rug" in seen

    seen.clear()
    vault = "contract V { function deposit() external payable { } }"
    run_deep_audit(_prepared(source=vault), llm=Llm(), summarize=lambda **kw: "s", signing_key="")
    assert "erc20_rug" not in seen


def test_deep_audit_attaches_a_code_excerpt_and_ids_the_findings():
    llm = LensThenRefuteLlm([{"severity": "high", "title": "t", "location": "Target.sol:7",
                              "description": "d"}])
    r = run_deep_audit(_prepared(), llm=llm, summarize=lambda **kw: "s", signing_key="")
    kept = next(f for f in r.findings if f.title == "t")
    assert kept.code_excerpt is not None
    assert kept.code_excerpt.focus_line == 7
    assert [f.id for f in r.findings] == [f"F-{i}" for i in range(1, len(r.findings) + 1)]


def test_a_report_with_no_findings_at_all_still_scores_and_reads_ok():
    class Llm:
        def generate(self, prompt):
            if "REFUTE" in prompt:
                return json.dumps({"verdict": "refuted", "reason": "r"})
            return json.dumps({"findings": []})

    r = run_deep_audit(_prepared(hits=[]), llm=Llm(), summarize=lambda **kw: "nothing found",
                       signing_key="")
    assert r.findings == []
    assert r.risk_score == 0
    assert r.verdict == "looks_ok"
    assert r.status == "ok"


def test_every_lens_failing_degrades_instead_of_crashing():
    class DeadLlm:
        def generate(self, _):
            raise RuntimeError("model down")

    r = run_deep_audit(_prepared(), llm=DeadLlm(), summarize=lambda **kw: "", signing_key="")
    assert r.status == "degraded"
    assert r.confidence == "low"
    assert r.findings  # the static analysis hits still ship
    assert r.coverage.lenses_skipped


def test_coverage_names_what_was_not_checked_and_records_truncation():
    big = "// pad\n" * (MAX_PROMPT_SOURCE_CHARS // 4)
    llm = LensThenRefuteLlm([])
    r = run_deep_audit(_prepared(source=big, hits=[]), llm=llm,
                       summarize=lambda **kw: "s", signing_key="")
    assert any("truncat" in n.lower() for n in r.coverage.not_checked)
    assert any("run" in n.lower() or "executed" in n.lower() for n in r.coverage.not_checked)


def test_quick_scan_is_slither_plus_one_pass_and_carries_no_exploit_text():
    class Llm:
        def generate(self, _):
            return json.dumps({"summary": "quick take", "findings": [
                {"severity": "high", "title": "t", "location": "Target.sol:7", "description": "d"}]})

    r = run_quick_scan(_prepared(), llm=Llm(), signing_key="")
    assert r.tier == "scan"
    assert r.summary == "quick take"
    assert len(r.findings) <= 5
    assert all(f.exploit_scenario == "" for f in r.findings)
    assert r.coverage.lenses_run == ["triage"]
    assert any("refutation" in n.lower() for n in r.coverage.not_checked)


def test_quick_scan_keeps_at_most_five_findings():
    class Llm:
        def generate(self, _):
            return json.dumps({"summary": "s", "findings": [
                {"severity": "high", "title": f"t{i}", "location": f"Target.sol:{i}",
                 "description": "d"} for i in range(1, 9)]})

    r = run_quick_scan(_prepared(), llm=Llm(), signing_key="")
    assert len(r.findings) == 5


def test_quick_scan_falls_back_to_static_analysis_when_the_model_fails():
    class DeadLlm:
        def generate(self, _):
            raise RuntimeError("model down")

    r = run_quick_scan(_prepared(), llm=DeadLlm(), signing_key="")
    assert r.tier == "scan"
    assert r.confidence == "low"
    assert r.findings  # the slither hit still ships
    assert r.coverage.lenses_run == []
