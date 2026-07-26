import json

from aegis_engine.refute import build_refute_prompt, refute_findings

FINDING = {"id": "F-1", "severity": "high", "title": "Owner can drain", "location": "A.sol:10",
           "category": "access_control", "description": "d", "impact": "i",
           "provenance": ["lens:access_control"]}


def test_prompt_tells_the_model_to_refute_and_to_default_to_refuted():
    p = build_refute_prompt(FINDING, excerpt={"file": "A.sol", "start_line": 8, "focus_line": 10,
                                              "lines": ["a", "b", "c"]})
    assert "refute" in p.lower()
    assert "uncertain" in p.lower()
    assert "Owner can drain" in p


def test_prompt_numbers_the_code_lines_from_the_excerpt_start():
    p = build_refute_prompt(FINDING, excerpt={"file": "A.sol", "start_line": 8, "focus_line": 10,
                                              "lines": ["first", "second"]})
    assert "8: first" in p
    assert "9: second" in p


def test_prompt_says_plainly_when_no_code_was_available():
    p = build_refute_prompt(FINDING, excerpt=None)
    assert "not available" in p


def test_a_refuted_finding_is_dropped():
    class Llm:
        def generate(self, _):
            return json.dumps({"verdict": "refuted", "reason": "the modifier does gate it"})

    kept = refute_findings([FINDING], files={"A.sol": "x\n" * 20}, llm=Llm())
    assert kept == []


def test_a_kept_finding_carries_the_verdict():
    class Llm:
        def generate(self, _):
            return json.dumps({"verdict": "stands", "reason": "no gate anywhere"})

    kept = refute_findings([FINDING], files={"A.sol": "x\n" * 20}, llm=Llm())
    assert kept[0]["refutation"] == {"verdict": "kept", "reason": "no gate anywhere"}
    assert kept[0]["severity"] == "high"


def test_a_partly_refuted_finding_is_demoted_to_info_not_deleted():
    class Llm:
        def generate(self, _):
            return json.dumps({"verdict": "weakened", "reason": "only reachable by the owner"})

    kept = refute_findings([FINDING], files={"A.sol": "x\n" * 20}, llm=Llm())
    assert kept[0]["severity"] == "info"
    assert kept[0]["refutation"]["verdict"] == "demoted"


def test_a_verdict_is_read_whatever_its_case():
    class Llm:
        def generate(self, _):
            return json.dumps({"verdict": "  STANDS ", "reason": "r"})

    kept = refute_findings([FINDING], files={"A.sol": "x"}, llm=Llm())
    assert kept[0]["refutation"]["verdict"] == "kept"


def test_an_unparsable_verdict_is_treated_as_refuted():
    class Llm:
        def generate(self, _):
            return "the model rambled"

    assert refute_findings([FINDING], files={"A.sol": "x"}, llm=Llm()) == []


def test_an_unknown_verdict_word_is_treated_as_refuted():
    class Llm:
        def generate(self, _):
            return json.dumps({"verdict": "maybe", "reason": "r"})

    assert refute_findings([FINDING], files={"A.sol": "x"}, llm=Llm()) == []


def test_info_findings_skip_the_pass_and_are_marked_not_checked():
    class Llm:
        def generate(self, _):
            raise AssertionError("must not be called for info")

    out = refute_findings([{**FINDING, "severity": "info"}], files={"A.sol": "x"}, llm=Llm())
    assert out[0]["refutation"]["verdict"] == "not_checked"


def test_every_finding_is_challenged_and_the_original_order_is_kept():
    seen = []

    class Llm:
        def generate(self, prompt):
            title = prompt.split("title: ")[1].split("\n")[0]
            seen.append(title)
            return json.dumps({"verdict": "stands", "reason": "r"})

    findings = [{**FINDING, "title": f"F{i}", "location": f"A.sol:{i}"} for i in range(1, 6)]
    kept = refute_findings(findings, files={"A.sol": "x\n" * 20}, llm=Llm())
    assert sorted(seen) == ["F1", "F2", "F3", "F4", "F5"]
    assert [f["title"] for f in kept] == ["F1", "F2", "F3", "F4", "F5"]


def test_a_challenge_that_hangs_past_the_budget_drops_that_finding_only():
    import threading

    release = threading.Event()

    class Llm:
        def generate(self, prompt):
            if "slow" in prompt:
                release.wait(5)
                return json.dumps({"verdict": "stands", "reason": "late"})
            return json.dumps({"verdict": "stands", "reason": "r"})

    findings = [{**FINDING, "title": "slow", "location": "A.sol:1"},
                {**FINDING, "title": "fast", "location": "A.sol:2"}]
    try:
        kept = refute_findings(findings, files={"A.sol": "x\n" * 20}, llm=Llm(),
                               budget_seconds=0.2)
        titles = [f["title"] for f in kept]
        assert "fast" in titles
        assert "slow" not in titles
    finally:
        release.set()
