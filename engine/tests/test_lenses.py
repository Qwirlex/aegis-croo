import json
import threading

from aegis_engine.lenses import LENSES, lenses_for, build_lens_prompt, run_lenses


def test_six_lenses_exist_and_rug_is_last():
    assert [l.name for l in LENSES] == [
        "access_control", "reentrancy_state", "arithmetic_logic",
        "economics_oracle", "upgrade_proxy", "erc20_rug",
    ]


def test_rug_lens_only_runs_for_a_token():
    token = lenses_for({"is_erc20": True, "is_upgradeable": False})
    vault = lenses_for({"is_erc20": False, "is_upgradeable": False})
    assert "erc20_rug" in [l.name for l in token]
    assert "erc20_rug" not in [l.name for l in vault]
    assert len(vault) == 5


def test_prompt_carries_source_slither_and_the_style_rules():
    lens = LENSES[0]
    p = build_lens_prompt(lens, source="contract A {}", inventory={"functions": []},
                          slither=[{"check": "reentrancy-eth", "line": 7}])
    assert "contract A {}" in p
    assert "reentrancy-eth" in p
    assert lens.focus in p
    assert "em dash" in p
    assert "STRICT JSON" in p


def test_run_lenses_collects_findings_and_tags_provenance():
    calls = []

    class FakeLlm:
        def generate(self, prompt):
            calls.append(prompt)
            return json.dumps({"findings": [{
                "severity": "high", "title": "Owner can drain", "location": "A.sol:12",
                "category": "access_control", "description": "d", "impact": "i",
                "exploit_scenario": "s", "recommendation": "r",
            }]})

    out = run_lenses(
        lenses=LENSES[:2], source="contract A {}", inventory={"functions": []},
        slither=[], llm=FakeLlm(),
    )
    assert len(calls) == 2
    assert len(out.findings) == 2
    assert out.findings[0]["provenance"] == ["lens:access_control"]
    assert out.lenses_run == ["access_control", "reentrancy_state"]
    assert out.lenses_skipped == []


def test_a_finding_without_a_line_is_dropped():
    class FakeLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "high", "title": "vague", "location": "", "description": "d"},
                {"severity": "low", "title": "real", "location": "A.sol:3", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=FakeLlm())
    assert [f["title"] for f in out.findings] == ["real"]


def test_a_failing_lens_is_recorded_and_does_not_kill_the_run():
    class FlakyLlm:
        def __init__(self):
            self.n = 0

        def generate(self, _):
            self.n += 1
            if self.n == 1:
                raise RuntimeError("model down")
            return json.dumps({"findings": []})

    out = run_lenses(lenses=LENSES[:2], source="s", inventory={}, slither=[], llm=FlakyLlm())
    assert len(out.lenses_skipped) == 1
    assert len(out.lenses_run) == 1


def test_an_invalid_severity_is_clamped_to_info_not_left_raw():
    class BadSeverityLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "catastrophic", "title": "t", "location": "A.sol:5", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=BadSeverityLlm())
    assert out.findings[0]["severity"] == "info"


def test_a_capitalized_severity_still_counts_as_the_real_severity():
    class CapitalizedSeverityLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "Critical", "title": "t", "location": "A.sol:5", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=CapitalizedSeverityLlm())
    assert out.findings[0]["severity"] == "critical"


def test_an_all_caps_severity_still_counts_as_the_real_severity():
    class AllCapsSeverityLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "HIGH", "title": "t", "location": "A.sol:5", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=AllCapsSeverityLlm())
    assert out.findings[0]["severity"] == "high"


def test_a_location_with_a_colon_but_no_line_number_is_dropped():
    class NoDigitLocationLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "high", "title": "empty tail", "location": "A.sol:", "description": "d"},
                {"severity": "high", "title": "not a number", "location": "A.sol:abc", "description": "d"},
                {"severity": "low", "title": "real", "location": "A.sol:3", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=NoDigitLocationLlm())
    assert [f["title"] for f in out.findings] == ["real"]


def test_a_lens_returning_a_json_list_instead_of_an_object_is_recorded_not_fatal():
    class ListLlm:
        def generate(self, _):
            return json.dumps([{"severity": "high", "location": "A.sol:1"}])

    out = run_lenses(lenses=LENSES[:2], source="s", inventory={}, slither=[], llm=ListLlm())
    assert len(out.lenses_skipped) == 2
    assert out.lenses_run == []
    assert out.findings == []


def test_run_lenses_with_an_empty_lens_list_does_not_crash_on_max_workers():
    class UnusedLlm:
        def generate(self, _):
            raise AssertionError("should not be called when there are no lenses")

    out = run_lenses(lenses=[], source="s", inventory={}, slither=[], llm=UnusedLlm())
    assert out.findings == []
    assert out.lenses_run == []
    assert out.lenses_skipped == []


def test_run_lenses_accepts_a_generator_without_silently_returning_an_empty_result():
    def gen():
        yield LENSES[0]

    class FakeLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "high", "title": "t", "location": "A.sol:1", "description": "d"},
            ]})

    out = run_lenses(lenses=gen(), source="s", inventory={}, slither=[], llm=FakeLlm())
    assert out.lenses_run == ["access_control"]
    assert len(out.findings) == 1


def test_a_lens_that_hangs_past_the_budget_is_skipped_and_does_not_block_the_fast_one():
    release = threading.Event()

    class SlowThenFastLlm:
        def generate(self, prompt):
            if "LENS: reentrancy_state" in prompt:
                # Never returns on its own within the test, only once the
                # test releases it, well after the tiny budget below.
                release.wait(timeout=5)
                return json.dumps({"findings": []})
            return json.dumps({"findings": [{
                "severity": "high", "title": "fast finding", "location": "A.sol:1",
                "description": "d",
            }]})

    try:
        out = run_lenses(
            lenses=LENSES[:2], source="s", inventory={}, slither=[],
            llm=SlowThenFastLlm(), budget_seconds=0.2,
        )
    finally:
        release.set()  # let the blocked worker thread finish, nothing lingers

    assert out.lenses_run == ["access_control"]
    assert [f["title"] for f in out.findings] == ["fast finding"]
    assert len(out.lenses_skipped) == 1
    assert out.lenses_skipped[0]["lens"] == "reentrancy_state"
    assert "time" in out.lenses_skipped[0]["reason"].lower()


def test_a_lens_returning_only_ungrounded_findings_is_run_with_a_nonzero_dropped_count():
    class AllUngroundedLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "high", "title": "vague one", "location": "", "description": "d"},
                {"severity": "high", "title": "vague two", "location": "A.sol:", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=AllUngroundedLlm())
    assert out.lenses_run == ["access_control"]
    assert out.findings == []
    assert out.dropped == [{"lens": "access_control", "count": 2}]


def test_a_lens_with_no_dropped_findings_does_not_appear_in_dropped():
    class CleanLlm:
        def generate(self, _):
            return json.dumps({"findings": [
                {"severity": "high", "title": "real", "location": "A.sol:1", "description": "d"},
            ]})

    out = run_lenses(lenses=LENSES[:1], source="s", inventory={}, slither=[], llm=CleanLlm())
    assert out.dropped == []
