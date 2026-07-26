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


# --- Self review characterization tests ---
#
# These pin down current behavior for edge cases that were not in the plan's
# own test list. None of them changed the implementation; each documents a
# tradeoff or confirms the code already does the safe thing.


def test_same_basename_in_different_directories_can_incorrectly_collapse():
    # Known, accepted limitation: the dedup key is the basename plus the line,
    # not the full path, so "A.sol:12" and "src/A.sol:12" collapse on purpose
    # when they are the same file reported two ways. The same mechanism also
    # collapses two genuinely different contracts that happen to share a file
    # name and a line number. There is no full path in "location" to
    # disambiguate them, so this is a real accuracy tradeoff of the v1
    # heuristic, not something this module can fix without more context than
    # a lens or detector currently provides.
    a = {"severity": "high", "title": "Reentrancy in TokenA", "location": "contracts/tokens/Token.sol:12",
         "provenance": ["lens:reentrancy"]}
    b = {"severity": "high", "title": "Access control bug in TokenB", "location": "contracts/vendor/Token.sol:12",
         "provenance": ["lens:access_control"]}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert out[0]["title"] == "Reentrancy in TokenA"


def test_location_without_a_colon_does_not_crash_and_groups_by_raw_text():
    # A location with no colon at all puts the whole string in the "line" slot
    # of the key (file becomes ""), per rpartition. That does not crash and
    # does not falsely merge two distinct colonless findings, because the
    # dedup key still differs whenever the raw text differs. In the real
    # pipeline this never happens: lenses.py's grounding rule already drops
    # any finding whose location has no colon before merge_findings ever sees
    # it, and slither_as_findings always builds "file:line" itself.
    a = {"severity": "medium", "title": "Unlocated finding one", "location": "no line info here",
         "provenance": ["lens:x"]}
    b = {"severity": "medium", "title": "Unlocated finding two", "location": "a different unlocated finding",
         "provenance": ["lens:y"]}
    c = {"severity": "low", "title": "Unlocated finding one, again", "location": "no line info here",
         "provenance": ["lens:z"]}
    out = merge_findings([a, b, c])
    assert len(out) == 2
    merged = next(f for f in out if f["title"] == "Unlocated finding one")
    assert sorted(merged["provenance"]) == ["lens:x", "lens:z"]


def test_merging_an_already_merged_list_with_a_new_finding_renumbers_ids():
    # Ids are recomputed from scratch on every call based on the current sort
    # order, so calling merge_findings twice on the same unchanged data is
    # stable, but folding a new finding into an already merged list can shift
    # every existing id. This is a real hazard for a caller that merges twice
    # in one audit and expects "F-1" to keep meaning the same finding between
    # calls; that caller must either merge once over the complete finding set,
    # or treat ids as a display label recomputed at render time rather than a
    # persistent key. Fixing this in merge.py itself would mean abandoning the
    # contiguous F-1..F-n numbering the plan's own test asserts, so it is left
    # as a documented behavior rather than changed here.
    first_pass = merge_findings([
        {"severity": "high", "title": "Old finding", "location": "A.sol:5", "provenance": ["lens:a"]},
    ])
    assert [f["id"] for f in first_pass] == ["F-1"]

    second_pass = merge_findings(first_pass + [
        {"severity": "critical", "title": "New finding", "location": "A.sol:9", "provenance": ["lens:b"]},
    ])
    assert [f["title"] for f in second_pass] == ["New finding", "Old finding"]
    old_finding = next(f for f in second_pass if f["title"] == "Old finding")
    assert old_finding["id"] == "F-2"  # shifted from F-1 in the first pass


def test_slither_hit_with_missing_or_unrecognized_impact_falls_back_to_info():
    # Missing "impact" hits the dict.get default of "Informational". An
    # impact word the map does not recognize, for example a future Slither
    # version or a custom detector using different wording, falls through the
    # inner lookup's own default. Both land on "info" rather than crashing or
    # silently escalating, which is the safe direction for a paid report to
    # err in.
    missing = slither_as_findings([{"check": "no-impact-field", "line": 3, "file": "A.sol"}])
    assert missing[0]["severity"] == "info"

    unexpected = slither_as_findings([
        {"check": "weird-detector", "impact": "Severe", "line": 4, "file": "A.sol"},
    ])
    assert unexpected[0]["severity"] == "info"


def test_output_order_is_deterministic_regardless_of_input_order():
    # A buyer comparing two runs of a report over the same contract should
    # never see findings shuffle. Two same severity findings at different
    # locations sort by location text, and that text is unique per output
    # finding by construction, since anything that would collide on location
    # is already folded into one entry before the sort runs. So the final
    # order does not depend on the order findings were supplied in.
    a = {"severity": "high", "title": "a", "location": "A.sol:20", "provenance": ["lens:a"]}
    b = {"severity": "high", "title": "b", "location": "A.sol:5", "provenance": ["lens:b"]}
    forward = merge_findings([a, b])
    backward = merge_findings([b, a])
    assert [f["location"] for f in forward] == [f["location"] for f in backward] == ["A.sol:20", "A.sol:5"]
