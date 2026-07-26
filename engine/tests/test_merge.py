from aegis_engine.merge import assign_ids, merge_findings, slither_as_findings


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
    # Deviation from the plan text: ids are no longer assigned inside
    # merge_findings, see assign_ids and the Important 3 fix note in the
    # task report. merge_findings's own output carries no "id" at all.
    assert all("id" not in f for f in out)
    assign_ids(out)
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


def test_the_losing_variant_is_kept_as_a_short_also_flagged_entry():
    # Two lenses on one line often explain different things, one the access
    # control hole, the other the token specific consequence. The buyer paid
    # for both, so the discarded variant is not thrown away, only its
    # category and description travel forward, impact, exploit_scenario and
    # recommendation do not, so the merged finding stays readable.
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:10",
         "category": "access_control", "provenance": ["lens:access_control"],
         "description": "Owner role can call mint with no cap.",
         "impact": "should not appear", "exploit_scenario": "should not appear",
         "recommendation": "should not appear"}
    b = {"severity": "high", "title": "Unbounded mint", "location": "A.sol:10",
         "category": "erc20_rug", "provenance": ["lens:erc20_rug"],
         "description": "Minted supply has no ceiling."}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert out[0]["also_flagged"] == [
        {"category": "access_control", "description": "Owner role can call mint with no cap."},
    ]
    for entry in out[0]["also_flagged"]:
        assert set(entry) == {"category", "description"}


# --- Self review characterization tests ---
#
# These pin down behavior for edge cases beyond the plan's own test list.
# Tests marked KNOWN LIMITATION document a real, accepted gap this module
# does not fix. Every other test here confirms behavior that is correct and
# should not regress.


def test_same_basename_in_different_directories_no_longer_collapses():
    # VERIFIED CORRECT, not a known limitation: an earlier version of this
    # module keyed on basename alone and incorrectly collapsed this case. The
    # Critical fix keys on the full lowercased path and only folds two
    # findings when one path is an unambiguous suffix of the other, so two
    # genuinely different vendored files with the same name, and even the
    # same line number, now stay apart and neither is silently lost.
    a = {"severity": "high", "title": "Reentrancy in TokenA", "location": "contracts/tokens/Token.sol:12",
         "provenance": ["lens:reentrancy"]}
    b = {"severity": "high", "title": "Access control bug in TokenB", "location": "contracts/vendor/Token.sol:12",
         "provenance": ["lens:access_control"]}
    out = merge_findings([a, b])
    assert len(out) == 2
    assert {f["title"] for f in out} == {"Reentrancy in TokenA", "Access control bug in TokenB"}


def test_bare_and_prefixed_path_for_the_same_file_still_collapse():
    # VERIFIED CORRECT: the intended collapse this module is built to keep.
    # Two lenses describing the same real file, one with a bare filename and
    # one with a directory prefix, are still one finding.
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:12",
         "provenance": ["lens:a"]}
    b = {"severity": "medium", "title": "Owner can mint", "location": "src/A.sol:12",
         "provenance": ["lens:b"]}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert sorted(out[0]["provenance"]) == ["lens:a", "lens:b"]


def test_three_way_basename_ambiguity_leaves_all_entries_separate():
    # VERIFIED CORRECT: a verified multi file project can vendor the same
    # file name under two different directories. A third finding that only
    # reports the bare basename could plausibly belong to either, so this
    # module refuses to guess and keeps all three apart, mirroring
    # sources.py's own suffix matching rule. The bare finding is listed
    # first here on purpose, a naive "match against groups formed so far"
    # implementation would let it bridge the two real files together if it
    # arrives before either of them; this proves the result does not depend
    # on arrival order.
    bare = {"severity": "high", "title": "Bug reported without a directory", "location": "Token.sol:12",
            "provenance": ["lens:c"]}
    a = {"severity": "high", "title": "Bug in tokens/Token.sol", "location": "contracts/tokens/Token.sol:12",
         "provenance": ["lens:a"]}
    b = {"severity": "high", "title": "Bug in vendor/Token.sol", "location": "contracts/vendor/Token.sol:12",
         "provenance": ["lens:b"]}
    out = merge_findings([bare, a, b])
    assert len(out) == 3


def test_location_without_a_colon_does_not_crash_and_groups_by_raw_text():
    # A location with no colon at all puts the whole string in the line slot
    # and leaves the path empty. That does not crash and does not falsely
    # merge two distinct colonless findings, because they only match when
    # the raw text is identical. In the real pipeline this never happens:
    # lenses.py's grounding rule already drops any finding whose location
    # has no colon before merge_findings ever sees it, and
    # slither_as_findings always builds "file:line" itself.
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


def test_assign_ids_renumbers_across_repeated_merge_calls_known_limitation():
    # KNOWN LIMITATION, not fixed here: assign_ids recomputes F-1 upward
    # fresh every call, from whatever order the list is in at that moment.
    # Calling it again after merge_findings folds in a new finding can shift
    # every existing id, so a caller that merges twice in one audit, which
    # the orchestrator does, must not treat "F-1" as a persistent key across
    # calls, it is a display label recomputed at render time, not a
    # database style id.
    first_pass = merge_findings([
        {"severity": "high", "title": "Old finding", "location": "A.sol:5", "provenance": ["lens:a"]},
    ])
    assign_ids(first_pass)
    assert [f["id"] for f in first_pass] == ["F-1"]

    second_pass = merge_findings(first_pass + [
        {"severity": "critical", "title": "New finding", "location": "A.sol:9", "provenance": ["lens:b"]},
    ])
    assign_ids(second_pass)
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
    # never see findings shuffle. Two same severity findings at genuinely
    # different locations sort by location text, and that ordering does not
    # depend on the order findings were supplied in. This is not a claim
    # that every raw-text variant of "the same real line" is caught before
    # the sort runs in general, only that whatever this module actually
    # treats as the same place, exact matches, whitespace and leading zero
    # differences in the line, and unambiguous path suffix matches, is
    # guaranteed to fold together first. A formatting difference none of
    # those rules cover could still reach the sort as two separate entries.
    a = {"severity": "high", "title": "a", "location": "A.sol:20", "provenance": ["lens:a"]}
    b = {"severity": "high", "title": "b", "location": "A.sol:5", "provenance": ["lens:b"]}
    forward = merge_findings([a, b])
    backward = merge_findings([b, a])
    assert [f["location"] for f in forward] == [f["location"] for f in backward] == ["A.sol:20", "A.sol:5"]


def test_interior_whitespace_after_the_colon_still_merges():
    # Lens output is only stripped at its outer edges before it reaches
    # merge_findings, so "A.sol:12" and "A.sol: 12" are a plausible pair of
    # formatting variants two lenses could produce for the same real line.
    # Before this normalization, an interior space after the colon kept the
    # two from merging and a paid report would show the same defect twice.
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:12",
         "provenance": ["lens:access_control"]}
    b = {"severity": "high", "title": "Unbounded mint", "location": "A.sol: 12",
         "provenance": ["lens:erc20_rug"]}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert sorted(out[0]["provenance"]) == ["lens:access_control", "lens:erc20_rug"]


def test_location_with_trailing_whitespace_merges_with_its_clean_twin():
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:12",
         "provenance": ["lens:access_control"]}
    b = {"severity": "high", "title": "Unbounded mint", "location": "A.sol:12 ",
         "provenance": ["lens:erc20_rug"]}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert sorted(out[0]["provenance"]) == ["lens:access_control", "lens:erc20_rug"]


def test_leading_zeros_in_the_line_number_also_merge():
    # The fix normalizes the line part to an integer when it parses as one,
    # so "12" and "012" agree the same way two differently zero padded
    # reports of the same line should.
    a = {"severity": "medium", "title": "Owner can mint", "location": "A.sol:012",
         "provenance": ["lens:access_control"]}
    b = {"severity": "high", "title": "Unbounded mint", "location": "A.sol:12",
         "provenance": ["lens:erc20_rug"]}
    out = merge_findings([a, b])
    assert len(out) == 1
    assert sorted(out[0]["provenance"]) == ["lens:access_control", "lens:erc20_rug"]
