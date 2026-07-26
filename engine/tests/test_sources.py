import json
from aegis_engine.sources import split_sources, excerpt_at


def test_plain_source_becomes_one_target_file():
    files = split_sources("contract A {}")
    assert files == {"Target.sol": "contract A {}"}


def test_double_wrapped_standard_json_is_split_by_path():
    blob = "{" + json.dumps({
        "language": "Solidity",
        "sources": {"src/A.sol": {"content": "contract A {}"},
                    "src/B.sol": {"content": "contract B {}"}},
    }) + "}"
    files = split_sources(blob)
    assert sorted(files) == ["src/A.sol", "src/B.sol"]
    assert files["src/B.sol"] == "contract B {}"


def test_legacy_multi_file_map_is_split_too():
    blob = json.dumps({"A.sol": {"content": "contract A {}"}})
    assert split_sources(blob) == {"A.sol": "contract A {}"}


def test_standard_json_with_an_empty_sources_map_falls_back_to_target():
    # a source map that parses but carries no entries must not return {}
    blob = "{" + json.dumps({"language": "Solidity", "sources": {}}) + "}"
    assert split_sources(blob) == {"Target.sol": blob}


def test_excerpt_centres_on_the_line_and_reports_the_window():
    files = {"A.sol": "\n".join(f"line{i}" for i in range(1, 21))}
    ex = excerpt_at(files, "A.sol:10", radius=2)
    assert ex["file"] == "A.sol"
    assert ex["start_line"] == 8
    assert ex["lines"] == ["line8", "line9", "line10", "line11", "line12"]
    assert ex["focus_line"] == 10


def test_excerpt_matches_a_file_by_basename_when_slither_shortens_the_path():
    files = {"src/deep/A.sol": "a\nb\nc"}
    assert excerpt_at(files, "A.sol:2")["file"] == "src/deep/A.sol"


def test_excerpt_refuses_to_guess_between_two_files_sharing_a_basename():
    # vendoring IERC20.sol/SafeMath.sol under two directories is normal;
    # a bare basename must not silently pick one of them
    files = {"src/a/IERC20.sol": "a\nb", "src/b/IERC20.sol": "x\ny"}
    assert excerpt_at(files, "IERC20.sol:1") is None


def test_excerpt_uses_a_suffix_match_to_disambiguate_two_same_basename_files():
    # when the location still carries a directory, the suffix match picks
    # the one file it actually names, not just any file with that basename
    files = {"src/a/IERC20.sol": "a\nb", "src/b/IERC20.sol": "x\ny"}
    ex = excerpt_at(files, "a/IERC20.sol:1")
    assert ex["file"] == "src/a/IERC20.sol"
    assert ex["lines"][0] == "a"


def test_excerpt_returns_none_when_the_location_cannot_be_placed():
    assert excerpt_at({"A.sol": "a"}, "nope") is None
    assert excerpt_at({"A.sol": "a"}, "B.sol:1") is None


def test_excerpt_returns_none_for_a_non_integer_line_part():
    assert excerpt_at({"A.sol": "a"}, "A.sol:abc") is None


def test_excerpt_returns_none_when_the_location_has_no_file_part():
    # a bare ":LINE" location names no file; must not match anything by accident
    assert excerpt_at({"A.sol": "a"}, ":1") is None


def test_excerpt_returns_none_for_a_file_whose_content_is_empty():
    # Etherscan sometimes ships a source entry with empty content
    assert excerpt_at({"A.sol": ""}, "A.sol:1") is None


def test_excerpt_clamps_a_radius_larger_than_the_file():
    # short files (interfaces, single-function libraries) are common; the
    # window should just clamp to the file's actual bounds, not error
    files = {"A.sol": "a\nb\nc"}
    ex = excerpt_at(files, "A.sol:2", radius=10)
    assert ex["start_line"] == 1
    assert ex["lines"] == ["a", "b", "c"]
