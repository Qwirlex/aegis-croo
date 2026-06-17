import json
import pathlib
import pytest
from aegis_engine.static_analysis import (
    run_slither,
    resolve_solc_version,
    flatten_source,
    _to_standard_json,
    SlitherCompileError,
)

FIX = pathlib.Path(__file__).parent / "fixtures" / "VulnerableVault.sol"

def test_slither_detects_reentrancy():
    findings = run_slither(FIX.read_text(), solc_version="0.8.25")
    detectors = {f["check"] for f in findings}
    assert any("reentrancy" in d for d in detectors)
    assert all("line" in f and "check" in f for f in findings)


def test_resolve_version_explicit_wins():
    # an explicit concrete version overrides whatever the pragma says
    assert resolve_solc_version("pragma solidity 0.5.0;", "0.8.25") == "0.8.25"


def test_resolve_version_from_pragma():
    # when the caller has no concrete version, read it from the pragma
    assert resolve_solc_version("pragma solidity ^0.6.12;\ncontract C{}", "auto") == "0.6.12"


def test_resolve_version_default():
    # no concrete version and no pragma falls back to the default
    assert resolve_solc_version("contract C{}", "auto") == "0.8.25"


def test_slither_raises_on_compile_failure():
    # a source that cannot compile must raise, not return [] (which would look clean)
    with pytest.raises(SlitherCompileError):
        run_slither("this is not valid solidity at all", solc_version="0.8.25")


# ---------------------------------------------------------------------------
# Etherscan multi-file / standard-json source handling
# ---------------------------------------------------------------------------

def test_plain_source_is_not_standard_json():
    assert _to_standard_json("pragma solidity ^0.8.0;\ncontract C{}") is None


def test_double_wrapped_standard_json_is_unwrapped():
    # Basescan double-wraps standard-json input in an extra pair of braces.
    blob = "{{" + json.dumps({
        "language": "Solidity",
        "sources": {"A.sol": {"content": "contract A{}"}},
        "settings": {"optimizer": {"enabled": True, "runs": 200}},
    })[1:-1] + "}}"
    std = _to_standard_json(blob)
    assert std is not None
    assert std["language"] == "Solidity"
    assert "A.sol" in std["sources"]
    # optimizer settings are preserved, outputSelection is forced to include the AST
    assert std["settings"]["optimizer"]["runs"] == 200
    assert std["settings"]["outputSelection"]["*"][""] == ["ast"]


def test_legacy_multifile_map_is_wrapped_as_standard_json():
    blob = json.dumps({
        "contracts/A.sol": {"content": "contract A{}"},
        "contracts/B.sol": {"content": "contract B{}"},
    })
    std = _to_standard_json(blob)
    assert std is not None
    assert set(std["sources"]) == {"contracts/A.sol", "contracts/B.sol"}


def test_flatten_source_concatenates_multifile():
    blob = json.dumps({
        "A.sol": {"content": "contract A{}"},
        "B.sol": {"content": "contract B{}"},
    })
    flat = flatten_source(blob)
    assert "// File: A.sol" in flat
    assert "contract A{}" in flat
    assert "contract B{}" in flat


def test_flatten_source_passthrough_for_plain():
    src = "pragma solidity ^0.8.0;\ncontract C{}"
    assert flatten_source(src) == src
