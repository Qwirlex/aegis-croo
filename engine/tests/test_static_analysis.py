import pathlib
import pytest
from aegis_engine.static_analysis import (
    run_slither,
    resolve_solc_version,
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
