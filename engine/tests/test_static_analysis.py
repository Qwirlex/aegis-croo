import pathlib
from aegis_engine.static_analysis import run_slither

FIX = pathlib.Path(__file__).parent / "fixtures" / "VulnerableVault.sol"

def test_slither_detects_reentrancy():
    findings = run_slither(FIX.read_text(), solc_version="0.8.25")
    detectors = {f["check"] for f in findings}
    assert any("reentrancy" in d for d in detectors)
    assert all("line" in f and "check" in f for f in findings)
