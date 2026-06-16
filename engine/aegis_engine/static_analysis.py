from __future__ import annotations
import json
import os
import pathlib
import re
import subprocess
import tempfile

# Resolve the venv Scripts directory relative to this file so subprocess
# calls work regardless of the system PATH (needed on Windows where solc/slither
# are installed into the project venv, not the system PATH). On Linux the venv
# uses bin/ not Scripts/, so these fall back to PATH names, and the systemd unit
# puts the venv bin on PATH.
_SCRIPTS = pathlib.Path(__file__).parent.parent / ".venv" / "Scripts"
_SLITHER = str(_SCRIPTS / "slither.exe") if (_SCRIPTS / "slither.exe").exists() else "slither"
_SOLC = str(_SCRIPTS / "solc.exe") if (_SCRIPTS / "solc.exe").exists() else "solc"
_SOLC_SELECT = str(_SCRIPTS / "solc-select.exe") if (_SCRIPTS / "solc-select.exe").exists() else "solc-select"

_DEFAULT_SOLC = "0.8.25"


class SlitherCompileError(RuntimeError):
    """Raised when slither could not compile or analyze the source.

    This is distinct from a clean contract. A clean contract still produces the
    JSON report with zero detectors, whereas a compile failure produces no
    report at all. Callers turn this into a cannot_analyze result instead of a
    misleading "0 findings, looks clean" report.
    """


def resolve_solc_version(source: str, solc_version: str | None) -> str:
    """Pick a concrete solc version.

    An explicit concrete version from the caller wins. Otherwise parse the first
    concrete version out of the source pragma. Otherwise fall back to the default.
    """
    if solc_version and solc_version not in ("auto", ""):
        return solc_version
    m = re.search(r"pragma\s+solidity[^;]*?(\d+\.\d+\.\d+)", source)
    return m.group(1) if m else _DEFAULT_SOLC


def _ensure_solc(version: str) -> None:
    """Install the requested solc version if it is missing. Idempotent."""
    subprocess.run([_SOLC_SELECT, "install", version], capture_output=True, text=True)


def run_slither(source: str, solc_version: str = _DEFAULT_SOLC) -> list[dict]:
    """Compile + run slither on a single-file source, return normalized findings.

    Compiles with the contract's own solc version, resolved from solc_version or
    the source pragma, via solc-select and the SOLC_VERSION env var, so contracts
    that are not on the default version still compile. Raises SlitherCompileError
    when compilation or analysis fails, so the caller reports cannot_analyze
    instead of an empty, falsely clean result.

    Notes
    -----
    - ``--solc`` points slither at the solc-select shim, and SOLC_VERSION selects
      the concrete version for that single invocation.
    - ``shell=False`` everywhere; absolute paths remove PATH dependency on Windows.
    """
    version = resolve_solc_version(source, solc_version)
    _ensure_solc(version)

    with tempfile.TemporaryDirectory() as d:
        sol_file = pathlib.Path(d) / "Target.sol"
        sol_file.write_text(source, encoding="utf-8")
        out_json = pathlib.Path(d) / "slither.json"

        cmd = [
            _SLITHER,
            str(sol_file),
            "--solc", _SOLC,
            "--json", str(out_json),
        ]
        env = {**os.environ, "SOLC_VERSION": version}

        proc = subprocess.run(
            cmd,
            cwd=d,
            capture_output=True,
            text=True,
            env=env,
        )

        if not out_json.exists():
            # No report means slither could not compile or analyze the source.
            # Do not pretend the contract is clean.
            err = (proc.stderr or proc.stdout or "").strip()
            raise SlitherCompileError(
                f"could not compile or analyze with solc {version}: {err[-400:]}"
            )

        data = json.loads(out_json.read_text(encoding="utf-8"))

    findings: list[dict] = []
    for det in data.get("results", {}).get("detectors", []):
        # Prefer the first element's source_mapping for line number; fall back to 0.
        elem = (det.get("elements") or [{}])[0]
        line = (elem.get("source_mapping", {}).get("lines") or [0])[0]
        findings.append({
            "check": det.get("check", "unknown"),
            "impact": det.get("impact", "Informational"),
            "description": det.get("description", "").strip(),
            "line": line,
        })
    return findings
