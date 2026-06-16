from __future__ import annotations
import json
import pathlib
import subprocess
import tempfile

# Resolve the venv Scripts directory relative to this file so subprocess
# calls work regardless of the system PATH (needed on Windows where solc/slither
# are installed into the project venv, not the system PATH).
_SCRIPTS = pathlib.Path(__file__).parent.parent / ".venv" / "Scripts"
_SLITHER = str(_SCRIPTS / "slither.exe") if (_SCRIPTS / "slither.exe").exists() else "slither"
_SOLC = str(_SCRIPTS / "solc.exe") if (_SCRIPTS / "solc.exe").exists() else "solc"


def run_slither(source: str, solc_version: str = "0.8.25") -> list[dict]:
    """Compile + run slither on a single-file source, return normalized findings.

    Deviations from reference implementation
    -----------------------------------------
    - Uses ``--solc <absolute-path>`` instead of ``solc-select use`` + the
      ``--solc-solcs-select`` flag.  On Windows the venv's ``solc.exe`` is not
      on the system PATH, so we pass its absolute path directly.  This is
      equivalent behaviour for single-version workflows.
    - ``shell=False`` everywhere; absolute paths remove any PATH dependency.
    - ``solc_version`` parameter is kept in the signature for API stability
      (Task 6 passes it), but is currently unused because ``solc.exe`` in the
      venv is already pinned to 0.8.25 via solc-select.
    """
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

        subprocess.run(
            cmd,
            cwd=d,
            capture_output=True,
            text=True,
        )

        if not out_json.exists():
            return []

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
