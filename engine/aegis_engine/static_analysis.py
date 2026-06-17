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


def _to_standard_json(source: str) -> dict | None:
    """Detect an Etherscan multi-file / standard-json source blob.

    Etherscan's getsourcecode returns ``SourceCode`` as one of:
      - a plain single-file Solidity string -> returns None, the caller writes
        a single Target.sol exactly as before;
      - a legacy multi-file map ``{"path/File.sol": {"content": "..."}}`` with
        single braces;
      - a solc standard-json input wrapped in an EXTRA pair of braces, e.g.
        ``{{ "language": "Solidity", "sources": {...}, "settings": {...} }}``.

    Returns a solc standard-json input dict ready to feed crytic-compile's
    Solc-json platform, or None for a plain source. This is what lets
    multi-file verified contracts (DAI, USDC, anything OpenZeppelin based)
    compile instead of failing with "Expected pragma" on a raw ``{{``.
    """
    s = source.strip()
    if not s.startswith("{"):
        return None
    # Etherscan double-wraps the standard-json input with extra braces.
    if s.startswith("{{") and s.endswith("}}"):
        s = s[1:-1]
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    if isinstance(obj.get("sources"), dict):
        std = dict(obj)  # already a standard-json input
    else:
        # Legacy multi-file map: {path: {"content": ...}} or {path: "source"}.
        sources: dict = {}
        for path, val in obj.items():
            if isinstance(val, dict) and "content" in val:
                sources[path] = {"content": val["content"]}
            elif isinstance(val, str):
                sources[path] = {"content": val}
            else:
                return None
        std = {"language": "Solidity", "sources": sources}

    std.setdefault("language", "Solidity")
    settings = dict(std.get("settings") or {})
    # Force solc to emit the AST; slither needs it and Etherscan's stored
    # outputSelection often restricts output to bytecode only. Mirror
    # crytic-compile's own default selection.
    settings["outputSelection"] = {
        "*": {
            "*": ["abi", "metadata", "devdoc", "userdoc",
                  "evm.bytecode", "evm.deployedBytecode"],
            "": ["ast"],
        }
    }
    std["settings"] = settings
    return std


def flatten_source(source: str) -> str:
    """Return human-readable Solidity for the LLM.

    Plain single-file sources pass through unchanged. Multi-file / standard-json
    blobs are concatenated, each file under a ``// File: <path>`` header, so the
    model reads real code instead of an escaped JSON string.
    """
    std = _to_standard_json(source)
    if std is None:
        return source
    parts = []
    for path, entry in (std.get("sources") or {}).items():
        content = entry.get("content", "") if isinstance(entry, dict) else ""
        parts.append(f"// File: {path}\n{content}")
    return "\n\n".join(parts) if parts else source


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


# Map our report network names to crytic-compile's Etherscan-platform prefixes.
_NETWORK_PREFIX = {"base": "base", "base-sepolia": "sepolia.base", "mainnet": "mainnet"}


def _parse_slither_json(data: dict) -> list[dict]:
    """Normalize slither's detector list into our finding dicts."""
    findings: list[dict] = []
    for det in data.get("results", {}).get("detectors", []):
        # Prefer the first element's source_mapping for line number; fall back to 0.
        elem = (det.get("elements") or [{}])[0]
        sm = elem.get("source_mapping", {})
        line = (sm.get("lines") or [0])[0]
        # On multi-file builds the finding belongs to a specific file; carry it
        # so locations are not all misreported as Target.sol.
        fname = sm.get("filename_short") or sm.get("filename_relative") or "Target.sol"
        findings.append({
            "check": det.get("check", "unknown"),
            "impact": det.get("impact", "Informational"),
            "description": det.get("description", "").strip(),
            "line": line,
            "file": fname,
        })
    return findings


def _run_slither_cmd(cmd: list[str], cwd: str, version: str, out_json: pathlib.Path) -> list[dict]:
    """Run a slither invocation and turn its result into findings.

    Raises SlitherCompileError when slither could not compile/analyze, so the
    caller reports cannot_analyze rather than a falsely clean, empty report.
    Slither writes the JSON even on failure with ``success: false``, so a
    missing file AND an explicit failure flag both count as a compile error.
    """
    env = {**os.environ, "SOLC_VERSION": version}
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)

    if not out_json.exists():
        err = (proc.stderr or proc.stdout or "").strip()
        raise SlitherCompileError(
            f"could not compile or analyze with solc {version}: {err[-400:]}"
        )

    data = json.loads(out_json.read_text(encoding="utf-8"))
    if data.get("success") is False:
        err = (str(data.get("error") or "") or proc.stderr or proc.stdout or "").strip()
        raise SlitherCompileError(
            f"could not compile or analyze with solc {version}: {err[-400:]}"
        )
    return _parse_slither_json(data)


def run_slither(
    source: str,
    solc_version: str = _DEFAULT_SOLC,
    *,
    address: str | None = None,
    network: str = "base",
) -> list[dict]:
    """Compile + run slither, return normalized findings.

    Two paths:
    - ``address`` given: hand the verified contract to crytic-compile's Etherscan
      platform (``slither base:0x...``). It fetches the source, lays multi-file
      and standard-json projects out on disk with the right remappings, and
      compiles them. This is what makes multi-file contracts (DAI, USDC, anything
      OpenZeppelin based) analyze instead of failing on a raw ``{{`` blob.
    - raw ``source`` only: write a single Target.sol and compile it, as before.

    The contract's own solc version is resolved from solc_version or the source
    pragma and installed via solc-select; SOLC_VERSION selects it for the run.
    Raises SlitherCompileError on compile/analyze failure so the caller reports
    cannot_analyze instead of an empty, falsely clean result.
    """
    version = resolve_solc_version(source, solc_version)
    _ensure_solc(version)

    with tempfile.TemporaryDirectory() as d:
        out_json = pathlib.Path(d) / "slither.json"

        if address:
            # crytic-compile fetches + lays out + compiles every Etherscan source
            # shape (single file, multi-file map, double-wrapped standard json).
            # Note: do NOT pass --solc here. The Etherscan platform copies the
            # --solc value into compiler_version.compiler, which slither then
            # reads as the *language*; an absolute path becomes "Unknown
            # language". Leaving it unset defaults to the bare "solc" shim on
            # PATH, and SOLC_VERSION selects the concrete version.
            prefix = _NETWORK_PREFIX.get(network, "base")
            cmd = [
                _SLITHER,
                f"{prefix}:{address}",
                "--etherscan-apikey", os.environ.get("BASESCAN_API_KEY", ""),
                "--json", str(out_json),
            ]
        else:
            target = pathlib.Path(d) / "Target.sol"
            target.write_text(source, encoding="utf-8")
            cmd = [
                _SLITHER,
                str(target),
                "--solc", _SOLC,
                "--json", str(out_json),
            ]

        return _run_slither_cmd(cmd, d, version, out_json)
