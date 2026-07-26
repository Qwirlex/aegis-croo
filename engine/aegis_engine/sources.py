from __future__ import annotations

# Reusing the private normalizer rather than duplicating its parsing of the
# three Etherscan source shapes (plain, legacy multi-file, double-wrapped
# standard json). static_analysis.py notes that this module depends on its
# return shape, so a change there must be checked against this file too.
from .static_analysis import _to_standard_json


def split_sources(source: str) -> dict[str, str]:
    """Return a path to content map for any Etherscan source shape.

    A plain single file source becomes one Target.sol entry, which keeps the
    same name Slither reports for raw source runs. Multi file and standard json
    blobs are split by their real paths so a finding location can be resolved to
    the file it belongs to.
    """
    std = _to_standard_json(source)
    if std is None:
        return {"Target.sol": source}
    out: dict[str, str] = {}
    for path, entry in (std.get("sources") or {}).items():
        if isinstance(entry, dict):
            out[path] = entry.get("content", "")
        elif isinstance(entry, str):
            out[path] = entry
    return out or {"Target.sol": source}


def _match_file(files: dict[str, str], name: str) -> str | None:
    """Resolve a Slither location name to a real key in files, without guessing.

    Three ordered steps, each stricter than a plain "same basename" scan:
    1. an exact key hit wins outright.
    2. otherwise, a suffix match against keys ending in "/" + name, since
       Slither often shortens a path but keeps the last directory. Used only
       when exactly one key matches.
    3. otherwise, a bare basename match, again used only when exactly one key
       matches.
    Any step that turns up more than one candidate returns None immediately
    instead of falling through and guessing. Vendoring the same file name
    (IERC20.sol, SafeMath.sol) under two different directories is normal in
    Solidity projects, and silently picking one would put unrelated code into
    a paid report as the offending excerpt, and could make the refutation pass
    judge a real finding against code that never had the bug.
    """
    if name in files:
        return name

    suffix = "/" + name
    suffix_hits = [path for path in files if path.endswith(suffix)]
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    if len(suffix_hits) > 1:
        return None

    base = name.rsplit("/", 1)[-1]
    base_hits = [path for path in files if path.rsplit("/", 1)[-1] == base]
    if len(base_hits) == 1:
        return base_hits[0]
    return None


def excerpt_at(files: dict[str, str], location: str, radius: int = 4) -> dict | None:
    """Cut a small window of code around a File.sol:LINE location.

    Returns None when the location has no line or names a file we do not hold,
    so the report simply omits the excerpt instead of inventing code. The
    default radius is small on purpose, the excerpt is meant to fit and stay
    readable inside a report card, not reproduce the whole function.
    """
    if ":" not in (location or ""):
        return None
    name, _, line_s = location.rpartition(":")
    try:
        line = int(line_s)
    except ValueError:
        return None
    path = _match_file(files, name)
    if path is None or line < 1:
        return None
    all_lines = files[path].splitlines()
    if line > len(all_lines):
        return None
    start = max(1, line - radius)
    end = min(len(all_lines), line + radius)
    return {
        "file": path,
        "start_line": start,
        "focus_line": line,
        "lines": all_lines[start - 1:end],
    }
