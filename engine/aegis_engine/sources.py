from __future__ import annotations

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
    if name in files:
        return name
    base = name.rsplit("/", 1)[-1]
    for path in files:
        if path.rsplit("/", 1)[-1] == base:
            return path
    return None


def excerpt_at(files: dict[str, str], location: str, radius: int = 4) -> dict | None:
    """Cut a small window of code around a File.sol:LINE location.

    Returns None when the location has no line or names a file we do not hold,
    so the report simply omits the excerpt instead of inventing code.
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
