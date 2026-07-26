from __future__ import annotations

_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Slither reports an impact word, our report uses a severity. Optimization and
# Informational are noise for a paid audit, they land in info.
_SLITHER_SEVERITY = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Optimization": "info",
}


_MAX_DETECTOR_TEXT = 320


def clean_detector_text(text: str) -> str:
    """Make a detector's own prose fit to print in a paid report.

    Slither writes multi line output with tabs and full dependency paths, for
    example node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol#4. That
    reads like a build log next to the written findings, so the paths are cut
    back to the file name, the whitespace is collapsed and the text is capped.
    """
    import re

    cleaned = re.sub(r"[\w./@-]*/([\w.-]+\.sol)", r"\1", text or "")
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > _MAX_DETECTOR_TEXT:
        cleaned = cleaned[:_MAX_DETECTOR_TEXT].rstrip() + " ..."
    return cleaned


def slither_as_findings(slither: list[dict]) -> list[dict]:
    out = []
    for hit in slither:
        check = hit.get("check", "unknown")
        out.append({
            "severity": _SLITHER_SEVERITY.get(hit.get("impact", "Informational"), "info"),
            "title": check.replace("-", " "),
            "location": f"{hit.get('file', 'Target.sol')}:{hit.get('line', 0)}",
            "category": "static_analysis",
            "description": clean_detector_text(hit.get("description") or ""),
            "impact": "",
            "exploit_scenario": "",
            "recommendation": "",
            "provenance": [f"slither:{check}"],
        })
    return out


def _normalize_location(loc: str) -> tuple[str, str | int]:
    """Split "path:line" into a lowercased path and a normalized line.

    The line is stripped and parsed as an integer when it parses as one, so
    "12", " 12" and "012" all agree. A location with no colon at all puts
    the whole string in the line slot and leaves the path empty, that only
    groups with another finding whose raw text is identical, and in practice
    it never happens here, lenses.py drops any finding whose location fails
    its own grounding rule before merge_findings ever sees it, and
    slither_as_findings always builds "file:line" itself.
    """
    file, _, line = (loc or "").rpartition(":")
    line = line.strip()
    normalized_line: str | int
    try:
        normalized_line = int(line)
    except ValueError:
        normalized_line = line
    return file.strip().lower(), normalized_line


def _paths_match(a: str, b: str) -> bool:
    """True when one normalized path is a suffix of the other, or they are equal.

    Mirrors sources.py's _match_file, which resolves a Slither location
    against a set of real file paths without guessing which one it means.
    "A.sol" and "src/A.sol" are the same file reported two ways. This is
    only the pairwise check, whether it is safe to act on is decided by
    _cluster_paths below.
    """
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _cluster_paths(paths: set[str]) -> dict[str, str]:
    """Map every distinct path reported on one line to a canonical path.

    Two distinct paths fold together only when each is the other's single
    suffix match candidate among every other path reported on that same
    line, mirroring sources.py's rule that a step turning up more than one
    candidate does not guess. A verified multi file project routinely
    vendors more than one file under the same name, so "contracts/tokens/
    Token.sol" and "contracts/vendor/Token.sol" must stay apart even though
    they share a basename. A third finding that reports a bare "Token.sol"
    on the same line matches both of them and therefore stays on its own
    too, rather than silently picking one or chaining the two real files
    together through it. That holds regardless of which order the three
    findings arrive in, since every path's candidates are recomputed from
    the whole set each time, not from whatever has been grouped so far.
    """
    representative = {p: p for p in paths}
    for p in paths:
        matches = [q for q in paths if q != p and _paths_match(p, q)]
        if len(matches) != 1:
            continue
        q = matches[0]
        back_matches = [r for r in paths if r != q and _paths_match(q, r)]
        if len(back_matches) == 1 and back_matches[0] == p:
            rep = min(p, q)
            representative[p] = rep
            representative[q] = rep
    return representative


def _demote(group: dict, loser: dict) -> None:
    """Record a discarded variant as a short, readable also_flagged entry.

    Only category and description travel over, impact, exploit_scenario and
    recommendation are left out on purpose. Two lenses on one line often
    explain different things, and repeating their full text on every entry
    would make the merged finding unreadable.
    """
    group["also_flagged"].append({
        "category": loser.get("category", ""),
        "description": loser.get("description", ""),
    })
    # A finding being demoted may itself already carry flagged variants from
    # an earlier merge pass over the same data, carry those forward too.
    group["also_flagged"].extend(loser.get("also_flagged", []))


def merge_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings that point at the same real line.

    Two findings merge only when their normalized line matches and their
    paths cluster together under _cluster_paths, which keeps "A.sol:12" and
    "src/A.sol:12" together as the same file reported two ways, while two
    genuinely different files that happen to share a name, ordinary in a
    verified multi file project, stay apart rather than have one silently
    swallow the other.

    The highest severity variant keeps its own title, description, impact,
    exploit scenario and recommendation, and every provenance entry is kept,
    so the report can show the entry was flagged from several angles.
    Co-location on the same line is not agreement: an unrelated static
    analysis hit can land on the same line as a lens finding by coincidence,
    so this module does not establish that two provenance entries describe
    the same underlying issue, only that they point at the same place. That
    judgment belongs to the refutation pass, not here.

    Ids are not assigned here, see assign_ids.
    """
    keyed = [(*_normalize_location(f.get("location", "")), f) for f in findings]

    paths_by_line: dict[str | int, set[str]] = {}
    for path, line, _f in keyed:
        paths_by_line.setdefault(line, set()).add(path)
    representative_by_line = {line: _cluster_paths(paths) for line, paths in paths_by_line.items()}

    groups: dict[tuple, dict] = {}
    for path, line, f in keyed:
        root = (line, representative_by_line[line][path])
        g = groups.get(root)
        if g is None:
            groups[root] = {
                "provenance": list(f.get("provenance", [])),
                "also_flagged": list(f.get("also_flagged", [])),
                "best": f,
            }
            continue
        g["provenance"] = list(dict.fromkeys(g["provenance"] + list(f.get("provenance", []))))
        if _RANK.get(f.get("severity", "info"), 1) > _RANK.get(g["best"].get("severity", "info"), 1):
            _demote(g, g["best"])
            g["best"] = f
        else:
            _demote(g, f)

    ordered = sorted(
        groups.values(),
        key=lambda g: (-_RANK.get(g["best"].get("severity", "info"), 1), g["best"].get("location", "")),
    )
    return [
        {**g["best"], "provenance": g["provenance"], "also_flagged": g["also_flagged"]}
        for g in ordered
    ]


def assign_ids(findings: list[dict]) -> list[dict]:
    """Stamp F-1 upward over the given list, in the order given, in place.

    Kept separate from merge_findings: an orchestrator that merges twice in
    one audit would otherwise get an id from the first merge that silently
    points at a different finding after the second. Call this once, after
    all merging for the audit is finished, and treat the result as a
    display label, not a persistent key.
    """
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i}"
    return findings
