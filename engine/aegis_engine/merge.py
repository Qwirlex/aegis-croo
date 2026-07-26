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


def slither_as_findings(slither: list[dict]) -> list[dict]:
    out = []
    for hit in slither:
        check = hit.get("check", "unknown")
        out.append({
            "severity": _SLITHER_SEVERITY.get(hit.get("impact", "Informational"), "info"),
            "title": check.replace("-", " "),
            "location": f"{hit.get('file', 'Target.sol')}:{hit.get('line', 0)}",
            "category": "static_analysis",
            "description": (hit.get("description") or "").strip(),
            "impact": "",
            "exploit_scenario": "",
            "recommendation": "",
            "provenance": [f"slither:{check}"],
        })
    return out


def _key(f: dict) -> tuple[str, str | int]:
    loc = f.get("location", "")
    file, _, line = loc.rpartition(":")
    line = line.strip()
    normalized_line: str | int
    try:
        normalized_line = int(line)
    except ValueError:
        normalized_line = line
    return (file.rsplit("/", 1)[-1].lower(), normalized_line)


def merge_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings that point at the same file and line.

    The highest severity variant keeps its own wording, and every provenance is
    kept, so the report can show that two independent lenses agreed. Agreement is
    the strongest signal we can give a buyer without running the code.
    """
    best: dict[tuple[str, str | int], dict] = {}
    for f in findings:
        k = _key(f)
        cur = best.get(k)
        if cur is None:
            best[k] = {**f, "provenance": list(f.get("provenance", []))}
            continue
        merged_prov = list(dict.fromkeys(cur["provenance"] + list(f.get("provenance", []))))
        if _RANK.get(f.get("severity", "info"), 1) > _RANK.get(cur.get("severity", "info"), 1):
            best[k] = {**f, "provenance": merged_prov}
        else:
            cur["provenance"] = merged_prov

    ordered = sorted(
        best.values(),
        key=lambda f: (-_RANK.get(f.get("severity", "info"), 1), f.get("location", "")),
    )
    for i, f in enumerate(ordered, 1):
        f["id"] = f"F-{i}"
    return ordered
