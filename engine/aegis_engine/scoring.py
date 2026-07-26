from __future__ import annotations

# Weight per finding and a cap per severity band. The cap is what stops a pile of
# small notes from reading like a critical bug, which is the failure mode of the
# old plain sum score. An unknown severity weighs nothing rather than raising,
# since a scoring call must never be the thing that fails a paid audit.
_WEIGHT = {"critical": 60, "high": 25, "medium": 10, "low": 3, "info": 0}
_CAP = {"critical": 100, "high": 60, "medium": 20, "low": 9, "info": 0}
_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def risk_score(findings: list[dict]) -> int:
    """Score 0 to 100, capped per severity band so quantity cannot fake severity."""
    total = 0
    for severity, weight in _WEIGHT.items():
        n = sum(1 for f in findings if f.get("severity") == severity)
        total += min(n * weight, _CAP[severity])
    return min(100, total)


def verdict_for(score: int, findings: list[dict]) -> str:
    """Label the audit by its worst real finding, not by the score.

    The score is a summary a buyer skims. The verdict is the sentence they act
    on, so one critical outranks any number of mediums even when the arithmetic
    of the score would say otherwise.
    """
    worst = max((_RANK.get(f.get("severity", "info"), 1) for f in findings), default=1)
    if worst == 5:
        return "critical_risk"
    if worst == 4:
        return "high_risk"
    if worst == 3:
        return "caution"
    return "looks_ok"


def confidence_for(*, source_verified: bool, lenses_run: int, lenses_total: int,
                   refuted_share: float) -> str:
    """Confidence is computed, never asserted.

    A run where no lens completed is static analysis only, so it cannot claim
    more than low. A refutation rate above 0.8 means the lenses were mostly
    wrong, so whatever survived deserves a warning too.
    """
    if lenses_run <= 0 or lenses_total <= 0:
        return "low"
    if refuted_share > 0.8:
        return "low"
    if lenses_run < lenses_total:
        return "medium"
    if not source_verified:
        return "medium"
    return "high"
