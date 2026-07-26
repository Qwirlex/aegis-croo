from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

# _strip_json is private but reused here on purpose. It is the one place that
# knows how a model wraps its json in a fenced block, and a second copy would
# drift from it. The same decision was made in sources.py and lenses.py.
from .llm import GeminiClient, _strip_json
from .sources import excerpt_at

_PROMPT = """You are a skeptical reviewer whose only job is to REFUTE a claimed vulnerability.
Assume the claim is wrong until the code proves otherwise. If you are uncertain, answer refuted.
A claim survives only when the code in front of you clearly shows the problem is real and reachable.
Return STRICT JSON: {{"verdict": one of refuted|weakened|stands, "reason": str}}
refuted means the claim is wrong, already prevented, or not reachable.
weakened means something real is there but the severity is overstated or it needs a privileged caller.
stands means the claim holds as written.
Keep the reason to one or two short sentences in plain English. No em dashes, no parentheses.
CLAIM:
title: {title}
severity: {severity}
location: {location}
what it says: {description}
claimed impact: {impact}
CODE AROUND {location}:
{code}
"""

# What each verdict does to the finding. None means the finding does not ship.
# Anything the reviewer did not clearly defend is treated as refuted, which is
# the whole point of this pass: what survives is what could not be argued away.
_VERDICT_MAP: dict[str, str | None] = {
    "refuted": None,
    "weakened": "demoted",
    "stands": "kept",
}

# Overall wall clock budget for one refutation pass across every finding, not
# per finding. A challenge that has not answered by then does not ship, same as
# one that was refuted, because an undefended finding is exactly what this pass
# exists to remove. A caller can override it, and a test can pass a tiny value.
DEFAULT_REFUTE_BUDGET_SECONDS = 180.0


def build_refute_prompt(finding: dict, *, excerpt: dict | None) -> str:
    if excerpt:
        start = excerpt["start_line"]
        code = "\n".join(f"{start + i}: {line}" for i, line in enumerate(excerpt["lines"]))
    else:
        code = "the source for this location was not available"
    return _PROMPT.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        location=finding.get("location", ""),
        description=finding.get("description", ""),
        impact=finding.get("impact", ""),
        code=code,
    )


def _is_static_evidence(finding: dict) -> bool:
    """True when a static analyser reported this, not only a reasoning pass.

    The distinction decides what happens when the skeptic cannot answer. A model
    claim with nobody to defend it is a guess and does not ship. A detector hit
    is a deterministic fact about the code, so it ships marked as unchallenged
    rather than being deleted by an unrelated outage.
    """
    return any(str(p).startswith("slither:") for p in finding.get("provenance", []))


def _unchallenged(finding: dict, reason: str) -> dict | None:
    if not _is_static_evidence(finding):
        return None
    return {**finding, "refutation": {"verdict": "not_checked", "reason": reason}}


def _challenge(finding: dict, *, files: dict[str, str], llm) -> dict | None:
    """Put one finding in front of a skeptic. Returns None when it does not survive."""
    prompt = build_refute_prompt(finding, excerpt=excerpt_at(files, finding.get("location", "")))
    try:
        data = _strip_json(llm.generate(prompt))
        verdict_raw = str(data.get("verdict", "refuted")).strip().lower()
        reason = str(data.get("reason", ""))[:400]
    except Exception:
        # A challenge we could not even read is not a defence, so a model claim
        # does not ship. Failing the other way would let an outage fill a report
        # with unchallenged guesses. Static analysis evidence is different, it
        # stands on its own and survives marked as unchallenged.
        return _unchallenged(finding, "the reviewer was unavailable, this is a static analysis result")
    mapped = _VERDICT_MAP.get(verdict_raw)
    if mapped is None:
        return None
    if mapped == "demoted":
        return {**finding, "severity": "info",
                "refutation": {"verdict": "demoted", "reason": reason}}
    return {**finding, "refutation": {"verdict": "kept", "reason": reason}}


def refute_findings(
    findings: list[dict],
    *,
    files: dict[str, str],
    llm=None,
    budget_seconds: float = DEFAULT_REFUTE_BUDGET_SECONDS,
) -> list[dict]:
    """Try to kill every finding. What survives is what the buyer pays for.

    Info level findings are not worth a model call, they are passed through
    marked not_checked. Anything the reviewer refutes is dropped, anything it
    weakens is demoted to info and kept so the report can still show it. The
    input order is preserved, so a caller that sorts later sees a stable list.
    """
    findings = list(findings)
    llm = llm or GeminiClient()

    outcomes: list[dict | None] = [None] * len(findings)
    to_check: list[int] = []
    for i, f in enumerate(findings):
        if f.get("severity") == "info":
            outcomes[i] = {**f, "refutation": {"verdict": "not_checked",
                                               "reason": "info level, not worth a challenge"}}
        else:
            to_check.append(i)

    if to_check:
        pool = ThreadPoolExecutor(max_workers=min(8, len(to_check)))
        try:
            futures = {pool.submit(_challenge, findings[i], files=files, llm=llm): i
                       for i in to_check}
            try:
                for fut in as_completed(futures, timeout=budget_seconds):
                    outcomes[futures[fut]] = fut.result()
            except TimeoutError:
                # Whatever has not answered by now is undefended, which is
                # treated exactly like refuted for a model claim. A detector hit
                # still ships, marked as unchallenged.
                for i in to_check:
                    if outcomes[i] is None:
                        outcomes[i] = _unchallenged(
                            findings[i], "the challenge did not finish in time")
        finally:
            # Never wait here. A stuck model call cannot be killed from outside,
            # so waiting would hand the hang straight back to the paying caller.
            pool.shutdown(wait=False)

    return [o for o in outcomes if o is not None]
