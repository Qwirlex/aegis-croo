from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

# Reusing the private JSON unwrapper rather than duplicating its handling of a
# fenced code block around the model's reply. sources.py made the same call
# for a different helper, see the comment there.
from .llm import GeminiClient, _strip_json


@dataclass(frozen=True)
class Lens:
    name: str
    focus: str
    checklist: str
    token_only: bool = False


LENSES: list[Lens] = [
    Lens(
        "access_control",
        "who is allowed to do what, and what a privileged caller can do to other people's money",
        "Missing or wrong caller gates. Functions that should be restricted and are not. "
        "What the owner or an admin can do to user funds. Ownership transfer and renounce paths. "
        "Absence of a delay on dangerous actions. Roles that can grant themselves more power.",
    ),
    Lens(
        "reentrancy_state",
        "external calls and the order of state updates around them",
        "State written after an external call. Balances not zeroed before a transfer. "
        "Callbacks and hooks that let a caller re enter. Loops that call out. "
        "Cross function and cross contract re entry through shared state.",
    ),
    Lens(
        "arithmetic_logic",
        "arithmetic, precision and accounting logic",
        "Rounding that favours the wrong side. Precision loss from dividing before multiplying. "
        "Unchecked blocks that can wrap. Unsafe casts to a smaller type. "
        "Off by one in accounting. Zero amount and empty set edge cases.",
    ),
    Lens(
        "economics_oracle",
        "how value and prices enter the contract and how they can be manipulated",
        "A price read from a source a caller can move inside one transaction. "
        "Spot reserves used as a price. Missing slippage or deadline bounds. Fee math that can be gamed. "
        "First depositor and share inflation. Sensitivity to a flash loan.",
    ),
    Lens(
        "upgrade_proxy",
        "upgradeability, initialization and low level calls",
        "An initializer that can be called twice or was never called. Storage layout that a new "
        "implementation can collide with. delegatecall to an address a caller controls. selfdestruct "
        "exposure. An implementation slot that is writable by the wrong party.",
    ),
    Lens(
        "erc20_rug",
        "the ways a token contract can be turned against its holders",
        "Mint that is unbounded or reachable by one address. Blocklists and allowlists that can stop a "
        "holder from selling. A transfer fee that can be raised without limit. Transfers that can be "
        "paused. Paths where only the owner can sell. A token whose code can be replaced later.",
        token_only=True,
    ),
]

_STYLE = (
    "STYLE: plain direct English a non expert can read. Do NOT use em dashes, en dashes or hyphens. "
    "Do NOT use parentheses or any bracketed aside. Write a bare function name with no trailing "
    "brackets. Avoid hyphenated jargon, say it in plain words instead. Keep sentences short. "
    "The location and category fields are identifiers, do not restyle them."
)

_PROMPT = """You are a Solidity security auditor working one narrow lens only.
LENS: {name}
FOCUS: {focus}
CHECK FOR: {checklist}
Report ONLY issues that belong to this lens. Ignore everything else, another auditor covers it.
Return STRICT JSON: {{"findings": [{{"severity": one of critical|high|medium|low|info, "title": str,
"location": "File.sol:LINE", "category": "{name}", "description": str, "impact": str,
"exploit_scenario": str, "recommendation": str}}]}}
RULES: every finding MUST have a concrete location File.sol:LINE taken from the source below.
Never invent a line. If you find nothing real, return an empty findings list, an empty list is a
valid and useful answer. description says what is wrong, impact says what an attacker or a
privileged caller can actually achieve, exploit_scenario gives concrete ordered steps,
recommendation gives the specific fix.
{style}
INVENTORY:
{inventory}
SLITHER:
{slither}
SOURCE:
{source}
"""


@dataclass
class LensRun:
    findings: list[dict] = field(default_factory=list)
    lenses_run: list[str] = field(default_factory=list)
    lenses_skipped: list[dict] = field(default_factory=list)
    # Per lens count of findings _parse discarded for having no real location.
    # Without this, a lens that came back with ten ungrounded findings reads
    # in a report exactly like a lens that found nothing, which is not the
    # same thing and should not look the same in the coverage section. Only
    # lenses that actually dropped something get an entry here, same as
    # lenses_skipped only holding lenses that actually failed.
    dropped: list[dict] = field(default_factory=list)


def lenses_for(inventory: dict) -> list[Lens]:
    is_token = bool(inventory.get("is_erc20"))
    return [l for l in LENSES if not l.token_only or is_token]


def build_lens_prompt(lens: Lens, *, source: str, inventory: dict, slither: list[dict]) -> str:
    return _PROMPT.format(
        name=lens.name,
        focus=lens.focus,
        checklist=lens.checklist,
        style=_STYLE,
        inventory=json.dumps({
            "is_erc20": inventory.get("is_erc20"),
            "is_upgradeable": inventory.get("is_upgradeable"),
            "functions": inventory.get("functions", [])[:120],
        }),
        slither=json.dumps(slither),
        source=source,
    )


# The only severities a later task's weight table knows how to score. A lens
# that reports anything else is clamped to info rather than left raw, since an
# unrecognized value would raise a KeyError downstream instead of just scoring
# low.
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _parse(lens: Lens, raw: str) -> tuple[list[dict], int]:
    """Return the grounded findings and a count of what got discarded.

    The count matters as much as the survivors: a lens that came back with
    ten ungrounded findings is not the same as a lens that found nothing, and
    the caller needs to be able to tell the two apart.
    """
    data = _strip_json(raw)
    out: list[dict] = []
    dropped = 0
    for f in data.get("findings", []):
        loc = (f.get("location") or "").strip()
        if not loc or ":" not in loc:
            dropped += 1
            continue  # grounding rule, a finding without a line is not a finding
        line_part = loc.rpartition(":")[2].strip()
        if not line_part.isdigit():
            dropped += 1
            continue  # grounding rule, a colon with no real line number is not a finding
        # A model very often answers "Critical" or "HIGH" rather than the
        # lowercase form the checklist shows, so the case is normalized before
        # the membership check. Clamping the raw, un-normalized value would
        # silently drop a genuine critical to info, weight 0, which is worse
        # than not clamping at all.
        severity = str(f.get("severity") or "info").strip().lower()
        if severity not in _ALLOWED_SEVERITIES:
            severity = "info"
        out.append({
            "severity": severity,
            "title": f.get("title", "").strip(),
            "location": loc,
            "category": f.get("category") or lens.name,
            "description": f.get("description", ""),
            "impact": f.get("impact", ""),
            "exploit_scenario": f.get("exploit_scenario", ""),
            "recommendation": f.get("recommendation", ""),
            "provenance": [f"lens:{lens.name}"],
        })
    return out, dropped


# Overall wall clock budget for one run_lenses call across the whole set of
# lenses, not per lens. Six concurrent model calls that each normally answer
# in well under a minute comfortably fit inside this, with room to spare for
# one slow one. A caller can override it, and a test can pass a tiny value so
# a stuck lens surfaces immediately instead of hanging the whole suite.
DEFAULT_LENS_BUDGET_SECONDS = 180.0


def run_lenses(
    *,
    lenses: list[Lens],
    source: str,
    inventory: dict,
    slither: list[dict],
    llm=None,
    budget_seconds: float = DEFAULT_LENS_BUDGET_SECONDS,
) -> LensRun:
    """Run every lens concurrently, bounded by one overall time budget.

    Draining goes through as_completed with that budget as its timeout, so a
    slow or hung lens can never delay collecting the ones that already
    finished, and can never block the whole run past the budget either. A
    lens that raises, and a lens still running when the budget runs out, are
    both recorded in lenses_skipped rather than left to stall a paid job
    forever. The pool is shut down without waiting for any lens still running
    past the budget, an abandoned thread is not worth blocking on twice. The
    output order still follows the original lens order, not completion
    order, so callers see a stable, predictable report regardless of which
    lens happened to answer first.
    """
    lenses = list(lenses)
    llm = llm or GeminiClient()
    result = LensRun()

    def one(lens: Lens):
        prompt = build_lens_prompt(lens, source=source, inventory=inventory, slither=slither)
        return _parse(lens, llm.generate(prompt))

    pool = ThreadPoolExecutor(max_workers=len(lenses) or 1)
    outcomes: list[tuple | None] = [None] * len(lenses)
    try:
        futures = [pool.submit(one, lens) for lens in lenses]
        future_index = {fut: i for i, fut in enumerate(futures)}
        try:
            for fut in as_completed(futures, timeout=budget_seconds):
                i = future_index[fut]
                try:
                    findings, dropped = fut.result()
                    outcomes[i] = ("ok", findings, dropped)
                except Exception as e:
                    outcomes[i] = ("error", str(e)[:200])
        except TimeoutError:
            pass  # whatever is still None below ran out of budget, not an error
    finally:
        # A lens still running past the budget must not block shutdown, that
        # would defeat the whole point of the budget. Abandon it instead of
        # waiting, the process exit hook joins any thread that is still
        # somehow alive once the underlying call itself finally gives up.
        pool.shutdown(wait=False)

    for lens, outcome in zip(lenses, outcomes):
        if outcome is None:
            result.lenses_skipped.append({
                "lens": lens.name,
                "reason": f"timed out after {budget_seconds} seconds",
            })
            continue
        kind = outcome[0]
        if kind == "error":
            result.lenses_skipped.append({"lens": lens.name, "reason": outcome[1]})
            continue
        _, findings, dropped = outcome
        result.lenses_run.append(lens.name)
        result.findings.extend(findings)
        if dropped:
            result.dropped.append({"lens": lens.name, "count": dropped})
    return result
