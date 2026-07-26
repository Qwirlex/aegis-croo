from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from .chains import chain_or_raise
from .integrity import sign_report
from .inventory import build_inventory
from .lenses import lenses_for, run_lenses
from .llm import GeminiClient, _strip_json
from .merge import assign_ids, merge_findings, slither_as_findings
from .models import Coverage, Finding, PrivilegedPower, Report
from .refute import refute_findings
from .scoring import confidence_for, risk_score, verdict_for
from .source import resolve_source as _resolve_source
from .sources import excerpt_at, split_sources
from .static_analysis import flatten_source, run_slither as _run_slither

# Every lens ships the whole source, so a large verified project multiplies the
# spend by six. Cap it here rather than inside a lens, since a lens must not be
# the thing deciding what the auditor is allowed to read. When the cap bites,
# the report says so, because a buyer must never be told the whole contract was
# read when it was not.
MAX_PROMPT_SOURCE_CHARS = 120_000

NOT_CHECKED = [
    "runtime behaviour, nothing was executed or simulated",
    "formal invariants and property proofs",
    "off chain components, keys and the deployment process",
    "economic assumptions that depend on future market conditions",
]

_SUMMARY_PROMPT = """Write the opening summary of a smart contract audit for a reader who is deciding
whether to put money into this contract. Three to five short sentences. Say what the contract is, what
the most serious problem is if there is one, and what the reader should do next.
No em dashes, no parentheses, no hyphenated jargon. Do not invent findings.
VERDICT: {verdict}
RISK SCORE: {score}
FINDINGS:
{findings}
"""

_TRIAGE_PROMPT = """You are a Solidity security auditor doing a fast triage pass, not a full audit.
Return STRICT JSON: {{"summary": str, "findings": [{{"severity": one of critical|high|medium|low|info,
"title": str, "location": "File.sol:LINE", "description": str}}]}}
Report at most five findings, the most serious ones only. Every finding MUST carry a real
File.sol:LINE from the source. Never invent a line. An empty list is a valid answer.
STYLE: plain direct English, no em dashes, no parentheses, no hyphenated jargon, short sentences.
SLITHER:
{slither}
SOURCE:
{source}
"""


@dataclass
class Prepared:
    """Everything the expensive part needs, produced before the buyer is charged."""
    source: str
    flat: str
    files: dict[str, str]
    inventory: dict
    slither: list[dict]
    address: str | None
    chain: str
    chain_id: int
    contract_name: str
    compiler: str
    source_verified: bool
    truncated_chars: int = 0


def _cap_source(flat: str) -> tuple[str, int]:
    if len(flat) <= MAX_PROMPT_SOURCE_CHARS:
        return flat, 0
    cut = len(flat) - MAX_PROMPT_SOURCE_CHARS
    marker = f"\n\n// the source was truncated here, {cut} characters were not read\n"
    return flat[:MAX_PROMPT_SOURCE_CHARS] + marker, cut


def prepare_target(*, source: str | None, address: str | None, chain: str = "base",
                   resolve=None, slither=None) -> Prepared:
    """Resolve, compile and statically analyse. Raises on anything that means we cannot audit.

    This runs inside the paid request before a response is written, so a target
    we cannot analyse produces an error status and the payment never settles.
    """
    resolve = resolve or _resolve_source
    slither = slither or _run_slither
    # Validate the chain even in raw source mode, so an unsupported value is a
    # plain error rather than a silent default, and the report names a real chain.
    c = chain_or_raise(chain)
    rs = resolve(source=source, address=address, chain=chain)
    compiler = "0.8.25" if rs.compiler in ("auto", "") else rs.compiler
    hits = slither(rs.source, compiler, address=address, chain=chain)
    files = split_sources(rs.source)
    flat, truncated = _cap_source(flatten_source(rs.source))
    return Prepared(
        source=rs.source, flat=flat, files=files, inventory=build_inventory(files),
        slither=hits, address=address, chain=c.name, chain_id=c.chain_id,
        contract_name=getattr(rs, "contract_name", "unknown"), compiler=compiler,
        source_verified=getattr(rs, "verified", False), truncated_chars=truncated,
    )


def _as_finding(d: dict, files: dict[str, str]) -> Finding:
    prov = d.get("provenance", [])
    return Finding(
        id=d.get("id", "F-0"),
        severity=d.get("severity", "info"),
        title=d.get("title", ""),
        location=d.get("location", ""),
        source=(prov[0] if prov else "llm"),
        description=d.get("description", ""),
        recommendation=d.get("recommendation", ""),
        category=d.get("category", "unspecified"),
        impact=d.get("impact", ""),
        exploit_scenario=d.get("exploit_scenario", ""),
        provenance=prov,
        also_flagged=d.get("also_flagged", []),
        refutation=d.get("refutation"),
        code_excerpt=excerpt_at(files, d.get("location", "")),
        # Two independent angles on one line is the strongest signal available
        # without executing the code, so it is the only thing that earns high.
        confidence="high" if len(prov) > 1 else "medium",
    )


def _coverage_notes(prepared: Prepared, extra: list[str] | None = None) -> list[str]:
    notes = list(NOT_CHECKED)
    if prepared.truncated_chars:
        notes.append(
            f"the contract was too large to read in full, {prepared.truncated_chars} characters "
            "were truncated and not analysed by the reasoning passes"
        )
    return notes + list(extra or [])


def _summary(llm, *, verdict: str, score: int, findings: list[dict]) -> str:
    brief = [{"severity": f.get("severity"), "title": f.get("title")} for f in findings[:8]]
    try:
        return llm.generate(_SUMMARY_PROMPT.format(
            verdict=verdict, score=score, findings=json.dumps(brief))).strip()
    except Exception:
        return "The written summary could not be generated for this run. The findings below are complete."


def _signed(report: Report, signing_key: str | None) -> Report:
    key = signing_key if signing_key is not None else os.environ.get("REPORT_SIGNING_KEY", "")
    return Report(**sign_report(report.model_dump(), private_key=key))


def run_deep_audit(prepared: Prepared, *, llm=None, summarize=None,
                   signing_key: str | None = None) -> Report:
    """The paid audit. Six lenses, then a skeptic that tries to kill every finding."""
    started = time.time()
    llm = llm or GeminiClient()
    lenses = lenses_for(prepared.inventory)

    lens_run = run_lenses(lenses=lenses, source=prepared.flat,
                          inventory=prepared.inventory, slither=prepared.slither, llm=llm)
    candidates = merge_findings(lens_run.findings + slither_as_findings(prepared.slither))
    before = len([f for f in candidates if f.get("severity") != "info"])
    kept = refute_findings(candidates, files=prepared.files, llm=llm)
    # Ids are stamped once, here, after the set is final. merge_findings does not
    # assign them, since it runs twice per audit and an id must not shift under a
    # reader who is looking at it.
    kept = assign_ids(merge_findings(kept))
    after = len([f for f in kept if f.get("severity") != "info"])
    refuted_share = 0.0 if before == 0 else (before - after) / before

    score = risk_score(kept)
    verdict = verdict_for(score, kept)
    degraded = len(lens_run.lenses_run) == 0
    confidence = "low" if degraded else confidence_for(
        source_verified=prepared.source_verified,
        lenses_run=len(lens_run.lenses_run), lenses_total=len(lenses),
        refuted_share=refuted_share,
    )
    summary = (summarize or (lambda **kw: _summary(llm, **kw)))(
        verdict=verdict, score=score, findings=kept)

    report = Report.build_v2(
        tier="audit", target_address=prepared.address, chain=prepared.chain,
        chain_id=prepared.chain_id, contract_name=prepared.contract_name,
        compiler=prepared.compiler, source_verified=prepared.source_verified,
        verdict=verdict, risk_score=score, confidence=confidence, summary=summary,
        findings=[_as_finding(f, prepared.files) for f in kept],
        privileged_powers=[PrivilegedPower(**p) for p in prepared.inventory["privileged_powers"]],
        coverage=Coverage(lenses_run=lens_run.lenses_run, lenses_skipped=lens_run.lenses_skipped,
                          dropped=lens_run.dropped, detectors_run=len(prepared.slither),
                          not_checked=_coverage_notes(prepared)),
        duration_ms=int((time.time() - started) * 1000),
    )
    if degraded:
        report.status = "degraded"
        report.reason = "every reasoning lens failed, this report is static analysis only"
    return _signed(report, signing_key)


def run_quick_scan(prepared: Prepared, *, llm=None, signing_key: str | None = None) -> Report:
    """The cheap tier. One triage pass, no lenses, no refutation, no exploit steps."""
    started = time.time()
    llm = llm or GeminiClient()
    skipped: list[dict] = []
    ran: list[str] = []
    try:
        data = _strip_json(llm.generate(_TRIAGE_PROMPT.format(
            slither=json.dumps(prepared.slither), source=prepared.flat)))
        raw = [{**f, "provenance": ["lens:triage"]}
               for f in data.get("findings", [])
               if ":" in (f.get("location") or "")][:5]
        summary = str(data.get("summary", ""))
        ran = ["triage"]
    except Exception as e:
        # The triage pass is the only reasoning in this tier, so when it fails the
        # buyer still gets the static analysis result, plainly marked as such.
        raw = slither_as_findings(prepared.slither)[:5]
        summary = "The reasoning pass was unavailable, so this is the static analysis result only."
        skipped = [{"lens": "triage", "reason": str(e)[:200]}]

    merged = assign_ids(merge_findings(raw))[:5]
    score = risk_score(merged)
    report = Report.build_v2(
        tier="scan", target_address=prepared.address, chain=prepared.chain,
        chain_id=prepared.chain_id, contract_name=prepared.contract_name,
        compiler=prepared.compiler, source_verified=prepared.source_verified,
        verdict=verdict_for(score, merged), risk_score=score,
        confidence="medium" if ran else "low", summary=summary,
        findings=[_as_finding(f, prepared.files) for f in merged],
        privileged_powers=[PrivilegedPower(**p) for p in prepared.inventory["privileged_powers"]],
        coverage=Coverage(lenses_run=ran, lenses_skipped=skipped,
                          detectors_run=len(prepared.slither),
                          not_checked=_coverage_notes(prepared, [
                              "the refutation pass, that is in the full audit",
                              "exploit scenarios, they are in the full audit",
                              "the five deeper lenses, they are in the full audit",
                          ])),
        duration_ms=int((time.time() - started) * 1000),
    )
    return _signed(report, signing_key)
