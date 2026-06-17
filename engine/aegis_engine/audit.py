from __future__ import annotations

from .source import resolve_source
from .static_analysis import run_slither, flatten_source
from .llm import reason_findings
from .models import Report, Finding


def audit(
    *,
    source: str | None,
    address: str | None,
    slither_fn=run_slither,
    reason_fn=reason_findings,
) -> Report:
    """Orchestrate source resolution, static analysis, and LLM reasoning.

    Implements fallback paths:
    - Source/compile error → cannot_analyze status
    - LLM failure → Slither-only report with low confidence
    - Success → full report with LLM-enhanced findings
    """
    try:
        rs = resolve_source(source=source, address=address)
    except Exception as e:
        return Report.cannot_analyze(
            target_address=address, network="base", reason=str(e)
        )

    # Determine compiler version
    compiler = "0.8.25" if rs.compiler in ("auto", "") else rs.compiler

    # Run Slither. When we have an address, let crytic-compile's Etherscan
    # platform fetch and lay out the (possibly multi-file) project itself.
    try:
        slither = slither_fn(rs.source, solc_version=compiler, address=address)
    except Exception as e:
        return Report.cannot_analyze(
            target_address=address, network="base", reason=str(e)
        )

    # Flatten multi-file / standard-json blobs into readable Solidity so the LLM
    # reasons over real code, not an escaped JSON string. Plain sources pass through.
    llm_source = flatten_source(rs.source)

    # Try LLM reasoning
    try:
        reasoned = reason_fn(source=llm_source, slither=slither)
    except Exception:
        # LLM failed → fallback to Slither-only, low confidence
        fb = [
            Finding(
                id=f"F-{i}",
                severity="medium",
                title=f["check"],
                location=f"{f.get('file', 'Target.sol')}:{f['line']}",
                source=f"slither:{f['check']}",
                description=f["description"],
                recommendation="review",
            )
            for i, f in enumerate(slither, 1)
        ]
        return Report.build(
            target_address=address,
            network="base",
            compiler=compiler,
            summary="Slither-only (LLM unavailable)",
            findings=fb,
            confidence="low",
        )

    # Success path
    return Report.build(
        target_address=address,
        network="base",
        compiler=compiler,
        summary=reasoned.summary,
        findings=reasoned.findings,
        confidence=reasoned.confidence,
    )
