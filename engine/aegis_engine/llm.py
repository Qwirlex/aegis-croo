from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .models import Finding


@dataclass
class ReasonResult:
    summary: str
    findings: list[Finding]
    confidence: str


PROMPT = """You are a Solidity security auditor. Given the contract SOURCE and SLITHER findings (JSON),
return STRICT JSON: {{"summary": str, "findings": [{{"severity": one of critical|high|medium|low|info,
"title": str, "location": "File.sol:LINE", "source": "slither:<check>" or "llm",
"description": str, "recommendation": str}}]}}.
RULES: every finding MUST have a concrete location "File.sol:LINE". Do NOT invent issues without a line.
Merge/dedupe slither findings; you may add real logic bugs slither missed.
SOURCE:
{source}
SLITHER:
{slither}
"""


class GeminiClient:
    def __init__(self):
        import google.generativeai as genai

        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        self._m = genai.GenerativeModel("gemini-2.0-flash")

    def generate(self, prompt: str) -> str:
        return self._m.generate_content(prompt).text


def _strip_json(text: str) -> dict:
    t = (
        text.strip()
        .removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )
    return json.loads(t)


def reason_findings(
    *, source: str, slither: list[dict], llm=None
) -> ReasonResult:
    llm = llm or GeminiClient()
    raw = llm.generate(PROMPT.format(source=source, slither=json.dumps(slither)))
    data = _strip_json(raw)
    findings = []
    for i, f in enumerate(data.get("findings", []), 1):
        loc = (f.get("location") or "").strip()
        if not loc or ":" not in loc:  # grounding rule
            continue
        findings.append(
            Finding(
                id=f"F-{i}",
                severity=f["severity"],
                title=f["title"],
                location=loc,
                source=f.get("source", "llm"),
                description=f.get("description", ""),
                recommendation=f.get("recommendation", ""),
            )
        )
    return ReasonResult(
        summary=data.get("summary", ""), findings=findings, confidence="high"
    )
