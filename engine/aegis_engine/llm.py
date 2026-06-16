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
STYLE: write summary, title, description and recommendation as plain direct English a non expert can read.
Do NOT use em dashes, en dashes or hyphens. Do NOT use parentheses or any bracketed aside.
Do NOT put "()" after a function name; write the bare name. Avoid hyphenated jargon such as
"checks-effects-interactions"; say it in plain words instead, for example "set the balance to zero before
the external call". Keep sentences short. The location and source fields are the only place identifiers
may appear, do not restyle them.
SOURCE:
{source}
SLITHER:
{slither}
"""


class GeminiClient:
    """Gemini via Vertex AI, authenticated with Application Default Credentials (ADC).

    No API key in code: ADC is picked up from the environment (set up via
    `gcloud auth application-default login`). Reads the GCP project/location from env.
    """

    def __init__(self):
        from google import genai

        project = os.environ["GOOGLE_CLOUD_PROJECT"]
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        self._client = genai.Client(vertexai=True, project=project, location=location)
        self._model = os.environ.get("AEGIS_LLM_MODEL", "gemini-3.5-flash")

    def generate(self, prompt: str) -> str:
        resp = self._client.models.generate_content(model=self._model, contents=prompt)
        return resp.text


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
