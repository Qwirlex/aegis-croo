import json
from aegis_engine.llm import reason_findings


class FakeLLM:
    def __init__(self, payload):
        self._p = payload

    def generate(self, prompt: str) -> str:
        return json.dumps(self._p)


def test_keeps_grounded_drops_ungrounded():
    payload = {
        "summary": "ok",
        "findings": [
            {
                "severity": "critical",
                "title": "reentrancy",
                "location": "Target.sol:8",
                "source": "slither:reentrancy-eth",
                "description": "d",
                "recommendation": "r",
            },
            {
                "severity": "high",
                "title": "made up",
                "location": "",
                "source": "llm",
                "description": "d",
                "recommendation": "r",
            },  # no location -> dropped
        ],
    }
    res = reason_findings(source="x", slither=[], llm=FakeLLM(payload))
    titles = [f.title for f in res.findings]
    assert "reentrancy" in titles
    assert "made up" not in titles
    assert res.summary == "ok"
