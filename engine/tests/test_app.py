from fastapi.testclient import TestClient
from aegis_engine.app import app, _set_audit


def test_audit_endpoint(monkeypatch):
    from aegis_engine.models import Report, Target
    _set_audit(lambda *, source, address: Report(
        target=Target(address=address, network="base", compiler="0.8.25"),
        status="ok", risk_score=0, summary="s", findings=[]))
    c = TestClient(app)
    r = c.post("/audit", json={"source": "contract C{}"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_endpoint():
    from fastapi.testclient import TestClient
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True
