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


from pathlib import Path

from aegis_engine import app as app_module
from aegis_engine.jobs import JobStore
from aegis_engine.source import ExplorerUnavailable
from aegis_engine.static_analysis import SlitherCompileError


def _wire(tmp_path: Path, *, prepare=None, deep=None, scan=None):
    """Point the module at a temp job store and report dir, inject fakes."""
    app_module._store = JobStore(dir=str(tmp_path / "jobs"), ttl_days=7)
    app_module._report_dir = tmp_path / "reports"
    app_module._prepare_fn = prepare or (lambda **kw: object())
    if deep:
        app_module._deep_fn = deep
    if scan:
        app_module._scan_fn = scan
    app_module._run_in_background = False  # run inline so the test is deterministic
    return TestClient(app)


class _FakeReport:
    def __init__(self, body):
        self._body = body

    def model_dump(self):
        return self._body


def test_create_job_returns_the_handle_and_writes_the_report_where_the_web_app_reads_it(tmp_path):
    client = _wire(
        tmp_path,
        prepare=lambda **kw: type("P", (), {"contract_name": "Vault", "compiler": "0.8.25",
                                            "chain": "base"})(),
        deep=lambda prepared, **kw: _FakeReport({"verdict": "caution", "risk_score": 20}),
    )
    r = client.post("/audit/jobs", json={"address": "0xabc", "chain": "base"})
    assert r.status_code == 200
    body = r.json()
    assert len(body["job_id"]) == 12
    assert body["target"]["contract_name"] == "Vault"

    got = client.get(f"/audit/jobs/{body['job_id']}").json()
    assert got["state"] == "done"
    assert got["report"]["verdict"] == "caution"
    assert (tmp_path / "reports" / f"{body['job_id']}.json").exists()


def test_unsupported_chain_is_a_400_and_creates_no_job(tmp_path):
    def prepare(**kw):
        raise ValueError("chain not supported, use one of base, ethereum")

    client = _wire(tmp_path, prepare=prepare)
    r = client.post("/audit/jobs", json={"address": "0xabc", "chain": "solana"})
    assert r.status_code == 400
    assert "chain not supported" in r.json()["detail"]
    assert list((tmp_path / "jobs").glob("*.json")) == []


def test_unverified_source_is_a_422(tmp_path):
    def prepare(**kw):
        raise ValueError("no verified source for this address on this chain")

    client = _wire(tmp_path, prepare=prepare)
    assert client.post("/audit/jobs", json={"address": "0xabc"}).status_code == 422


def test_a_compile_failure_is_a_422(tmp_path):
    def prepare(**kw):
        raise SlitherCompileError("could not compile with solc 0.4.1")

    client = _wire(tmp_path, prepare=prepare)
    r = client.post("/audit/jobs", json={"address": "0xabc"})
    assert r.status_code == 422
    assert "could not compile" in r.json()["detail"]


def test_an_explorer_outage_is_a_503_not_a_client_error(tmp_path):
    def prepare(**kw):
        raise ExplorerUnavailable("could not reach the block explorer for chain 8453")

    client = _wire(tmp_path, prepare=prepare)
    assert client.post("/audit/jobs", json={"address": "0xabc"}).status_code == 503


def test_any_other_upstream_failure_is_a_503(tmp_path):
    def prepare(**kw):
        raise RuntimeError("something else broke")

    client = _wire(tmp_path, prepare=prepare)
    assert client.post("/audit/jobs", json={"address": "0xabc"}).status_code == 503


def test_a_job_whose_analysis_throws_ends_failed_with_a_retry(tmp_path):
    def deep(prepared, **kw):
        raise RuntimeError("model down")

    client = _wire(tmp_path, deep=deep)
    job_id = client.post("/audit/jobs", json={"address": "0xabc"}).json()["job_id"]
    got = client.get(f"/audit/jobs/{job_id}").json()
    assert got["state"] == "failed"
    assert got["retries_left"] == 1

    assert client.post(f"/audit/jobs/{job_id}/retry").status_code == 200
    assert client.get(f"/audit/jobs/{job_id}").json()["retries_left"] == 0
    assert client.post(f"/audit/jobs/{job_id}/retry").status_code == 409


def test_retrying_an_unknown_job_is_a_404(tmp_path):
    client = _wire(tmp_path)
    assert client.post("/audit/jobs/deadbeefdead/retry").status_code == 404


def test_unknown_job_is_a_404(tmp_path):
    client = _wire(tmp_path)
    assert client.get("/audit/jobs/deadbeefdead").status_code == 404


def test_scan_returns_the_report_inline(tmp_path):
    client = _wire(tmp_path, scan=lambda prepared, **kw: _FakeReport({"tier": "scan",
                                                                     "risk_score": 5}))
    r = client.post("/scan", json={"address": "0xabc", "chain": "base"})
    assert r.status_code == 200
    assert r.json()["tier"] == "scan"


def test_a_scan_that_throws_is_a_503_so_nothing_settles(tmp_path):
    def scan(prepared, **kw):
        raise RuntimeError("model down")

    client = _wire(tmp_path, scan=scan)
    assert client.post("/scan", json={"address": "0xabc"}).status_code == 503
