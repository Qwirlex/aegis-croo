import json

import httpx
import pytest

from aegis_engine.source import ExplorerUnavailable, _explorer_fetch, resolve_source


def test_passthrough_when_source_given():
    res = resolve_source(source="contract C {}", address=None, fetch=None)
    assert res.source == "contract C {}"
    assert res.address is None


def test_fetch_from_basescan_defaults_to_base_chain_id():
    def fake_fetch(addr, chain_id):
        assert chain_id == 8453
        return {"SourceCode": "contract V {}", "CompilerVersion": "v0.8.25+commit"}
    res = resolve_source(source=None, address="0xabc", fetch=fake_fetch)
    assert res.source == "contract V {}"
    assert res.compiler.startswith("0.8.25")


def test_error_when_neither():
    try:
        resolve_source(source=None, address=None, fetch=None)
        assert False, "should raise"
    except ValueError:
        pass


def test_address_fetch_passes_the_chain_id_and_reads_the_contract_name():
    seen = {}

    def fake_fetch(address, chain_id, **_):
        seen["address"] = address
        seen["chain_id"] = chain_id
        return {"SourceCode": "contract A {}", "CompilerVersion": "v0.8.20+commit.a1b2",
                "ContractName": "A"}

    rs = resolve_source(source=None, address="0xabc", chain="polygon", fetch=fake_fetch)
    assert seen == {"address": "0xabc", "chain_id": 137}
    assert rs.compiler == "0.8.20"
    assert rs.contract_name == "A"
    assert rs.chain == "polygon"
    assert rs.verified is True


def test_raw_source_needs_no_chain_and_is_not_verified():
    rs = resolve_source(source="contract B {}", address=None)
    assert rs.verified is False
    assert rs.chain is None
    assert rs.contract_name == "unknown"


def test_unsupported_chain_is_rejected_before_any_network_call():
    def fetch_must_not_run(*_a, **_k):
        raise AssertionError("must not fetch")

    with pytest.raises(ValueError) as e:
        resolve_source(source=None, address="0xabc", chain="solana", fetch=fetch_must_not_run)
    assert "chain not supported" in str(e.value)


def test_missing_verified_source_says_so_plainly():
    def fake_fetch(*_a, **_k):
        return {"SourceCode": "", "ContractName": ""}

    with pytest.raises(ValueError) as e:
        resolve_source(source=None, address="0xabc", chain="base", fetch=fake_fetch)
    assert "no verified source" in str(e.value)


def test_a_non_string_compiler_version_falls_back_to_auto():
    def fake_fetch(*_a, **_k):
        return {"SourceCode": "contract Q {}", "CompilerVersion": 12345, "ContractName": "Q"}

    rs = resolve_source(source=None, address="0xabc", chain="base", fetch=fake_fetch)
    assert rs.compiler == "auto"


def _mock_get(handler):
    """Route httpx.get through a MockTransport so _explorer_fetch sees a real
    httpx.Response end to end, not a hand rolled stand in."""
    def fake_get(url, params=None, timeout=None):
        transport = httpx.MockTransport(handler)
        with httpx.Client(transport=transport) as client:
            return client.get(url, params=params, timeout=timeout)
    return fake_get


def test_explorer_fetch_without_an_api_key_says_so_plainly(monkeypatch):
    monkeypatch.delenv("BASESCAN_API_KEY", raising=False)

    with pytest.raises(ExplorerUnavailable) as e:
        _explorer_fetch("0xabc", 8453)
    assert "explorer api key is not configured" in str(e.value)


def test_explorer_fetch_reports_a_status_zero_answer_as_a_value_error(monkeypatch):
    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")

    def handler(request):
        return httpx.Response(
            200, json={"status": "0", "message": "NOTOK", "result": "Invalid API Key"}
        )

    monkeypatch.setattr(httpx, "get", _mock_get(handler))

    with pytest.raises(ValueError) as e:
        _explorer_fetch("0xabc", 8453)
    assert "explorer lookup failed" in str(e.value)


def test_explorer_fetch_reports_no_source_when_explorer_confirms_unverified(monkeypatch):
    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")

    def handler(request):
        return httpx.Response(
            200,
            json={"status": "1", "message": "OK",
                  "result": [{"SourceCode": "", "ContractName": ""}]},
        )

    monkeypatch.setattr(httpx, "get", _mock_get(handler))

    with pytest.raises(ValueError) as e:
        _explorer_fetch("0xabc", 8453)
    assert "no verified source" in str(e.value)


def test_explorer_fetch_wraps_a_non_json_response_as_explorer_unavailable(monkeypatch):
    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")

    def handler(request):
        return httpx.Response(200, content=b"not json at all")

    monkeypatch.setattr(httpx, "get", _mock_get(handler))

    with pytest.raises(ExplorerUnavailable) as e:
        _explorer_fetch("0xabc", 8453)
    assert "could not reach the block explorer for chain 8453" in str(e.value)
    assert isinstance(e.value.__cause__, json.JSONDecodeError)


def test_explorer_fetch_wraps_an_http_error_status_as_explorer_unavailable(monkeypatch):
    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")

    def handler(request):
        return httpx.Response(500, text="internal server error")

    monkeypatch.setattr(httpx, "get", _mock_get(handler))

    with pytest.raises(ExplorerUnavailable) as e:
        _explorer_fetch("0xabc", 8453)
    assert "could not reach the block explorer for chain 8453" in str(e.value)
    assert isinstance(e.value.__cause__, httpx.HTTPStatusError)


def test_explorer_fetch_happy_path_returns_the_entry(monkeypatch):
    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")

    def handler(request):
        return httpx.Response(
            200,
            json={
                "status": "1",
                "message": "OK",
                "result": [{
                    "SourceCode": "contract E {}",
                    "CompilerVersion": "v0.8.19+commit.abc123",
                    "ContractName": "E",
                }],
            },
        )

    monkeypatch.setattr(httpx, "get", _mock_get(handler))

    entry = _explorer_fetch("0xdef", 8453)
    assert entry["SourceCode"] == "contract E {}"
    assert entry["ContractName"] == "E"
