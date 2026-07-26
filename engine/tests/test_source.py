import httpx
import pytest
from aegis_engine.source import resolve_source


def test_passthrough_when_source_given():
    res = resolve_source(source="contract C {}", address=None, fetch=None)
    assert res.source == "contract C {}"
    assert res.address is None


def test_fetch_from_basescan_defaults_to_base_chain_id(monkeypatch):
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
