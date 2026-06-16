import httpx
from aegis_engine.source import resolve_source


def test_passthrough_when_source_given():
    res = resolve_source(source="contract C {}", address=None, fetch=None)
    assert res.source == "contract C {}"
    assert res.address is None


def test_fetch_from_basescan(monkeypatch):
    def fake_fetch(addr):
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
