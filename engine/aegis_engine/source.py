from __future__ import annotations
import os
import httpx
from dataclasses import dataclass


@dataclass
class ResolvedSource:
    source: str
    address: str | None
    compiler: str


def _basescan_fetch(address: str) -> dict:
    key = os.environ["BASESCAN_API_KEY"]
    url = "https://api.basescan.org/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    }
    r = httpx.get(url, params=params, timeout=30)
    r.raise_for_status()
    result = r.json()["result"][0]
    if not result.get("SourceCode"):
        raise ValueError("no verified source on Basescan")
    return result


def resolve_source(
    *, source: str | None, address: str | None, fetch=None
) -> ResolvedSource:
    if source:
        return ResolvedSource(source=source, address=None, compiler="auto")
    if address:
        fetch = fetch or _basescan_fetch
        data = fetch(address)
        comp = data.get("CompilerVersion", "auto").lstrip("v").split("+")[0]
        return ResolvedSource(
            source=data["SourceCode"], address=address, compiler=comp or "auto"
        )
    raise ValueError("must provide source or address")
