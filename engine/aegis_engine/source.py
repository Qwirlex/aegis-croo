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
    # Etherscan V2 unified API: one key works across chains, Base is chainid 8453.
    # The old api.basescan.org v1 path now rejects calls that omit chainid.
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": "8453",
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    }
    r = httpx.get(url, params=params, timeout=30)
    r.raise_for_status()
    payload = r.json()
    result = payload.get("result")
    # On error Etherscan returns status "0" and a string result, e.g. "Invalid API Key".
    if payload.get("status") != "1" or not isinstance(result, list) or not result:
        raise ValueError(f"Basescan lookup failed: {payload.get('message')}: {result}")
    entry = result[0]
    if not entry.get("SourceCode"):
        raise ValueError("no verified source on Basescan")
    return entry


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
