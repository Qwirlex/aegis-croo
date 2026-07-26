from __future__ import annotations
import os
import httpx
from dataclasses import dataclass

from .chains import chain_or_raise


@dataclass
class ResolvedSource:
    source: str
    address: str | None
    compiler: str
    chain: str | None = None
    contract_name: str = "unknown"
    verified: bool = False


def _explorer_fetch(address: str, chain_id: int) -> dict:
    key = os.environ["BASESCAN_API_KEY"]
    # Etherscan V2 is one endpoint and one key for every chain, selected by chainid.
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": str(chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    }
    r = httpx.get(url, params=params, timeout=30)
    r.raise_for_status()
    payload = r.json()
    result = payload.get("result")
    # On error Etherscan returns status "0" and a string result, for example Invalid API Key.
    if payload.get("status") != "1" or not isinstance(result, list) or not result:
        raise ValueError(f"explorer lookup failed: {payload.get('message')}: {result}")
    entry = result[0]
    if not entry.get("SourceCode"):
        raise ValueError("no verified source for this address on this chain")
    return entry


def resolve_source(
    *, source: str | None, address: str | None, chain: str = "base", fetch=None
) -> ResolvedSource:
    if source:
        return ResolvedSource(
            source=source, address=None, compiler="auto", chain=None,
            contract_name="unknown", verified=False,
        )
    if address:
        c = chain_or_raise(chain)
        fetch = fetch or _explorer_fetch
        data = fetch(address, c.chain_id)
        if not data.get("SourceCode"):
            raise ValueError("no verified source for this address on this chain")
        comp = (data.get("CompilerVersion") or "auto").lstrip("v").split("+")[0]
        return ResolvedSource(
            source=data["SourceCode"],
            address=address,
            compiler=comp or "auto",
            chain=c.name,
            contract_name=data.get("ContractName") or "unknown",
            verified=True,
        )
    raise ValueError("must provide source or address")
