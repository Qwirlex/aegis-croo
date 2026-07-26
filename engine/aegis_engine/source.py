from __future__ import annotations
import json
import os
import httpx
from dataclasses import dataclass

from .chains import chain_or_raise


class ExplorerUnavailable(RuntimeError):
    """Raised when the block explorer or our own setup is at fault, not the
    caller's input. A later task maps this to a 503, ValueError stays a 4xx."""


@dataclass
class ResolvedSource:
    source: str
    address: str | None
    compiler: str
    chain: str | None = None
    contract_name: str = "unknown"
    verified: bool = False


def _require_verified_source(data: dict) -> None:
    if not data.get("SourceCode"):
        raise ValueError("no verified source for this address on this chain")


def _explorer_fetch(address: str, chain_id: int) -> dict:
    # BASESCAN_API_KEY is a historical name from when this only queried Base.
    # One key now serves all six chains through Etherscan V2, selected by
    # chainid below, so do not add a per chain key.
    key = os.environ.get("BASESCAN_API_KEY")
    if not key:
        raise ExplorerUnavailable("the explorer api key is not configured on the server")
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": str(chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    }
    try:
        r = httpx.get(url, params=params, timeout=30)
        r.raise_for_status()
        payload = r.json()
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        raise ExplorerUnavailable(
            f"could not reach the block explorer for chain {chain_id}, try again shortly"
        ) from e
    result = payload.get("result")
    # On error Etherscan returns status "0" and a string result, for example Invalid API Key.
    # This is a genuine answer from a working explorer, so it stays a ValueError.
    if payload.get("status") != "1" or not isinstance(result, list) or not result:
        raise ValueError(f"explorer lookup failed: {payload.get('message')}: {result}")
    entry = result[0]
    _require_verified_source(entry)
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
        _require_verified_source(data)
        raw_compiler = data.get("CompilerVersion")
        if isinstance(raw_compiler, str) and raw_compiler:
            comp = raw_compiler.lstrip("v").split("+")[0] or "auto"
        else:
            comp = "auto"
        return ResolvedSource(
            source=data["SourceCode"],
            address=address,
            compiler=comp,
            chain=c.name,
            contract_name=data.get("ContractName") or "unknown",
            verified=True,
        )
    raise ValueError("must provide source or address")
