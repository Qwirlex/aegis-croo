from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Chain:
    name: str
    chain_id: int
    crytic_prefix: str
    explorer: str


# The crytic prefixes are the keys of crytic_compile.platform.etherscan
# SUPPORTED_NETWORK_V2, verified against crytic-compile 0.3.11. One Etherscan V2
# key serves every chain, so nothing here needs a per chain secret.
CHAINS: dict[str, Chain] = {
    "base": Chain("base", 8453, "base", "basescan.org"),
    "ethereum": Chain("ethereum", 1, "mainnet", "etherscan.io"),
    "arbitrum": Chain("arbitrum", 42161, "arbi", "arbiscan.io"),
    "optimism": Chain("optimism", 10, "optim", "optimistic.etherscan.io"),
    "polygon": Chain("polygon", 137, "poly", "polygonscan.com"),
    "bsc": Chain("bsc", 56, "bsc", "bscscan.com"),
}


def chain_names() -> list[str]:
    return list(CHAINS)


def chain_or_raise(name: str) -> Chain:
    c = CHAINS.get((name or "").strip().lower())
    if c is None:
        raise ValueError(f"chain not supported, supported {', '.join(CHAINS)}")
    return c
