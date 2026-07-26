import pytest
from crytic_compile.platform.etherscan import SUPPORTED_NETWORK_V2

from aegis_engine.chains import CHAINS, chain_or_raise, chain_names


def test_six_chains_supported():
    assert chain_names() == ["base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"]


def test_chain_carries_id_and_crytic_prefix():
    c = chain_or_raise("ethereum")
    assert c.chain_id == 1
    assert c.crytic_prefix == "mainnet"
    assert c.explorer == "etherscan.io"


def test_base_is_the_default_shape():
    c = chain_or_raise("base")
    assert (c.chain_id, c.crytic_prefix) == (8453, "base")


def test_unknown_chain_raises_with_the_supported_list():
    with pytest.raises(ValueError) as e:
        chain_or_raise("solana")
    assert "base" in str(e.value)


def test_lookup_is_case_insensitive():
    assert chain_or_raise("BASE").chain_id == 8453


def test_crytic_prefixes_match_installed_package():
    for chain in CHAINS.values():
        assert chain.crytic_prefix in SUPPORTED_NETWORK_V2
        upstream_chain_id, _ = SUPPORTED_NETWORK_V2[chain.crytic_prefix]
        assert upstream_chain_id == str(chain.chain_id)


def test_lookup_strips_whitespace():
    assert chain_or_raise(" base ").chain_id == 8453


def test_empty_name_raises_plainly():
    with pytest.raises(ValueError) as e:
        chain_or_raise("")
    assert "base" in str(e.value)
