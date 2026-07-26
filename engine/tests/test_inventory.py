from aegis_engine.inventory import build_inventory

TOKEN = """
pragma solidity ^0.8.20;
contract Tok {
    address public owner;
    mapping(address => bool) public blacklist;
    function totalSupply() public view returns (uint256) { return 1; }
    function transfer(address to, uint256 amount) public returns (bool) { return true; }
    function approve(address s, uint256 a) public returns (bool) { return true; }
    function mint(address to, uint256 amount) external onlyOwner { }
    function setFee(uint256 f) external onlyOwner { }
    function pause() external onlyOwner { }
    function _internalThing() internal { }
    function _internalGated() internal onlyOwner { }
}
"""

VAULT = """
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 a) external payable { }
    function upgradeTo(address impl) external onlyAdmin { }
}
"""


def test_functions_are_listed_with_visibility_and_modifiers():
    inv = build_inventory({"Tok.sol": TOKEN})
    names = [f["name"] for f in inv["functions"]]
    assert "mint" in names and "transfer" in names
    mint = next(f for f in inv["functions"] if f["name"] == "mint")
    assert mint["visibility"] == "external"
    assert "onlyOwner" in mint["modifiers"]
    assert mint["file"] == "Tok.sol"


def test_erc20_is_detected_from_the_standard_signature_set():
    assert build_inventory({"Tok.sol": TOKEN})["is_erc20"] is True
    assert build_inventory({"Vault.sol": VAULT})["is_erc20"] is False


def test_proxy_shape_is_detected():
    assert build_inventory({"Vault.sol": VAULT})["is_upgradeable"] is True
    assert build_inventory({"Tok.sol": TOKEN})["is_upgradeable"] is False


def test_privileged_powers_are_classified_and_fund_moving_ones_flagged():
    powers = build_inventory({"Tok.sol": TOKEN})["privileged_powers"]
    by_fn = {p["function"]: p for p in powers}
    assert by_fn["mint"]["capability"] == "mint new supply"
    assert by_fn["mint"]["can_move_funds"] is True
    assert by_fn["pause"]["capability"] == "pause activity"
    assert by_fn["setFee"]["capability"] == "change fees"
    assert "_internalThing" not in by_fn
    # Genuinely gated but internal: the visibility filter, not the gate check,
    # must be what excludes it. Without _internalGated, deleting the visibility
    # filter entirely would still pass this test.
    assert "_internalGated" not in by_fn


def test_no_gated_functions_means_no_powers():
    powers = build_inventory({"P.sol": "contract P { function ping() external {} }"})["privileged_powers"]
    assert powers == []


def test_modifier_with_arguments_still_flags_the_power():
    # onlyRole(ADMIN_ROLE) is the standard OpenZeppelin AccessControl gate and is
    # at least as common as the plain onlyOwner form used in the other fixtures.
    src = """
    contract C {
        function setAdmin(address a) external onlyRole(ADMIN_ROLE) { }
    }
    """
    powers = build_inventory({"C.sol": src})["privileged_powers"]
    assert [p["function"] for p in powers] == ["setAdmin"]


def test_multiline_function_header_is_still_matched():
    src = """
    contract C {
        function mint(
            address to,
            uint256 amount
        )
            external
            onlyOwner
        {
        }
    }
    """
    inv = build_inventory({"C.sol": src})
    names = [f["name"] for f in inv["functions"]]
    assert names == ["mint"]
    assert inv["privileged_powers"][0]["capability"] == "mint new supply"


def test_commented_out_function_is_not_inventoried():
    src = """
    contract C {
        // this function does nothing special
        /* function fakeOne() external onlyOwner { } */
        function real() external onlyOwner { }
    }
    """
    inv = build_inventory({"C.sol": src})
    names = [f["name"] for f in inv["functions"]]
    assert names == ["real"]
    assert [p["function"] for p in inv["privileged_powers"]] == ["real"]


def test_transfer_and_approve_without_total_supply_is_not_erc20():
    src = """
    contract Lookalike {
        function transfer(address to, uint256 amount) public returns (bool) { return true; }
        function approve(address s, uint256 a) public returns (bool) { return true; }
    }
    """
    assert build_inventory({"L.sol": src})["is_erc20"] is False


def test_proxy_marker_word_inside_a_comment_does_not_flag_upgradeable():
    src = """
    contract Plain {
        // this contract used to support upgradeTo before we removed the proxy
        function ping() external { }
    }
    """
    assert build_inventory({"P.sol": src})["is_upgradeable"] is False
