from aegis_engine.integrity import canonical_json, report_hash, sign_report

# A throwaway test key, the first key of the standard hardhat mnemonic. It holds
# nothing and signs nothing but this test.
TEST_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

REPORT = {"b": 2, "a": 1, "report_hash": "", "report_signature": "", "signer": ""}


def test_canonical_json_is_sorted_and_excludes_the_integrity_fields():
    assert canonical_json(REPORT) == '{"a":1,"b":2}'


def test_hash_is_stable_and_key_order_does_not_matter():
    assert report_hash({"a": 1, "b": 2}) == report_hash({"b": 2, "a": 1})
    assert report_hash({"a": 1}).startswith("0x")
    assert len(report_hash({"a": 1})) == 66


def test_a_changed_field_changes_the_hash():
    assert report_hash({"summary": "clean"}) != report_hash({"summary": "clean "})


def test_signing_fills_hash_signature_and_signer_and_is_recoverable():
    out = sign_report({"a": 1}, private_key=TEST_KEY)
    assert out["report_hash"] == report_hash({"a": 1})
    assert out["report_signature"].startswith("0x")
    assert out["signer"].startswith("0x") and len(out["signer"]) == 42

    from eth_account import Account
    from eth_account.messages import encode_defunct
    recovered = Account.recover_message(encode_defunct(hexstr=out["report_hash"]),
                                        signature=out["report_signature"])
    assert recovered == out["signer"]


def test_signing_does_not_hash_its_own_signature_fields():
    once = sign_report({"a": 1}, private_key=TEST_KEY)
    twice = sign_report(once, private_key=TEST_KEY)
    assert twice["report_hash"] == once["report_hash"]
    assert twice["report_signature"] == once["report_signature"]


def test_no_key_configured_still_fills_the_hash_and_says_unsigned():
    out = sign_report({"a": 1}, private_key="")
    assert out["report_hash"].startswith("0x")
    assert out["report_signature"] == ""
    assert out["signer"] == ""


def test_a_tampered_report_no_longer_matches_its_signature():
    from eth_account import Account
    from eth_account.messages import encode_defunct

    signed = sign_report({"verdict": "looks_ok"}, private_key=TEST_KEY)
    tampered = {**signed, "verdict": "critical_risk"}
    assert report_hash(tampered) != tampered["report_hash"]
    recovered = Account.recover_message(encode_defunct(hexstr=report_hash(tampered)),
                                        signature=tampered["report_signature"])
    assert recovered != tampered["signer"]
