from __future__ import annotations

import json
import os

from eth_hash.auto import keccak

# The three fields that describe the signature cannot be inside what is signed.
_EXCLUDED = ("report_hash", "report_signature", "signer")


def canonical_json(report: dict) -> str:
    """One stable text form of a report, so the same content always hashes alike.

    Keys are sorted and separators are tight, and the signature fields are left
    out, since they cannot describe a document they are part of.
    """
    body = {k: v for k, v in report.items() if k not in _EXCLUDED}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def report_hash(report: dict) -> str:
    return "0x" + keccak(canonical_json(report).encode("utf-8")).hex()


def sign_report(report: dict, *, private_key: str | None = None) -> dict:
    """Attach the hash, an Ethereum style signature and the signer address.

    A buyer verifies it with any standard message tool by recovering the signer
    from the hash, so there is no public key file to host or rotate. Without a
    configured key the report still carries its hash, so a modified file is
    still detectable, and the empty signature says plainly it was unsigned.
    """
    key = private_key if private_key is not None else os.environ.get("REPORT_SIGNING_KEY", "")
    h = report_hash(report)
    out = {**report, "report_hash": h, "report_signature": "", "signer": ""}
    if not key:
        return out
    from eth_account import Account
    from eth_account.messages import encode_defunct

    acct = Account.from_key(key)
    signed = Account.sign_message(encode_defunct(hexstr=h), private_key=key)
    signature = signed.signature.hex()
    out["report_signature"] = signature if signature.startswith("0x") else "0x" + signature
    out["signer"] = acct.address
    return out
