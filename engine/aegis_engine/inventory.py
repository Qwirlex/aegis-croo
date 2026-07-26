from __future__ import annotations

import re

# One Solidity function header. Solidity is not a regular language, so this is a
# deliberately shallow parse: it feeds the reasoning lenses and the powers table,
# it is never used to decide whether code compiles. Slither remains the source of
# truth for anything semantic.
_FN = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*(?P<tail>[^{;]*)",
    re.MULTILINE,
)
_VISIBILITY = ("external", "public", "internal", "private")
_MUTABILITY = ("view", "pure", "payable")
_KNOWN_KEYWORDS = set(_VISIBILITY) | set(_MUTABILITY) | {"virtual", "override", "returns"}

_ERC20_REQUIRED = {"transfer", "approve", "totalSupply"}
_PROXY_MARKERS = ("upgradeTo", "delegatecall", "implementation", "initializer")

# Modifier names that mean "only a privileged caller". Matched case insensitively
# on a substring so onlyOwner, onlyAdmin, onlyRole and ownerOnly all count.
_GATE_HINTS = ("only", "auth", "restricted", "admin", "governance")

# Function name hints mapped to a plain capability and whether it can move or
# freeze user value. Order matters, the first hit wins.
_CAPABILITIES: list[tuple[tuple[str, ...], str, bool]] = [
    (("mint",), "mint new supply", True),
    (("burnfrom", "burn"), "burn balances", True),
    (("blacklist", "blocklist", "denylist", "freeze"), "block specific holders", True),
    (("withdraw", "sweep", "rescue", "drain", "claimtokens"), "move funds out", True),
    (("pause", "unpause", "halt"), "pause activity", True),
    (("upgradeto", "upgrade", "setimplementation"), "replace the code", True),
    (("setfee", "settax", "fee", "tax"), "change fees", False),
    (("settreasury", "setowner", "transferownership", "renounce"), "change who is in control", False),
    (("setrouter", "setpair", "setoracle", "setprice"), "repoint a critical address", True),
]


def _strip_comments(src: str) -> str:
    """Blank out // line comments and /* block */ comments, string aware.

    Without this, a commented out ``function`` header reads as a real one and
    a proxy marker word mentioned only in prose (for example "this contract
    does not use delegatecall") flips is_upgradeable. Newlines inside removed
    comments are kept so line numbers computed against the result still match
    the original file. String literals are tracked so a URL like
    "https://example.com" inside a require message is not mistaken for the
    start of a line comment.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i])
                    out.append(src[i + 1])
                    i += 2
                    continue
                out.append(src[i])
                i += 1
            if i < n:
                out.append(src[i])
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _classify(name: str) -> tuple[str, bool]:
    low = name.lower()
    for hints, capability, moves in _CAPABILITIES:
        if any(h in low for h in hints):
            return capability, moves
    return "change protected settings", False


def _modifiers(tail: str) -> list[str]:
    out = []
    # Cut anything from returns onwards, its contents are types not modifiers.
    head = tail.split("returns")[0]
    for token in re.findall(r"[A-Za-z_]\w*", head):
        if token in _KNOWN_KEYWORDS:
            continue
        out.append(token)
    return out


def build_inventory(files: dict[str, str]) -> dict:
    functions: list[dict] = []
    for path, content in files.items():
        code = _strip_comments(content)
        for m in _FN.finditer(code):
            tail = m.group("tail") or ""
            vis = next((v for v in _VISIBILITY if re.search(rf"\b{v}\b", tail)), "public")
            mut = next((v for v in _MUTABILITY if re.search(rf"\b{v}\b", tail)), "nonpayable")
            line = code[: m.start()].count("\n") + 1
            functions.append({
                "name": m.group("name"),
                "file": path,
                "line": line,
                "visibility": vis,
                "mutability": mut,
                "modifiers": _modifiers(tail),
                "args": (m.group("args") or "").strip(),
            })

    names = {f["name"] for f in functions}
    joined = "\n".join(_strip_comments(c) for c in files.values())
    is_erc20 = _ERC20_REQUIRED.issubset(names)
    is_upgradeable = any(marker.lower() in joined.lower() for marker in _PROXY_MARKERS)

    powers: list[dict] = []
    for f in functions:
        if f["visibility"] not in ("external", "public"):
            continue
        gates = [mod for mod in f["modifiers"] if any(h in mod.lower() for h in _GATE_HINTS)]
        if not gates:
            continue
        capability, moves = _classify(f["name"])
        powers.append({
            "function": f["name"],
            "file": f["file"],
            "line": f["line"],
            "visibility": f["visibility"],
            "modifiers": gates,
            "capability": capability,
            "can_move_funds": moves,
        })

    return {
        "functions": functions,
        "is_erc20": is_erc20,
        "is_upgradeable": is_upgradeable,
        "privileged_powers": powers,
    }
