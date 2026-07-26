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
# "returns" is not listed here: the tail is already cut at the literal "returns"
# in _modifiers before this set is consulted, so a token spelled exactly
# "returns" can never reach it. Listing it again would be dead code.
_KNOWN_KEYWORDS = set(_VISIBILITY) | set(_MUTABILITY) | {"virtual", "override"}

# One modifier invocation: a name, optionally followed by a non-nested argument
# list. Matching the argument list as part of the same token, rather than
# scanning every identifier in the tail, is what keeps onlyRole(ADMIN_ROLE)
# from being tokenized as two separate "modifiers", onlyRole and ADMIN_ROLE.
_MODIFIER_INVOCATION = re.compile(r"(?P<name>[A-Za-z_]\w*)(?:\s*\((?:[^()]*)\))?")

_ERC20_REQUIRED = {"transfer", "approve", "totalSupply"}

# Function names that are themselves strong, structured evidence of an
# upgradeable / proxy shape. Matched by exact name against the parsed function
# list, not by searching for the word in raw text, so a getter like
# getImplementationDetails cannot flip this the way a bare "implementation"
# text search would.
_UPGRADE_FUNCTION_NAMES = {
    "upgradeto", "upgradetoandcall", "_authorizeupgrade",
    "setimplementation", "_setimplementation",
}
# Modifier names that are close to unique to OpenZeppelin's Initializable
# pattern. Also matched against parsed modifier names, not raw text.
_UPGRADE_MODIFIER_NAMES = {"initializer", "reinitializer"}
# The one piece of free text evidence still trusted: an actual delegatecall in
# the code, after comments are stripped. Word bounded so it cannot be fooled by
# a longer identifier that merely contains the word.
_DELEGATECALL_RE = re.compile(r"\bdelegatecall\b", re.IGNORECASE)

# Modifiers common enough to be plumbing, not evidence of an owner gate. A
# function guarded only by one of these is not treated as privileged, whatever
# its name suggests. Everything else is: this is a denylist, not an allowlist,
# because the failure that costs a reader money is a custom modifier (onlyRole,
# requiresRole, gated, ...) silently making a fund draining function invisible.
_BENIGN_MODIFIERS = {"nonreentrant", "whennotpaused", "whenpaused", "initializer", "reinitializer"}

# Modifier name fragments that read as a classic owner gate. This used to be
# the allowlist that decided whether a function counted as privileged at all;
# it is now demoted to a confidence signal only, since relying on it as the
# decision meant an unrecognized gate name made a function vanish from the
# table instead of showing up with a lower confidence.
_GATE_HINTS = ("only", "auth", "restricted", "admin", "governance")

_FALLBACK_CAPABILITY = "does something only a privileged caller can do, review it"

# Function name hints mapped to a plain capability and whether it can move or
# freeze user value. Order matters, the first hit wins, so more specific hints
# (setfeerecipient) are listed ahead of the general hints they are a substring
# neighbor of (fee).
_CAPABILITIES: list[tuple[tuple[str, ...], str, bool]] = [
    (("mint",), "mint new supply", True),
    (("burnfrom", "burn"), "burn balances", True),
    (("blacklist", "blocklist", "denylist", "freeze"), "block specific holders", True),
    # A claim is normally a caller taking their own already owed entitlement,
    # not the owner moving other people's money. Kept separate from the
    # withdraw bucket below so it does not render with a red fund moving
    # marker and erode trust in the real ones.
    (("claim",), "let users claim funds they are owed", False),
    (("withdraw", "sweep", "rescue", "drain"), "move funds out", True),
    (("pause", "unpause", "halt"), "pause activity", True),
    (("upgradeto", "upgrade", "setimplementation"), "replace the code", True),
    # A fee recipient or treasury address redirects future revenue to wherever
    # the owner points it, which is a fund moving power, not a mere setting.
    # Checked ahead of the plain fee bucket since setFeeRecipient and
    # setFeeTo would otherwise match the narrower "setfee" hint first.
    (("setfeerecipient", "setfeeto", "settreasury"), "repoint a critical address", True),
    (("setfee", "settax", "fee", "tax"), "change fees", False),
    (("setowner", "transferownership", "renounce"), "change who is in control", False),
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


def _classify(name: str) -> tuple[str, bool, bool]:
    """Return (capability, can_move_funds, matched_a_specific_rule).

    The fallback for a name that hits no rule defaults can_move_funds to
    True, not False: this table's whole job is to warn a non expert reader
    about owner power, and understating that power is the expensive failure
    while overstating it is only annoying. A gated function the classifier
    cannot name still gets flagged as capable of moving funds, just with
    lower confidence (see build_inventory).
    """
    low = name.lower()
    for hints, capability, moves in _CAPABILITIES:
        if any(h in low for h in hints):
            return capability, moves, True
    return _FALLBACK_CAPABILITY, True, False


def _modifiers(tail: str) -> list[str]:
    out = []
    # Cut anything from returns onwards, its contents are types not modifiers.
    head = tail.split("returns")[0]
    for m in _MODIFIER_INVOCATION.finditer(head):
        name = m.group("name")
        if name in _KNOWN_KEYWORDS:
            continue
        out.append(name)
    return out


def build_inventory(files: dict[str, str]) -> dict:
    functions: list[dict] = []
    stripped_by_file: dict[str, str] = {}
    for path, content in files.items():
        code = _strip_comments(content)
        stripped_by_file[path] = code
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
    joined = "\n".join(stripped_by_file.values())
    is_erc20 = _ERC20_REQUIRED.issubset(names)

    upgrade_fn_hit = any(f["name"].lower() in _UPGRADE_FUNCTION_NAMES for f in functions)
    upgrade_mod_hit = any(
        mod.lower() in _UPGRADE_MODIFIER_NAMES for f in functions for mod in f["modifiers"]
    )
    is_upgradeable = upgrade_fn_hit or upgrade_mod_hit or bool(_DELEGATECALL_RE.search(joined))

    powers: list[dict] = []
    for f in functions:
        if f["visibility"] not in ("external", "public"):
            continue
        # Inverted gate rule: a function counts as privileged when it carries
        # any modifier that is not on the small benign denylist, not only when
        # a modifier happens to match a known owner-gate name. See the comment
        # on _BENIGN_MODIFIERS for why this direction matters.
        gated_mods = [mod for mod in f["modifiers"] if mod.lower() not in _BENIGN_MODIFIERS]
        if not gated_mods:
            continue
        capability, moves, name_matched = _classify(f["name"])
        classic_gate = any(any(h in mod.lower() for h in _GATE_HINTS) for mod in gated_mods)
        if name_matched and classic_gate:
            confidence = "high"
        elif name_matched or classic_gate:
            confidence = "medium"
        else:
            confidence = "low"
        powers.append({
            "function": f["name"],
            "file": f["file"],
            "line": f["line"],
            "visibility": f["visibility"],
            "modifiers": gated_mods,
            "capability": capability,
            "can_move_funds": moves,
            "confidence": confidence,
        })

    return {
        "functions": functions,
        "is_erc20": is_erc20,
        "is_upgradeable": is_upgradeable,
        "privileged_powers": powers,
    }
