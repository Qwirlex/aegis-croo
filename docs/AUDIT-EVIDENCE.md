# Evidence from the first real multi lens audits

Date 2026-07-26. Everything below was run against the real engine with real Gemini calls
through Vertex AI and a real Etherscan V2 key, not mocks.

## Quick scan tier, real run

Command:

```
curl -X POST http://127.0.0.1:8731/scan -H "content-type: application/json" -d @vuln.json
```

The target was a deliberately vulnerable Bank contract with a withdraw that sends before it
updates state, an owner only mint, an owner only sweep of the whole balance, and a pause.

Result in 32 seconds:

```
tier scan | verdict high_risk | score 28 | confidence medium
 - high Target.sol:20  Reentrancy in withdraw function
 - low  Target.sol:46  Missing zero address check in sweep
 - info Target.sol:2   Outdated compiler version
powers: mint moves funds, setFee does not, pause moves funds, sweep moves funds
```

The line the scan named, Target.sol:20, is the external call that happens before the balance is
lowered, which is the real defect.

## Full audit tier, real run

Job 5bed423818b1, finished in 40 seconds, five lenses ran, the token lens correctly did not,
since the contract exposes totalSupply as a variable and not as a function so it is not an ERC-20.

```
verdict critical_risk | score 100 | confidence medium
 F-1 critical Target.sol:20  Reentrancy in withdraw allowing state manipulation   refute: kept
 F-2 critical Target.sol:46  Owner can drain all deposited user funds             refute: kept
 F-3 high     Target.sol:37  Mint creates unbacked tokens that can drain value    refute: kept
 F-4 info     Target.sol:2   solc version                                         refute: not_checked
 F-5 info     Target.sol:7   immutable states                                     refute: not_checked
signed by 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
```

The report page rendered from the same job at /audit/5bed423818b1 shows the verdict band, the
findings with the offending code and the line highlighted, the owner powers table with mint, pause
and sweep marked as touching funds, the coverage list and the signature footer.

## What this run changed in the product

The first full run demoted "owner can drain all user deposits" to info and buried it at the bottom
of the report next to a naming note. Two causes, both fixed before this evidence was recorded.

1. The refutation prompt listed "it needs a privileged caller" as a reason to weaken a claim. For an
   audit whose main promise is telling a buyer what the owner can do to their money, that is exactly
   backwards. The prompt now says plainly that a restriction to an owner or an admin is not a
   defence, and that only code which actually prevents the problem counts, such as a hard cap, a
   timelock, a check that reverts, or an unreachable path.
2. A weakened claim dropped straight to info. It now drops one severity band, so a weakened critical
   is a high and still reads as serious.

After both fixes the same contract and the same pipeline returned the owner drain finding as
critical, kept by the skeptic, which is the answer a buyer is paying for.

## Known gap on this machine

The address based path, where crytic-compile fetches verified source from the explorer itself, fails
on Windows with "File outside of allowed directories" from solc. The raw source path used above
works. Production is Linux, where this path is already proven, so the address path is verified on
the server rather than here.
