#!/usr/bin/env bash
# Prove the address based audit path end to end against the local engine.
# Usage: bash scripts/verify-audit.sh [address] [chain]
# No money is involved, this talks to the engine directly, not to the paid seller.
set -u

ADDR="${1:-0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb}"
CHAIN="${2:-base}"
ENGINE="${AEGIS_ENGINE_URL:-http://127.0.0.1:8731}"
PY="${AEGIS_PY:-/opt/aegis/engine/.venv/bin/python}"
[ -x "$PY" ] || PY=python3

echo "target $ADDR on $CHAIN"

CREATE=$(curl -s --max-time 300 -X POST "$ENGINE/audit/jobs" \
  -H 'content-type: application/json' \
  -d "{\"address\":\"$ADDR\",\"chain\":\"$CHAIN\"}")

JOB=$("$PY" - "$CREATE" <<'PY'
import json, sys
try:
    print(json.loads(sys.argv[1]).get("job_id", ""))
except Exception:
    print("")
PY
)

if [ -z "$JOB" ]; then
  echo "no job created, the engine answered:"
  echo "$CREATE" | head -c 600
  exit 1
fi
echo "job $JOB"

STATE=running
for i in $(seq 1 40); do
  sleep 10
  STATE=$(curl -s --max-time 30 "$ENGINE/audit/jobs/$JOB" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["state"])')
  echo "  ${i}0s $STATE"
  [ "$STATE" = "running" ] || break
done

# The finished job goes to a file rather than a pipe, because the heredoc below
# is itself stdin for python and would swallow a piped body.
OUT=$(mktemp)
curl -s --max-time 30 "$ENGINE/audit/jobs/$JOB" > "$OUT"

"$PY" - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
r = d.get("report")
if not r:
    print("state", d["state"], "reason", d.get("reason"))
    raise SystemExit(1)
t = r["target"]
print(f"contract {t['contract_name']} compiler {t['compiler']} chain {t['chain']} verified {t['source_verified']}")
print(f"verdict {r['verdict']} score {r['risk_score']} confidence {r['confidence']} status {r['status']} in {round(r['duration_ms']/1000)}s")
for f in r["findings"]:
    ref = (f.get("refutation") or {}).get("verdict")
    print(f"  {f['id']:5} {f['severity']:8} {f['location']:24} {f['title'][:52]}  refute={ref}")
print("powers:", ", ".join(f"{p['function']}{'*' if p['can_move_funds'] else ''}" for p in r["privileged_powers"]) or "none")
c = r["coverage"]
print("lenses:", ",".join(c["lenses_run"]) or "none", "| skipped:", len(c["lenses_skipped"]), "| detectors:", c["detectors_run"])
print("signer:", r["signer"] or "unsigned")
print("report page: https://aegiscan.xyz/audit/" + d["id"])
PY_END
PY

rm -f "$OUT"
