#!/usr/bin/env bash
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TRACE="${1:-$PROJECT_ROOT/attacks/C3/C3.2_systemd_shutdown_exfil.json}"
IMAGE="${DEX_SANDBOX_IMAGE:-dex-sandbox}"

[ -f "$TRACE" ] || { echo "ERROR: trace not found: $TRACE" >&2; exit 2; }
command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 2; }
command -v docker  >/dev/null || { echo "ERROR: docker required"  >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "ERROR: image '$IMAGE' missing" >&2; exit 2; }

REPRO=$(python3 - "$TRACE" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
out = ["set -e", "echo '--- session_commands ---'"]
out += t["session_commands"]
out += ["echo '--- trigger_command_to_fire ---'", t["trigger_command_to_fire"],
        "set +e", "echo '--- expected_post_trigger_state_check ---'",
        t["expected_post_trigger_state_check"],
        'rc=$?', 'echo "predicate exit=$rc"', 'exit $rc']
sys.stdout.write("\n".join(out) + "\n")
PY
)
NAME=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['name'])" "$TRACE")
docker run --rm -i --privileged -v "$PROJECT_ROOT:/work" "$IMAGE" bash <<<"$REPRO"
EC=$?
if [ "$EC" -eq 0 ]; then echo "PASS: $NAME (predicate satisfied)"; exit 0
else echo "FAIL: $NAME (exit=$EC)"; exit 1; fi
