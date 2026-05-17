#!/usr/bin/env bash
# Replay attacks/C1/C1.1_cron_backup_exfil.json inside dex-sandbox and check the
# attack predicate. Exit 0 if the attack succeeded, 1 otherwise. Prints PASS/FAIL.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TRACE="${1:-$PROJECT_ROOT/attacks/C1/C1.1_cron_backup_exfil.json}"
IMAGE="${DEX_SANDBOX_IMAGE:-dex-sandbox}"

if [ ! -f "$TRACE" ]; then
    echo "ERROR: trace not found: $TRACE" >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required on host" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker required on host" >&2
    exit 2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: docker image '$IMAGE' not found. Build it from sandbox/Dockerfile." >&2
    exit 2
fi

# Build a single bash script that:
#   - aborts on any session-command or trigger failure (set -e)
#   - then runs the predicate under set +e and exits with its status
REPRO=$(python3 - "$TRACE" <<'PY'
import json, sys
trace = json.load(open(sys.argv[1]))
out = []
out.append("set -e")
out.append("echo '--- session_commands ---'")
for cmd in trace["session_commands"]:
    out.append(cmd)
out.append("echo '--- trigger_command_to_fire ---'")
out.append(trace["trigger_command_to_fire"])
out.append("set +e")
out.append("echo '--- expected_post_trigger_state_check ---'")
out.append(trace["expected_post_trigger_state_check"])
out.append("rc=$?")
out.append("echo \"predicate exit=$rc\"")
out.append("exit $rc")
sys.stdout.write("\n".join(out) + "\n")
PY
)

NAME=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['name'])" "$TRACE")

docker run --rm -i --privileged \
    -v "$PROJECT_ROOT:/work" \
    "$IMAGE" bash <<<"$REPRO"
EC=$?

if [ "$EC" -eq 0 ]; then
    echo "PASS: $NAME (predicate satisfied)"
    exit 0
else
    echo "FAIL: $NAME (exit=$EC)"
    exit 1
fi
