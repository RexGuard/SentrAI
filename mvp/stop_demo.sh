#!/usr/bin/env bash
# Stops only the SentrAI demo components started by run_demo.sh (PIDs from mvp/.demo_pids.json).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT/.demo_pids.json"

if [ ! -f "$PID_FILE" ]; then
    echo "No running demo recorded (mvp/.demo_pids.json not found)."
    exit 0
fi

python3 - "$PID_FILE" <<'EOF' | while read -r name pid; do
import json, sys
for item in json.load(open(sys.argv[1])):
    print(item["name"], item["pid"])
EOF
    if kill -0 "$pid" 2>/dev/null; then
        # Each component leads its own process group (setsid in run_demo.sh): stop the group.
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
        for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done
        kill -KILL -- "-$pid" 2>/dev/null || true
        printf '  stopped %-10s (pid %s)\n' "$name" "$pid"
    else
        printf '  %-10s was already stopped\n' "$name"
    fi
done
rm -f "$PID_FILE"
echo "SentrAI demo stopped."
