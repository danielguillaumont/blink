#!/bin/sh
# One-shot setup for the docker compose demo: configure the lab checkout, record baselines and
# approve the lab's known-good scripts. Safe to re-run: it only fills in what is missing.
set -eu
cd /data

if [ ! -f blink.yaml ]; then
  blink init --lab
  cat >> blink.yaml <<'EOF'
# Demo cadence: every minute, no jitter (production: daily or weekly, see docs/operations.md).
schedule:
  interval: 1m
  jitter: 0s
  retries: 1
  retry_backoff: 5s
EOF
fi

blink baseline --if-missing --reason "docker compose demo"
blink inventory --sync >/dev/null

pending=$(blink inventory --json | python3 -c '
import json, sys
print(" ".join(sorted({r["id"] for r in json.load(sys.stdin)["scripts"] if not r["approved"]})))
')
if [ -n "$pending" ]; then
  # shellcheck disable=SC2086
  blink approve $pending --justification "Lab checkout script (demo)" --owner demo \
    --approved-by demo-setup
fi
echo "Demo ready. Dashboard token: /data/.blink/blink.token"
