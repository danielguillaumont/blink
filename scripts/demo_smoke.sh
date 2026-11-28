#!/usr/bin/env bash
# Scripted 60-second demo, used as the CI smoke test for the Docker image and compose stack:
#   docker compose up → dashboard healthy and hardened → lab switches to new_third_party_script
#   → the daemon raises an alert → acknowledge it through the API → signed report with PDF.
# Everything stays on localhost (the lab); no third-party site is contacted.
set -euo pipefail

BASE=http://127.0.0.1:8765
COMPOSE=(docker compose)
TIMEOUT=${BLINK_SMOKE_TIMEOUT:-300}
PY=${PYTHON:-python3}

log() { printf '\n== %s\n' "$*"; }
cleanup() {
  if [ "${KEEP_STACK:-0}" != "1" ]; then
    "${COMPOSE[@]}" logs --no-color --tail 80 setup daemon serve > demo-smoke-logs.txt 2>&1 || true
    "${COMPOSE[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "docker compose up"
"${COMPOSE[@]}" up -d --build --wait --wait-timeout "$TIMEOUT"
"${COMPOSE[@]}" ps

log "dashboard health and headers"
curl -fsS "$BASE/healthz"
echo
headers=$(curl -fsS -D - "$BASE/login" | tr -d '\r' | sed '/^$/q')
for h in content-security-policy x-frame-options x-content-type-options strict-transport-security; do
  grep -qi "^$h:" <<<"$headers" || { echo "missing header $h"; exit 1; }
done
code=$(curl -s -w '%{http_code}' "$BASE/api/alerts" | tail -c 3)
[ "$code" = "401" ] || { echo "non-loopback API without a token returned $code, expected 401"; exit 1; }

TOKEN=$("${COMPOSE[@]}" exec -T serve cat /data/.blink/blink.token | tr -d '\r\n')
AUTH=(-H "Authorization: Bearer $TOKEN")
curl -fsS "${AUTH[@]}" "$BASE/api/targets" > /dev/null

log "switch the lab to new_third_party_script"
"${COMPOSE[@]}" exec -T lab blink lab --port 8780 --scenario new_third_party_script

log "wait for the daemon to raise an alert"
deadline=$((SECONDS + TIMEOUT))
alert=""
while [ $SECONDS -lt $deadline ]; do
  alert=$(curl -fsS "${AUTH[@]}" "$BASE/api/alerts?state=open" | "$PY" -c '
import json, sys
alerts = [a for a in json.load(sys.stdin)
          if a["detector"] in ("scripts", "inventory") and a["severity"] in ("critical", "high")]
print(alerts[0]["id"] if alerts else "")
')
  [ -n "$alert" ] && break
  sleep 10
done
[ -n "$alert" ] || { echo "no alert within ${TIMEOUT}s"; exit 1; }
echo "alert $alert"

log "acknowledge it through the API"
curl -fsS -X POST "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"by": "demo-smoke", "note": "smoke test"}' "$BASE/api/alerts/$alert/ack" \
  | "$PY" -c 'import json, sys; s = json.load(sys.stdin)["state"]; print(s); assert s == "acknowledged"'

log "metrics and ledger"
curl -fsS "$BASE/metrics" | grep -q '^blink_scans_total' || { echo "no scan metrics"; exit 1; }
curl -fsS "${AUTH[@]}" "$BASE/api/ledger" \
  | "$PY" -c 'import json, sys; v = json.load(sys.stdin); print(v); assert v["ok"]'

log "signed report (HTML, PDF, report.json) inside the container"
"${COMPOSE[@]}" exec -T serve blink report --out /data/demo-report --days 1
"${COMPOSE[@]}" exec -T serve blink verify-report /data/demo-report \
  --public-key /data/.blink/keys/ledger_ed25519.pub
"${COMPOSE[@]}" exec -T serve python3 -c "
import pathlib
pdf = pathlib.Path('/data/demo-report/report.pdf').read_bytes()
assert pdf.startswith(b'%PDF-') and len(pdf) > 10_000, len(pdf)
print('report.pdf', len(pdf), 'bytes')"

log "demo smoke passed"
