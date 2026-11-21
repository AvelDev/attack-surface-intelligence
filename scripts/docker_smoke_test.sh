#!/usr/bin/env bash
# Test dymny obrazu Dockera: buduje obraz, uruchamia kontener na losowym porcie, sprawdza
# narzędzia, logowanie admina, panel React i (opcjonalnie) pełny skan wskazanego celu.
#
#   bash scripts/docker_smoke_test.sh                    # bez skanu
#   bash scripts/docker_smoke_test.sh scanme.nmap.org    # + skan (cel musi być autoryzowany!)
#
# Zmienne: IMAGE (domyślnie attack-surface-intelligence:latest), SKIP_BUILD=1, PORT (domyślnie 18000),
# SCAN_TIMEOUT (s, domyślnie 600).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-attack-surface-intelligence:latest}
PORT=${PORT:-18000}
NAME=asi-smoke-$$
TARGET=${1:-}
SCAN_TIMEOUT=${SCAN_TIMEOUT:-600}
BASE="http://127.0.0.1:${PORT}"
JAR=$(mktemp)
PY=""
for c in python3 python; do "$c" -c 1 >/dev/null 2>&1 && { PY=$c; break; }; done  # pomija atrapę python3 z Windows Store
[ -n "$PY" ] || { echo "FAIL: brak Pythona na hoście" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; docker logs "$NAME" 2>&1 | tail -30 >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -f "$JAR"; }
trap cleanup EXIT
json() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1" | tr -d "\r"; }

if [ "${SKIP_BUILD:-0}" != 1 ]; then
  echo "== build $IMAGE"
  docker build -q -t "$IMAGE" . >/dev/null
fi

echo "== run $NAME na :$PORT"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8000" \
  --cap-drop ALL --cap-add NET_RAW "$IMAGE" >/dev/null

for _ in $(seq 1 60); do
  curl -fsS "$BASE/" -o /dev/null 2>/dev/null && break
  sleep 1
done
curl -fsS "$BASE/" | grep -q '<div id="root"' || fail "panel React nie jest serwowany pod /"
echo "ok  panel React pod /"

PASS=""
for _ in $(seq 1 10); do
  PASS=$(docker logs "$NAME" 2>&1 | sed -n 's/.*admin \/ \([^ ]*\).*/\1/p' | head -1)
  [ -n "$PASS" ] && break; sleep 1
done
[ -n "$PASS" ] || fail "brak hasła admina w logu"

curl -fsS -c "$JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" "$BASE/api/login" >/dev/null || fail "logowanie"
echo "ok  logowanie admina"

TOOLS=$(curl -fsS -b "$JAR" "$BASE/api/tools")
for t in nmap subfinder dnsx naabu httpx nuclei; do
  [ "$(echo "$TOOLS" | json "d['$t']['installed']")" = True ] || fail "narzędzie $t niedostępne: $TOOLS"
done
echo "ok  narzędzia: nmap subfinder dnsx naabu httpx nuclei"

STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$NAME")
echo "ok  healthcheck: $STATUS"

if [ -n "$TARGET" ]; then
  echo "== skan $TARGET (limit ${SCAN_TIMEOUT}s)"
  SID=$(curl -fsS -b "$JAR" -H 'Content-Type: application/json' \
    -d "{\"target\":\"$TARGET\",\"authorized\":true}" "$BASE/api/scans" | json "d['id']")
  END=$((SECONDS + SCAN_TIMEOUT))
  while :; do
    S=$(curl -fsS -b "$JAR" "$BASE/api/scans/$SID")
    ST=$(echo "$S" | json "d['scan']['status']")
    case "$ST" in done) break ;; failed|stopped|paused_window) fail "skan: $ST" ;; esac
    [ $SECONDS -lt $END ] || fail "skan nie skończył się w ${SCAN_TIMEOUT}s (status $ST)"
    sleep 5
  done
  echo "$S" | "$PY" -c "
import sys,json
d=json.load(sys.stdin); s=d.get('scan',d)
print('ok  skan #%s: status=%s ryzyko=%s zasoby=%d ustalenia=%d' % (
  s.get('id'), s.get('status'), s.get('score'), len(d.get('assets',[])), len(d.get('findings',[]))))
assert d.get('assets'), 'skan nie znalazł żadnych zasobów'
"
fi
echo "PASS"
