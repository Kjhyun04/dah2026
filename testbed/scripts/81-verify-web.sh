#!/usr/bin/env bash
# 81-verify-web.sh — P8 검증 = 게이트 G5 (대시보드: 텔레메트리 tap + 위치 갱신 ≥1Hz + 페이지)
set -uo pipefail
log(){ printf '\033[1;36m[G5]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) web_backend 가동"
docker ps --format '{{.Names}}' | grep -qx web_backend && ok "web_backend up" || bad "web_backend 미가동"

GET='import urllib.request,sys;print(urllib.request.urlopen("http://127.0.0.1:8080"+sys.argv[1],timeout=5).read().decode())'
log "2) 대시보드 페이지 서빙 (HTTP 8080)"
docker exec web_backend python3 -c "$GET" / 2>/dev/null | grep -qi cesium \
  && ok "index.html(CesiumJS) 서빙" || bad "페이지 서빙 실패"

log "3) 평문 텔레메트리 tap + 위치 갱신율(5s 윈도우 실측)"
P1=$(docker exec web_backend python3 -c "$GET" /stats 2>/dev/null | sed -n 's/.*"positions":\s*\([0-9]*\).*/\1/p')
sleep 5
ST=$(docker exec web_backend python3 -c "$GET" /stats 2>/dev/null); echo "      $ST"
P2=$(echo "$ST" | sed -n 's/.*"positions":\s*\([0-9]*\).*/\1/p')
RATE=$(awk "BEGIN{printf \"%.2f\", (${P2:-0}-${P1:-0})/5.0}")
awk "BEGIN{exit !($RATE >= 1.0)}" && ok "위치 갱신 ${RATE}Hz (≥1Hz, 윈도우)" || bad "위치 갱신율 부족 (${RATE}Hz)"
[ "${P2:-0}" -ge 1 ] && ok "GLOBAL_POSITION_INT 수신 ${P2}건" || bad "위치 텔레메트리 없음"

echo
[ "$FAIL" -eq 0 ] && log "G5 통과 ✅ — 웹 대시보드(로그+3D) 동작. 브라우저에서 SSH-L 8080 → http://localhost:8080" || { log "G5 실패 ✗"; exit 1; }
