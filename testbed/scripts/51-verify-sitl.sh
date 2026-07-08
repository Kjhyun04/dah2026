#!/usr/bin/env bash
# 51-verify-sitl.sh — P5 검증 = 게이트 G2 (SITL 가동 + GPS 인젝터 + GPS fix≥3)
set -uo pipefail
log(){ printf '\033[1;36m[G2]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$*"; }
FAIL=0

log "1) uav_sitl / uav_gps 가동"
for c in uav_sitl uav_gps; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && ok "$c up" || bad "$c 미가동"
done

log "2) GPS_INPUT 주입중"
docker logs uav_gps 2>&1 | grep -q 'injected' && ok "인젝터 주입 로그" || warn "주입 로그 미확인(초기화중일 수 있음)"

log "3) GPS fix≥3 (SITL serial1 tcp:5762 — 프록시와 무충돌)"
FIX=$(docker run -i --rm --network container:uav_ue dahv2/air:latest python3 - <<'PY' 2>/dev/null
import time
from pymavlink import mavutil
m=mavutil.mavlink_connection('tcp:127.0.0.1:5762')
if not m.wait_heartbeat(timeout=30): print("FIX=0"); raise SystemExit
m.mav.request_data_stream_send(m.target_system,m.target_component,mavutil.mavlink.MAV_DATA_STREAM_ALL,4,1)
t=time.time(); fix=0
while time.time()-t<45:
    g=m.recv_match(type='GPS_RAW_INT',blocking=True,timeout=2)
    if g:
        fix=g.fix_type
        if fix>=3: break
print("FIX=%d"%fix)
PY
)
FIXN=$(echo "$FIX" | sed -n 's/.*FIX=\([0-9]*\).*/\1/p' | tail -1)
[ "${FIXN:-0}" -ge 3 ] && ok "GPS fix_type=$FIXN (≥3)" || bad "GPS fix 미획득 (fix=${FIXN:-?})"

echo
[ "$FAIL" -eq 0 ] && log "G2 통과 ✅ — P6(평문 C2) 진입 가능" || { log "G2 실패 ✗ — docker logs uav_sitl / uav_gps 확인"; exit 1; }
