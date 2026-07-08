#!/usr/bin/env bash
# 41-verify-sgi.sh — P4 검증 = 게이트 G1 (기본 베어러 + SGi 직접 라우팅)
set -uo pipefail
log(){ printf '\033[1;36m[G1]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) epc가 net_sgi(172.30.0.2)로 연결 (SGi 게이트웨이)"
docker exec epc ip -o -4 addr show 2>/dev/null | grep -q '172\.30\.0\.2' \
  && ok "epc net_sgi 172.30.0.2" || bad "epc net_sgi 미연결(40 먼저)"

log "2) UE → UPF GW(10.45.0.1) — 기본 데이터 베어러"
docker exec uav_ue ping -I tun_srsue -c3 -W2 10.45.0.1 >/dev/null 2>&1 \
  && ok "GW ping OK" || bad "GW ping 실패(베어러 확인)"

log "3) UE → SGi 호스트(172.30.0.100) — SGi 직접 라우팅(F 결정 실증)"
docker exec uav_ue ping -I tun_srsue -c3 -W2 172.30.0.100 >/dev/null 2>&1 \
  && ok "SGi ping OK — UE풀↔SGi 직접 라우팅 성립" || bad "SGi ping 실패(포워딩/역경로 확인)"

echo
[ "$FAIL" -eq 0 ] && log "G1 통과 ✅ — P5(SITL+GPS) 진입 가능" || { log "G1 실패 ✗"; exit 1; }
