#!/usr/bin/env bash
# 71-verify-aria.sh — P7 검증 = 게이트 G4 (셀룰러엔 ARIA 암호문만 + GCS 평문 C2 유지)
set -uo pipefail
log(){ printf '\033[1;36m[G4]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) 프록시 쌍 가동 (uav_proxy, gcs_proxy)"
for c in uav_proxy gcs_proxy gcs_c2; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && ok "$c up" || bad "$c 미가동"
done

log "2) 셀룰러(tun_srsue)에 ARIA 암호문(14555)만 — 평문 MAVLink(14550) 없음"
N5=$(docker exec uav_ue timeout 5 tcpdump -ni tun_srsue udp port 14555 2>/dev/null | grep -c 'UDP')
N0=$(docker exec uav_ue timeout 5 tcpdump -ni tun_srsue udp port 14550 2>/dev/null | grep -c 'UDP')
[ "${N5:-0}" -ge 1 ] && ok "ARIA 암호문 흐름 (14555, ${N5}pkt)" || bad "암호문 미흐름"
[ "${N0:-0}" -eq 0 ] && ok "평문 MAVLink 셀룰러 부재 (14550, 0pkt)" || bad "평문이 셀룰러에 노출됨(${N0}pkt)"

log "3) GCS 평문 C2 유지 (ARIA 복호 후 — HB/ACK/PARAM)"
docker logs gcs_c2 2>&1 | grep -q 'DOWNLINK HEARTBEAT' && ok "다운링크 HEARTBEAT" || bad "다운링크 불통"
docker logs gcs_c2 2>&1 | grep -q 'UPLINK ACK ok'      && ok "업링크 명령/ACK"   || bad "업링크 실패"
docker logs gcs_c2 2>&1 | grep -q 'PARAM roundtrip ok' && ok "파라미터 왕복"     || bad "파라미터 실패"

echo
[ "$FAIL" -eq 0 ] && log "G4 통과 ✅ — 셀룰러엔 ARIA-GCM 암호문만, 종단은 평문 C2. P8(시각화) 진입 가능" || { log "G4 실패 ✗"; exit 1; }
