#!/usr/bin/env bash
# 61-verify-c2.sh — P6 검증 = 게이트 G3 (평문 C2 종단: HB + 명령 ACK + 파라미터 왕복)
set -uo pipefail
log(){ printf '\033[1;36m[G3]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) gcs_c2 가동"
docker ps --format '{{.Names}}' | grep -qx gcs_c2 && ok "gcs_c2 up" || bad "gcs_c2 미가동"

log "2) 다운링크 — GCS가 UAV HEARTBEAT 수신 (셀룰러 경유)"
docker logs gcs_c2 2>&1 | grep -q 'DOWNLINK HEARTBEAT' && ok "UAV→GCS HEARTBEAT" || bad "다운링크 불통"

log "3) 업링크 — 명령 ACK"
docker logs gcs_c2 2>&1 | grep -q 'UPLINK ACK ok' && ok "GCS→UAV 명령/ACK" || bad "업링크 ACK 없음"

log "4) 파라미터 프로토콜 왕복"
docker logs gcs_c2 2>&1 | grep -q 'PARAM roundtrip ok' && ok "PARAM 요청/응답 왕복" || bad "파라미터 왕복 실패"

echo
[ "$FAIL" -eq 0 ] && log "G3 통과 ✅ — 평문 C2-over-cellular 성립. P7(ARIA 암호) 진입 가능" || { log "G3 실패 ✗ — docker logs gcs_c2 / uav_sitl 확인"; exit 1; }
