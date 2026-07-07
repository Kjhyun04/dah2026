#!/usr/bin/env bash
# 22-verify-epc.sh — P2 검증 (EPC 가동 · MME S1AP · NF 데몬 · 가입자)
set -uo pipefail
log(){ printf '\033[1;36m[VERIFY]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) 컨테이너 가동"
for c in epc_mongo epc; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && ok "$c up" || bad "$c 미가동"
done

log "2) MME S1AP SCTP :36412 listen"
docker exec epc sh -c 'ss -lnaA sctp 2>/dev/null | grep -q 36412 || ss -lna 2>/dev/null | grep -q 36412' \
  && ok "S1AP :36412 개방" || bad "S1AP 미개방(mme 로그 확인)"

log "3) 핵심 NF 데몬 실행중"
docker exec epc sh -c 'pgrep -x open5gs-mmed >/dev/null && pgrep -x open5gs-upfd >/dev/null && pgrep -x open5gs-hssd >/dev/null && pgrep -x open5gs-sgwud >/dev/null' \
  && ok "mme/upf/hss/sgwu 데몬 OK" || bad "NF 데몬 누락(docker logs epc)"

log "4) ogstun(UE 데이터 평면)"
docker exec epc sh -c 'ip -o -4 addr show ogstun 2>/dev/null | grep -q 10.45.0.1' \
  && ok "ogstun 10.45.0.1/16" || bad "ogstun 없음"

log "5) 가입자 등록"
N=$(docker exec epc mongosh "mongodb://epc_mongo/open5gs" --quiet --eval 'db.subscribers.countDocuments()' 2>/dev/null | tr -dc '0-9')
[ "${N:-0}" -ge 1 ] && ok "가입자 ${N}건" || bad "가입자 없음(21-provision.sh 먼저)"

echo
[ "$FAIL" -eq 0 ] && log "P2 검증 통과 ✅ — P3(RAN attach) 진입 가능" || { log "P2 검증 실패 ✗"; exit 1; }
