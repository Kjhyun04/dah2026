#!/usr/bin/env bash
# 21-provision.sh — 가입자 등록 (CONFIG_SPEC 값 사용). open5gs-dbctl 로 epc_mongo 에 넣는다.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[PROV]\033[0m %s\n' "$*"; }

# .env 있으면 로드, 없으면 CONFIG_SPEC 기본값
[ -f "$HERE/.env" ] && set -a && . "$HERE/.env" && set +a || true
IMSI="${IMSI:-001010000000001}"
UE_KEY="${UE_KEY:-00112233445566778899aabbccddeeff}"
UE_OPC="${UE_OPC:-63bfa50ee6523365ff14c1f45f88737d}"

if docker exec epc mongosh "mongodb://epc_mongo/open5gs" --quiet --eval "db.subscribers.countDocuments({imsi:'$IMSI'})" 2>/dev/null | grep -q '^[1-9]'; then
  log "가입자 IMSI=$IMSI 이미 등록됨 — 스킵(idempotent)"
else
  log "가입자 등록: IMSI=$IMSI (APN internet, 기본 프로필)"
  docker exec -e DB_URI="mongodb://epc_mongo/open5gs" epc \
    open5gs-dbctl add "$IMSI" "$UE_KEY" "$UE_OPC"
fi
echo
log "등록 확인:"
docker exec epc mongosh "mongodb://epc_mongo/open5gs" --quiet \
  --eval 'db.subscribers.find({},{imsi:1,_id:0}).toArray()' || true
