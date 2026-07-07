#!/usr/bin/env bash
# 70-aria-up.sh — P7 ARIA-256-GCM 종단 암호. uav_proxy ↔ gcs_proxy(+gcs_c2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;35m[ARIA]\033[0m %s\n' "$*"; }
cd "$HERE"

# 공유 마스터키(양 프록시 동일). .env-aria 에 보존(비커밋).
if [ -f .env-aria ]; then ARIA_KEY_HEX="$(cat .env-aria)"; else ARIA_KEY_HEX="$(openssl rand -hex 32)"; echo "$ARIA_KEY_HEX" > .env-aria; fi
export ARIA_KEY_HEX
log "공유 ARIA 키(앞8): ${ARIA_KEY_HEX:0:8}…  (uav_proxy/gcs_proxy 동일)"

log "GCS측 재구성: gcs_proxy + gcs_c2 (기존 gcs_c2 단독 대체)"
docker compose -f compose/docker-compose.gcs.yml up -d --force-recreate

log "UAV측: SITL(→127.0.0.1 프록시) + uav_proxy (SITL+GPS+proxy 함께 재생성)"
docker compose -f compose/docker-compose.uav.yml up -d --force-recreate

log "C2 왕복 대기(20s)..."; sleep 20
log "gcs_c2 로그:"; docker logs gcs_c2 2>&1 | tail -4 || true
log "완료 — 검증: scripts/71-verify-aria.sh (G4)"
