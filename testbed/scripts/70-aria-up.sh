#!/usr/bin/env bash
# 70-aria-up.sh — P7 ARIA-256-GCM 종단 암호. uav_proxy ↔ gcs_proxy(+gcs_c2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;35m[ARIA]\033[0m %s\n' "$*"; }
cd "$HERE"

# 공유 마스터키(양 프록시 동일). .env-aria 에 보존(비커밋).
if [ -f .env-aria ]; then ARIA_KEY_HEX="$(cat .env-aria)"; else ARIA_KEY_HEX="$(openssl rand -hex 32)"; echo "$ARIA_KEY_HEX" > .env-aria; fi
# compose 는 이제 키를 argv(${ARIA_KEY_HEX})가 아니라 .env-aria 파일마운트(:ro, ARIA_KEY_FILE=/aria.key)로
#   주입한다 → docker inspect(Config.Cmd)/ps 에 키 미노출. export 불필요(제거). 로그엔 평문키 금지 —
#   sha256 지문(비가역)만 남긴다. (.env-aria 는 아래 compose up 전에 반드시 존재 — 위 라인이 보장.)
ARIA_FP="$(printf '%s' "$ARIA_KEY_HEX" | openssl dgst -sha256 -r 2>/dev/null | cut -c1-8)"
log "공유 ARIA 키(.env-aria 파일주입) 지문 sha256:${ARIA_FP}  (uav_proxy/gcs_proxy 동일)"

log "GCS측 재구성: gcs_proxy + gcs_c2 (기존 gcs_c2 단독 대체)"
docker compose -f compose/docker-compose.gcs.yml up -d --force-recreate

log "UAV측: SITL(→127.0.0.1 프록시) + uav_proxy (SITL+GPS+proxy 함께 재생성)"
docker compose -f compose/docker-compose.uav.yml up -d --force-recreate

log "C2 왕복 대기(20s)..."; sleep 20
log "gcs_c2 로그:"; docker logs gcs_c2 2>&1 | tail -4 || true
log "완료 — 검증: scripts/71-verify-aria.sh (G4)"
