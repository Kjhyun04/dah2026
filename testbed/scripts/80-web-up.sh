#!/usr/bin/env bash
# 80-web-up.sh — P8 웹 대시보드. web 이미지 빌드 + web_backend + gcs fan-out 갱신.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[WEB]\033[0m %s\n' "$*"; }
cd "$HERE"

log "web 이미지 빌드 (dahv2/air + FastAPI/uvicorn)"
docker build -t dahv2/web:latest images/web

log "web_backend 기동 (net_sgi 172.30.0.20, 호스트 8080)"
docker compose -f compose/docker-compose.web.yml up -d

# gcs_proxy 의 fan-out(web_backend 로 내보내기)을 반영하려고 GCS측을 재기동한다(ARIA 키는 유지).
export ARIA_KEY_HEX="$(cat .env-aria)"
log "gcs_proxy fan-out 갱신(→web_backend)"
docker compose -f compose/docker-compose.gcs.yml up -d --force-recreate

log "대시보드 수신 대기(15s)..."; sleep 15
log "완료 — 검증: scripts/81-verify-web.sh (G5) · 브라우저: SSH -L 8080 → http://localhost:8080"
