#!/usr/bin/env bash
# 60-c2-up.sh — P6 평문 C2 종단. SITL 에서 GCS 로(셀룰러 경유) 잇고, gcs_c2 는 SGi 로 붙는다.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[C2]\033[0m %s\n' "$*"; }
cd "$HERE"

log "SITL serial0 → GCS(172.30.0.10) 재구성 (SITL+GPS 함께 재생성 — lockstep GPS 핸드셰이크)"
docker compose -f compose/docker-compose.uav.yml up -d --force-recreate

log "uav_ue 라우트: 172.30.0.0/24 dev tun_srsue (C2 over cellular)"
docker exec uav_ue ip route replace 172.30.0.0/24 dev tun_srsue

log "gcs_c2 기동 (SGi 172.30.0.10, sysid255)"
docker compose -f compose/docker-compose.gcs.yml up -d

log "C2 왕복 대기(20s)..."; sleep 20
log "gcs_c2 로그:"; docker logs gcs_c2 2>&1 | tail -5 || true
log "완료 — 검증: scripts/61-verify-c2.sh (G3)"
