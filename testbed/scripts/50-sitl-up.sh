#!/usr/bin/env bash
# 50-sitl-up.sh — P5 UAV SITL + GPS 인젝터 기동 (uav_ue netns 공유)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[UAV]\033[0m %s\n' "$*"; }
cd "$HERE"
C="compose/docker-compose.uav.yml"

docker ps --format '{{.Names}}' | grep -qx uav_ue || { echo "uav_ue 미가동 — 30-ran-up.sh 먼저"; exit 1; }

log "uav_sitl + uav_gps 기동"
docker compose -f "$C" up -d
log "SITL 초기화 + GPS fix 대기(25s)..."; sleep 25
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'uav_sitl|uav_gps' || true
echo
log "GPS 인젝터 로그:"; docker logs uav_gps 2>&1 | tail -3 || true
log "완료 — 검증: scripts/51-verify-sitl.sh (G2)"
