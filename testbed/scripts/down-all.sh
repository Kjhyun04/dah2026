#!/usr/bin/env bash
# down-all.sh — DAH v2 전체 종료 (이미지·mongo 볼륨 유지). ⚠ --remove-orphans 사용 금지.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[DOWN]\033[0m %s\n' "$*"; }
cd "$HERE"

for c in web uav gcs ran sgi epc; do
  log "down: $c"
  docker compose -f "compose/docker-compose.$c.yml" down 2>/dev/null || true
done
log "전체 종료 완료 (dahv2/* 이미지·vol_mongo 보존)"
