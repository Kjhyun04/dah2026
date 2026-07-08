#!/usr/bin/env bash
# 30-ran-up.sh — P3 RAN 기동. eNB 먼저→안정화→UE (ZMQ desync 방지).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[RAN]\033[0m %s\n' "$*"; }
cd "$HERE"
C="compose/docker-compose.ran.yml"

log "eNB 기동 (ran_enb)"; docker compose -f "$C" up -d ran_enb
log "eNB ZMQ 안정화 대기(8s)..."; sleep 8
log "UE 기동 (uav_ue)"; docker compose -f "$C" up -d uav_ue
log "attach 대기(최대 60s): tun_srsue IP..."
IP=""
for i in $(seq 1 60); do
  IP="$(docker exec uav_ue ip -o -4 addr show tun_srsue 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
  [ -n "$IP" ] && break; sleep 1
done
if [ -n "$IP" ]; then log "✓ tun_srsue = $IP"; else log "✗ tun 미생성 — 로그 확인"; docker exec uav_ue tail -20 /tmp/ue.log 2>/dev/null || true; fi
log "완료 — 검증: scripts/31-verify-ran.sh (G0)"
