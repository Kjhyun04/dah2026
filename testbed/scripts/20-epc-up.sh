#!/usr/bin/env bash
# 20-epc-up.sh — P2 EPC 기동 (epc_mongo + epc 단일 컨테이너)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[EPC]\033[0m %s\n' "$*"; }
cd "$HERE"

log "docker compose up (epc_mongo → epc)"
docker compose -f compose/docker-compose.epc.yml up -d
log "기동 대기(12s)..."; sleep 12
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'epc' || true
echo
log "MME 로그(마지막 8줄):"
docker logs epc 2>&1 | tail -8 || true
log "완료 — 가입자 등록: scripts/21-provision.sh · 검증: scripts/22-verify-epc.sh"
