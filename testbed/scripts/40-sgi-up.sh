#!/usr/bin/env bash
# 40-sgi-up.sh — P4 SGi 직접 라우팅. net_sgi + sgi_test + epc(UPF) 연결 + 역경로.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;34m[SGi]\033[0m %s\n' "$*"; }
cd "$HERE"
C="compose/docker-compose.sgi.yml"

log "net_sgi + sgi_test 기동"
docker compose -f "$C" up -d
sleep 3

# .1은 Docker 브리지 게이트웨이용으로 예약되어 있어, epc는 172.30.0.2를 쓴다.
log "epc(UPF)를 net_sgi에 연결 (172.30.0.2, SGi측 라우팅 게이트웨이)"
if docker exec epc ip -o -4 addr show 2>/dev/null | grep -q '172\.30\.0\.2'; then
  log "  epc 이미 net_sgi 연결됨"
else
  docker network connect --ip 172.30.0.2 net_sgi epc && log "  epc→net_sgi 연결"
fi
# UPF 포워딩 보장(직접 라우팅, NAT 없음)
docker exec epc sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

log "sgi_test 역경로 추가 (10.45.0.0/16 → 172.30.0.2)"
docker exec sgi_test ip route replace 10.45.0.0/16 via 172.30.0.2

# UAV측 C2/암호문이 SGi로 나가는 경로(셀룰러 베어러 경유) — ARIA 경로에 필수
if docker ps --format '{{.Names}}' | grep -qx uav_ue; then
  log "uav_ue 라우트: 172.30.0.0/24 dev tun_srsue (C2/암호문 over cellular)"
  docker exec uav_ue ip route replace 172.30.0.0/24 dev tun_srsue
fi

log "완료 — 검증: scripts/41-verify-sgi.sh (G1)"
