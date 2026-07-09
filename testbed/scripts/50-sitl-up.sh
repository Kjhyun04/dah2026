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

# ── 5762 백도어 관측 계수 체인(DAH5762) — 항상 설치(토글 없음) · 관측 전용(DROP/REJECT 없음) ──
#   방어 WebProbe 가 `iptables -nvxL DAH5762` 로 SYN 카운터를 읽어, 5s ss 스냅샷이 놓치는 짧은
#   백도어 연결까지 결정론적으로 포착한다. 정상 5762 legit 트래픽 없음(C2=14550 서명·GPS=14540 lo)
#   이라 순수 공격신호. NFLOG(xt_NFLOG) 미지원 커널이면 comment-only 규칙으로 폴백(카운터 동일).
#   트래픽·공격성공 불변(가역·무해). netns 진입엔 root 필요 → sudo -n, 실패 시 무해 degrade(|| true).
UAV_PID="$(docker inspect -f '{{.State.Pid}}' uav_ue 2>/dev/null || true)"
if [ -n "$UAV_PID" ]; then
  _ns(){ sudo -n nsenter -t "$UAV_PID" -n "$@" 2>/dev/null || nsenter -t "$UAV_PID" -n "$@" 2>/dev/null; }
  _ns iptables -N DAH5762 2>/dev/null || _ns iptables -F DAH5762 || true
  _ns iptables -C INPUT -p tcp --dport 5762 -j DAH5762 2>/dev/null || _ns iptables -A INPUT -p tcp --dport 5762 -j DAH5762 || true
  _ns iptables -A DAH5762 -i lo -j RETURN || true                                              # 루프백(legit 로컬) 제외
  _ns iptables -A DAH5762 -p tcp --syn -j NFLOG --nflog-group 5762 --nflog-prefix DAH5762_SYN \
    || _ns iptables -A DAH5762 -p tcp --syn -m comment --comment DAH5762_SYN -j RETURN || true # SYN 카운터(±NFLOG)
  _ns iptables -A DAH5762 -j RETURN || true
  log "DAH5762 관측 계수 체인 설치(5762 SYN 카운터 · DROP 없음)"
fi

log "완료 — 검증: scripts/51-verify-sitl.sh (G2)"
