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

# ── 5762 백도어 관측 계수 체인(DAH5762) — bringup 정본 경로에 설치(항상 on · 관측 전용, DROP 없음) ──
#   방어 WebProbe 가 SYN 카운터(iptables -nvxL DAH5762)를 읽어, 5s ss 스냅샷이 놓치는 짧은 5762
#   백도어 연결까지 결정론 포착. 정상 5762 legit 없음(C2=14550 서명·GPS=14540 lo)이라 순수 공격신호.
#   uav_ue netns(3/7 RAN에서 생성, uav compose 재생성에도 유지)에 설치. netns 진입 root 필요 → sudo -n,
#   실패 시 무해 degrade(|| true, ss 경로는 계속 동작). 트래픽·공격성공 불변(가역·무해).
UAV_PID="$(docker inspect -f '{{.State.Pid}}' uav_ue 2>/dev/null || true)"
if [ -n "$UAV_PID" ]; then
  _ns(){ sudo -n nsenter -t "$UAV_PID" -n "$@" 2>/dev/null || nsenter -t "$UAV_PID" -n "$@" 2>/dev/null; }
  _ns iptables -N DAH5762 2>/dev/null || _ns iptables -F DAH5762 || true
  _ns iptables -C INPUT -p tcp --dport 5762 -j DAH5762 2>/dev/null || _ns iptables -A INPUT -p tcp --dport 5762 -j DAH5762 || true
  _ns iptables -A DAH5762 -i lo -j RETURN || true
  _ns iptables -A DAH5762 -p tcp --syn -j NFLOG --nflog-group 5762 --nflog-prefix DAH5762_SYN \
    || _ns iptables -A DAH5762 -p tcp --syn -m comment --comment DAH5762_SYN -j RETURN || true
  _ns iptables -A DAH5762 -j RETURN || true
  log "DAH5762 관측 계수 체인 설치(5762 SYN 카운터 · DROP 없음)"
fi

log "C2 왕복 대기(20s)..."; sleep 20
log "gcs_c2 로그:"; docker logs gcs_c2 2>&1 | tail -4 || true
log "완료 — 검증: scripts/71-verify-aria.sh (G4)"
