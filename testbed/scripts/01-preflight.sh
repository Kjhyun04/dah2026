#!/usr/bin/env bash
# ============================================================================
# 01-preflight.sh — DAH testbed v2 · P0 프리플라이트 검증
#   검증: docker · docker compose · SCTP 모듈(S1AP 필수) · /dev/net/tun · 자원
#   전제: 00-server-setup.sh 실행 + 재로그인. 사용: bash scripts/01-preflight.sh
# ============================================================================
set -uo pipefail
log(){ printf '\033[1;36m[PRE]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$*"; }
FAIL=0

log "1) Docker"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then ok "docker 데몬 OK ($(docker --version | awk '{print $3}' | tr -d ,))"
  else bad "docker 있으나 데몬 접근 불가 — 'newgrp docker' 또는 재로그인"; fi
else bad "docker 미설치 — 00-server-setup.sh 먼저"; fi

log "2) docker compose plugin"
if docker compose version >/dev/null 2>&1; then ok "$(docker compose version | head -1)"
else bad "compose plugin 없음 — 00-server-setup.sh 먼저"; fi

log "3) SCTP 커널 모듈 (MME S1AP 필수)"
if lsmod 2>/dev/null | grep -q '^sctp'; then ok "sctp 로드됨"
elif sudo -n modprobe sctp 2>/dev/null || modprobe sctp 2>/dev/null; then
  lsmod | grep -q '^sctp' && ok "sctp modprobe 성공" || bad "modprobe 후에도 미로드"
else
  bad "sctp 미로드 — 'sudo modprobe sctp' (실패 시: sudo apt-get install -y linux-modules-extra-\$(uname -r))"
fi

log "4) /dev/net/tun (TUN 장치)"
if [ -c /dev/net/tun ]; then ok "/dev/net/tun 존재"; else bad "/dev/net/tun 없음"; fi

log "5) 자원"
CPUS=$(nproc 2>/dev/null || echo 0)
MEMG=$(free -g 2>/dev/null | awk '/Mem:/{print $2}')
if [ "${CPUS:-0}" -ge 8 ]; then ok "vCPU=$CPUS"; else warn "vCPU=$CPUS (권장 ≥8 · c6i.2xlarge+)"; fi
if [ "${MEMG:-0}" -ge 15 ]; then ok "RAM=${MEMG}GB"; else warn "RAM=${MEMG:-?}GB (권장 ≥16)"; fi

echo
if [ "$FAIL" -eq 0 ]; then log "P0 프리플라이트 통과 ✅ — P1(이미지 확보) 진입 가능"; exit 0
else log "프리플라이트 실패 ✗ — 위 항목 해결 후 재실행"; exit 1; fi
