#!/usr/bin/env bash
# ============================================================================
# 00-server-setup.sh — DAH testbed v2 · P0 서버 셋업 (idempotent, 재실행 안전)
#   docker + docker compose + SCTP(부팅영속) + TUN + docker 그룹.
#   대상: Ubuntu 22.04 / 24.04. 사용: bash scripts/00-server-setup.sh
#   이후: 재로그인(또는 newgrp docker) → bash scripts/01-preflight.sh
# ============================================================================
set -euo pipefail
log(){ printf '\033[1;36m[SETUP]\033[0m %s\n' "$*"; }

log "apt update"
sudo apt-get update -qq

log "docker.io + SCTP 커널모듈 설치"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  docker.io "linux-modules-extra-$(uname -r)"

log "docker compose 플러그인"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-v2 \
  || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin \
  || log "! compose 플러그인 설치 실패 — 수동확인"

log "에이전트 실행 전제(python3-venv/pip · defense_agent 의 python -m venv + pip install -e)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip \
  || log "! python3-venv/pip 설치 실패 — 수동확인(apt install python3-venv python3-pip)"

log "SCTP 로드 + 부팅 영속(S1AP 필수)"
sudo modprobe sctp
echo sctp | sudo tee /etc/modules-load.d/sctp.conf >/dev/null

log "TUN 확인/로드"
sudo modprobe tun 2>/dev/null || true
[ -c /dev/net/tun ] || { log "! /dev/net/tun 없음 — 커널 확인 필요"; exit 1; }

log "docker 데몬 enable + 그룹 추가"
sudo systemctl enable --now docker >/dev/null 2>&1 || true
sudo usermod -aG docker "$USER"

echo
sudo docker --version; sudo docker compose version 2>/dev/null | head -1 || true
log "완료 ✅ — docker 그룹 반영 위해 재로그인(또는 newgrp docker) 후 01-preflight.sh"
