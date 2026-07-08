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

log "docker.io 설치"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io

# SCTP(S1AP 필수): 최신 커널(예: Ubuntu 26.04 kernel 7.x-aws)은 sctp 가 base linux-modules 에 내장되어
# modprobe 만으로 로드된다. linux-modules-extra-<kernel> 는 있으면 설치(구커널 대비)하되 없어도 실패시키지
# 않는다(아래 modprobe 로 실검증). 예전엔 docker.io 와 묶여, 이 패키지 부재 시 docker 까지 통째 실패했음.
log "SCTP 커널모듈(가능 시 linux-modules-extra; 최신 커널은 base 내장이라 불필요)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "linux-modules-extra-$(uname -r)" 2>/dev/null \
  || log "  linux-modules-extra-$(uname -r) 미제공 — base 모듈로 진행(modprobe 로 확인)"

log "docker compose 플러그인"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-v2 \
  || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin \
  || log "! compose 플러그인 설치 실패 — 수동확인"

log "에이전트/배포 전제(python3-venv/pip · openssl[.mav-sign-key 생성] · curl[웹검증])"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip openssl curl \
  || log "! 전제 패키지 설치 실패 — 수동확인(apt install python3-venv python3-pip openssl curl)"

log "SCTP 로드 + 부팅 영속(S1AP 필수)"
sudo modprobe sctp || { log "! sctp 모듈 로드 실패 — S1AP 불가(커널에 sctp 부재, 매우 드묾). 확인 필요."; exit 1; }
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
