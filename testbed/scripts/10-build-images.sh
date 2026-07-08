#!/usr/bin/env bash
# ============================================================================
# 10-build-images.sh — P1 이미지 빌드 (공식 업스트림 + 태그 pin, EC2 직접)
#   산출: dahv2/epc · dahv2/ran · dahv2/air  (:latest)
#   사용: bash scripts/10-build-images.sh   (오래 걸림 — 백그라운드 권장)
# ============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
log(){ printf '\033[1;35m[BUILD]\033[0m %s\n' "$*"; }

# ── 버전 pin (조정 지점) ──
UBUNTU="${UBUNTU:-22.04}"
OPEN5GS_VER="${OPEN5GS_VER:-}"                 # 비우면 PPA 최신(설치본 버전 기록됨)
SRSRAN_TAG="${SRSRAN_TAG:-release_23_11}"
ARDUPILOT_TAG="${ARDUPILOT_TAG:-Copter-4.5.7}"

log "1/3 EPC (Open5GS · ubuntu:$UBUNTU)"
docker build --build-arg UBUNTU="$UBUNTU" --build-arg OPEN5GS_VER="$OPEN5GS_VER" \
  -t dahv2/epc:latest "$HERE/images/epc"

log "2/3 RAN (srsRAN_4G $SRSRAN_TAG · ZMQ)"
docker build --build-arg UBUNTU="$UBUNTU" --build-arg SRSRAN_TAG="$SRSRAN_TAG" \
  -t dahv2/ran:latest "$HERE/images/ran"

log "3/3 AIR (ArduPilot $ARDUPILOT_TAG + pymavlink + mavlink-router + ARIA)"
docker build --build-arg UBUNTU="$UBUNTU" --build-arg ARDUPILOT_TAG="$ARDUPILOT_TAG" \
  -t dahv2/air:latest "$HERE/images/air"

log "빌드 완료 ✅ — scripts/11-verify-images.sh 로 검증"
docker images | grep dahv2 || true
