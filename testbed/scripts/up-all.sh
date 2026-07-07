#!/usr/bin/env bash
# up-all.sh — DAH v2 전체 콜드스타트 (최종 ARIA 구성). 재현성 검증용.
#   순서: EPC → 가입자 → RAN(attach) → SGi 라우팅 → ARIA(SITL+GPS+프록시+GCS) → 웹.
#   전제: 프리플라이트(01) 통과 + 이미지 3+web(10/80) 빌드 완료.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
log(){ printf '\n\033[1;35m========== %s ==========\033[0m\n' "$*"; }

log "1/6 EPC 기동";        bash "$HERE/20-epc-up.sh"
log "2/6 가입자 등록";      bash "$HERE/21-provision.sh" || echo "  (가입자 이미 존재 — 무시)"
log "3/6 RAN attach";      bash "$HERE/30-ran-up.sh"
log "4/6 SGi 라우팅";       bash "$HERE/40-sgi-up.sh"
log "5/6 ARIA C2 (SITL+GPS+프록시+GCS)"; bash "$HERE/70-aria-up.sh"
log "6/6 웹 대시보드";      bash "$HERE/80-web-up.sh"

log "콜드스타트 완료 — 검증: bash scripts/verify-all.sh"
