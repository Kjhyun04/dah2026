#!/usr/bin/env bash
# ============================================================================
# 11-verify-images.sh — P1 검증 (이미지 3종 + 핵심 바이너리/기능)
#   사용: bash scripts/11-verify-images.sh
# ============================================================================
set -uo pipefail
log(){ printf '\033[1;36m[VERIFY]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
FAIL=0

log "1) 이미지 3종 존재"
for i in dahv2/epc dahv2/ran dahv2/air; do
  docker image inspect "$i:latest" >/dev/null 2>&1 && ok "$i" || bad "$i 없음"
done

log "2) Open5GS 바이너리"
docker run --rm dahv2/epc:latest sh -c 'command -v open5gs-mmed >/dev/null && command -v open5gs-upfd >/dev/null' \
  && ok "open5gs-mmed/upfd 존재" || bad "open5gs 바이너리 없음"

log "3) srsRAN 바이너리 + ZMQ 링크"
docker run --rm dahv2/ran:latest sh -c 'command -v srsenb >/dev/null && command -v srsue >/dev/null' \
  && ok "srsenb/srsue 존재" || bad "srsRAN 바이너리 없음"
# ZMQ는 별도 RF 플러그인(libsrsran_rf_zmq.so → libzmq)로 빌드됨. srsue는 런타임 로드(ldd엔 안 보임=정상)
docker run --rm dahv2/ran:latest sh -c 'ldconfig -p | grep -q libsrsran_rf_zmq' \
  && ok "ZMQ RF 플러그인(libsrsran_rf_zmq) 빌드됨" || bad "ZMQ RF 미빌드"

log "4) ArduPilot SITL"
docker run --rm dahv2/air:latest sh -c 'test -x /ardupilot/build/sitl/bin/arducopter' \
  && ok "arducopter 빌드됨" || bad "arducopter 없음"

log "5) pymavlink import"
docker run --rm dahv2/air:latest python3 -c 'import pymavlink,sys; print(pymavlink.__version__)' >/dev/null 2>&1 \
  && ok "pymavlink OK" || bad "pymavlink import 실패"

log "6) MAVProxy (fan-out --out)"
docker run --rm dahv2/air:latest sh -c 'command -v mavproxy.py >/dev/null || python3 -c "import MAVProxy" 2>/dev/null' \
  && ok "MAVProxy 존재" || bad "MAVProxy 없음"

log "7) OpenSSL ARIA 가용 (mav_aria_proxy 전제)"
docker run --rm dahv2/air:latest python3 - <<'PY' >/dev/null 2>&1 \
  && ok "EVP_aria_256 가용" || bad "ARIA 불가(libcrypto 확인)"
import ctypes
lib=ctypes.CDLL("libcrypto.so.3")
lib.EVP_aria_256_cbc.restype=ctypes.c_void_p
assert lib.EVP_aria_256_cbc()
PY

echo
[ "$FAIL" -eq 0 ] && log "P1 검증 통과 ✅ — P2(EPC) 진입 가능" || { log "P1 검증 실패 ✗"; exit 1; }
