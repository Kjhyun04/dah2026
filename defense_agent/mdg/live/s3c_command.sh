#!/usr/bin/env bash
# ==============================================================================
# s3c_command.sh — S3-c / A1 무서명 DO_SET_MODE 주입 + 서명차단 실증
#
#   흐름: read-only baseline(UAV custom_mode) → tm1_inject_oracle.py 로 무서명
#         DO_SET_MODE 를 명령평면(→gcs_proxy:14556→uav_proxy) 주입
#         → AirCommandTap Unauthorized_Command(idle=0 이므로 ANY=신호) 확인
#         → uav_proxy 서명검증 실패 카운터 증가(=SITL 차단) 확인
#         → UAV custom_mode 불변 확인(서명차단 실증).
#   안전: 무서명이라 uav_proxy 가 SITL 차단 → UAV 상태 무변경(복원 불필요).
#         만약 custom_mode 가 실제로 바뀌면(서명우회) 즉시 abort.
#   지위: operator 승인 하 실행. 검증은 전부 read-only SSH.
# ==============================================================================
set -euo pipefail

SSH_KEY="${SSH_KEY:?set SSH_KEY in .env}"
TESTBED="${TESTBED:?set TESTBED (user@host) in .env}"
TM1_TOOL="~/dah_exec/A_TM1/tm1_inject_oracle.py"
RUN_JSONL="${RUN_JSONL:-~/mdg/live_out/live/run.jsonl}"
CMD_PORT=14556                    # gcs_proxy eth0 명령 진입점 (idle=0)

ro() { ssh -i "$SSH_KEY" "$TESTBED" "$@"; }
say() { printf '\n[s3c] %s\n' "$*"; }
die() { printf '\n[s3c][ABORT] %s\n' "$*" >&2; exit 1; }

# --- 컨테이너 해석 (read-only) ----------------------------------------------
say "S1 preflight (read-only): uav_proxy / gcs_proxy 해석 + 서명 강제 ON 확인"
UAVPX=$(ro "docker ps --format '{{.Names}}' | grep -i uav_proxy | head -1") || die "uav_proxy 미탐지"
GCSPX=$(ro "docker ps --format '{{.Names}}' | grep -i gcs_proxy | head -1") || die "gcs_proxy 미탐지"
say "uav_proxy=$UAVPX  gcs_proxy=$GCSPX"

# 서명 강제 ON 은 uav_proxy 로 확인(복호→SITL). gcs_proxy env 만 보면 OFF 오판 주의.
ro "docker logs $UAVPX --since 15m 2>&1 | grep -iE '서명 강제 ON|MAVLink2.*ON|signing.*on' | tail -2" \
  && say "★ uav_proxy MAVLink2 서명 강제 ON 확인" \
  || say "경고: uav_proxy 서명 ON 로그 미확인 — curl /api/signing 로 재확인 권장"

# --- BEFORE: 서명검증 실패 카운터 + UAV custom_mode -------------------------
# 실패 카운터는 재시작 시 리셋되므로 --since 윈도잉 diff 로 판정.
FAIL_BEFORE=$(ro "docker logs $UAVPX --since 20s 2>&1 | grep -cE '서명검증 실패|SITL 차단'") || true
FAIL_BEFORE="${FAIL_BEFORE:-0}"
MODE_BEFORE=$(ro "docker logs $UAVPX --since 60s 2>&1 | grep -oE 'custom_mode[=: ]+[0-9]+' | tail -1") || true
say "BEFORE 서명검증실패(20s)=$FAIL_BEFORE  UAV_custom_mode='$MODE_BEFORE'"

# --- 복원 trap: 주입 도구 종료(무서명이라 UAV 무변경 → 복원 불필요) --------
cleanup() {
  say "복원: 주입 도구 종료 (무서명 주입은 uav_proxy 가 차단 → UAV 상태 무변경)"
  ro "pkill -f 'tm1_inject_oracle.py' 2>/dev/null || true"
}
trap 'cleanup' EXIT

# --- DO: 무서명 DO_SET_MODE 주입 --------------------------------------------
say "DO: tm1_inject_oracle.py 무서명 DO_SET_MODE 주입 → 명령평면"
ro "cd ~/dah_exec/A_TM1 && python3 tm1_inject_oracle.py --unsigned --cmd DO_SET_MODE 2>&1 | tail -20" \
  || say "tm1_inject_oracle.py 종료(코드 무시 — 아래 탐지로 판정)"
sleep 2

# --- VERIFY (read-only) ------------------------------------------------------
say "VERIFY: AirCommandTap gcs_proxy:$CMD_PORT Unauthorized_Command (idle=0 → ANY=신호)"
ro "grep -a 'Unauthorized_Command' $RUN_JSONL | tail -3" \
  && say "★ MDG run.jsonl Unauthorized_Command 확인" \
  || say "경고: run.jsonl Unauthorized_Command 미확인 (틱/캡처 지연 가능)"

say "VERIFY: 서명차단 실증 — uav_proxy 서명검증 실패 카운터 증가"
ro "docker logs $UAVPX --since 20s 2>&1 | grep -E '서명검증 실패|SITL 차단' | tail -5" || true
FAIL_AFTER=$(ro "docker logs $UAVPX --since 20s 2>&1 | grep -cE '서명검증 실패|SITL 차단'") || true
FAIL_AFTER="${FAIL_AFTER:-0}"
say "AFTER 서명검증실패(20s)=$FAIL_AFTER (BEFORE=$FAIL_BEFORE)"
[ "$FAIL_AFTER" -gt "$FAIL_BEFORE" ] 2>/dev/null \
  && say "★ '[proxy] ⛔ 서명검증 실패 → SITL 차단' 카운터 증가 — 무서명 명령 차단 실증" \
  || say "경고: 서명검증 실패 카운터 증가 미관측"

# --- 안전 assert: UAV custom_mode 불변 (서명우회 아님) ----------------------
MODE_AFTER=$(ro "docker logs $UAVPX --since 60s 2>&1 | grep -oE 'custom_mode[=: ]+[0-9]+' | tail -1") || true
say "UAV custom_mode BEFORE='$MODE_BEFORE' AFTER='$MODE_AFTER'"
if [ -n "$MODE_BEFORE" ] && [ -n "$MODE_AFTER" ] && [ "$MODE_BEFORE" != "$MODE_AFTER" ]; then
  die "UAV custom_mode 변경 감지 — 무서명 명령이 SITL 반영됨(서명우회 심각). operator 서명강제 재확인 (§5 ABORT)"
fi
say "★ UAV custom_mode 불변 — 서명차단으로 무서명 명령이 SITL 미반영 확인"

say "DO/VERIFY 완료 — EXIT trap 이 주입도구 종료 수행 (UAV 무변경)"
