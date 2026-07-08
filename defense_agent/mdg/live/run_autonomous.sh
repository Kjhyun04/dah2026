#!/usr/bin/env bash
# ==============================================================================
# run_autonomous.sh — 마스터 오케스트레이션 (S2~S5)
#
#   수정된 live_autorun.py 를 서버 배경 실행(recon+6 collector+build_graph+run_driver+
#   Backend)하며, S3 공격(A2 PFCP → A4 5762 → A1 command)을 순차 주입하고 각 스텝 후
#   run.jsonl 탐지를 확인. 이어 S4 E4 자율 차단(operator 승인·allow_live=True 창)을 실증,
#   S5 종료·누수-0 검증으로 마감.
#
#   정체(경합) 버그 수정 검증 포함: air-tap tcpdump 관측이 read-only 라 세마포어 미획득 →
#   다틱 run.jsonl tick_i 단조증가 확인.
#
#   상태변경은 (i) 공격도구 (ii) S4 단일 가역 DROP 뿐이며 각각 즉시 복원. 기타 전부 read-only.
#   operator 명시 승인 하에서만 실행. 2대 불변식·운영제약 우선.
# ==============================================================================
set -euo pipefail

SSH_KEY="${SSH_KEY:?set SSH_KEY in .env}"
TESTBED="${TESTBED:?set TESTBED (user@host) in .env}"
PY="${PY:-~/mdg_venv/bin/python}"
RUN_ID="${RUN_ID:-live}"
OUT_DIR="~/mdg/live_out"
RUN_JSONL="$OUT_DIR/$RUN_ID/run.jsonl"
ALLOW_LIVE="${ALLOW_LIVE:-0}"    # S4 자율 DROP 실증 시에만 operator 가 1 로 설정
HERE="$(cd "$(dirname "$0")" && pwd)"

export SSH_KEY TESTBED RUN_JSONL

ro() { ssh -i "$SSH_KEY" "$TESTBED" "$@"; }
say() { printf '\n\n========== [run_autonomous] %s ==========\n' "$*"; }
sub() { printf '\n[run_autonomous] %s\n' "$*"; }
die() { printf '\n[run_autonomous][ABORT] %s\n' "$*" >&2; exit 1; }

detect_check() {   # $1=label $2=grep-pattern — run.jsonl 탐지 확인 (read-only)
  local label="$1" pat="$2" hit
  hit=$(ro "grep -aE '$pat' $RUN_JSONL 2>/dev/null | tail -2 || true")
  if [ -n "$hit" ]; then sub "★ [$label] run.jsonl 탐지 확인:"; printf '%s\n' "$hit";
  else sub "경고: [$label] run.jsonl '$pat' 미확인 (틱 지연 가능)"; fi
}

# ============================================================================
# S1 — 사전조건 (read-only)
# ============================================================================
say "S1 PRECONDITIONS (read-only)"
ro "docker ps --format '{{.Names}}'" | tr '\n' ' '; echo
sub "GATE0 회귀 (서버)"
ro "cd ~/mdg && $PY -m pytest mdg/tests -q 2>&1 | tail -3" || sub "경고: pytest 확인 필요"

# ============================================================================
# S2 — MDG 자율런 기동 (관측 read-only; ALLOW_LIVE=1 이면 S4 집행 창 개방)
# ============================================================================
say "S2 MDG 자율런 기동 (allow_live=$ALLOW_LIVE)"
# BEFORE 누수-0 스냅샷
CN_BEFORE=$(ro "docker ps -q | wc -l"); PROC_BEFORE=$(ro "pgrep -c -f 'tcpdump|nsenter' || echo 0")
sub "BEFORE 스냅샷: 컨테이너=$CN_BEFORE  tcpdump/nsenter proc=$PROC_BEFORE"

LIVE_FLAG=""; [ "$ALLOW_LIVE" = "1" ] && LIVE_FLAG="--allow-live"
ro "mkdir -p $OUT_DIR/$RUN_ID && cd ~/mdg && nohup $PY -m mdg.live_autorun --out $OUT_DIR --run-id $RUN_ID $LIVE_FLAG > $OUT_DIR/$RUN_ID/autorun.log 2>&1 & echo autorun_pid=\$!"

stop_autorun() {   # S5 종료 (EXIT trap)
  say "S5 종료·누수-0 검증 (read-only)"
  ro "pkill -f 'mdg.live_autorun' 2>/dev/null || true"
  ro "pkill -f 'tm1_inject_oracle.py|serial5762.py|pfcp_delete.py' 2>/dev/null || true"
  sleep 3
  local cn_after proc_after est ipt
  cn_after=$(ro "docker ps -q | wc -l"); proc_after=$(ro "pgrep -c -f 'tcpdump|nsenter' || echo 0")
  est=$(ro "ss -tnp state established '( sport = :5762 or dport = :5762 )' 2>/dev/null | grep -c ':5762'") || est=0
  sub "AFTER 스냅샷: 컨테이너=$cn_after (BEFORE=$CN_BEFORE)  tcpdump/nsenter proc=$proc_after  5762_ESTAB=$est"
  [ "$cn_after" = "$CN_BEFORE" ] 2>/dev/null && sub "★ 누수-0: 컨테이너 diff 0" || sub "경고: 컨테이너 수 diff≠0 — 누수 조사"
  [ "${est:-0}" -eq 0 ] 2>/dev/null && sub "★ 5762 ESTAB 0 복귀" || sub "경고: 5762 ESTAB 잔존"
  sub "testbed dahv2 컨테이너 최종 무변경 목표 — S5 완료"
}
trap 'stop_autorun' EXIT

# 다틱 진행 + 정체(경합) 버그 수정 확인
sub "다틱 진행 확인 (경합 버그 수정: air-tap read-only → 세마포어 미획득)"
sleep 8
T1=$(ro "grep -aoE '\"tick_i\": *[0-9]+' $RUN_JSONL 2>/dev/null | grep -oE '[0-9]+' | tail -1") || true
sleep 8
T2=$(ro "grep -aoE '\"tick_i\": *[0-9]+' $RUN_JSONL 2>/dev/null | grep -oE '[0-9]+' | tail -1") || true
sub "tick_i: t1=${T1:-?} t2=${T2:-?}"
[ -n "${T2:-}" ] && [ -n "${T1:-}" ] && [ "$T2" -gt "$T1" ] 2>/dev/null \
  && sub "★ tick_i 단조증가 — 다틱 자율런 정체 없음 (경합 버그 수정 확인)" \
  || sub "경고: tick_i 미증가 — 정체 재발 여부 조사 (autorun.log 확인)"

# ============================================================================
# S3 — 공격 순차 주입 + 각 스텝 후 탐지 확인
# ============================================================================
say "S3-a A2 PFCP teardown"
bash "$HERE/s3a_pfcp.sh" || sub "s3a 종료(내부 trap 복원 수행)"
detect_check "A2-PFCP" 'PFCP_Delete_Attempt|s5c_rx_deletesession'

say "S3-b A4 serial5762 백도어"
bash "$HERE/s3b_5762.sh" || sub "s3b 종료(내부 trap 복원 수행)"
detect_check "A4-5762" 'web_probe|5762|backdoor'

say "S3-c A1 무서명 command 주입"
bash "$HERE/s3c_command.sh" || sub "s3c 종료(내부 trap 복원 수행)"
detect_check "A1-command" 'Unauthorized_Command'

# ============================================================================
# S4 — E4 자율 차단 실증 (operator 승인 + ALLOW_LIVE=1 시에만)
# ============================================================================
if [ "$ALLOW_LIVE" = "1" ]; then
  say "S4 E4 자율 차단 실증 (allow_live=True — operator 승인 창)"
  bash "$HERE/s4_e4_autodrop.sh" || sub "s4 종료(내부 safe_revert trap 수행)"
  detect_check "E4-drop" 'nsenter_input_drop'
else
  say "S4 SKIP — ALLOW_LIVE!=1 (관측/탐지만 실증, 자율 DROP 미집행). 집행하려면 ALLOW_LIVE=1 operator 승인 후 재실행"
fi

# ============================================================================
# S5 — 종료·누수-0 검증은 EXIT trap(stop_autorun) 에서 수행
# ============================================================================
say "메인 시퀀스 완료 — EXIT trap(S5) 이 자율런 종료 + 누수-0 검증 수행"
