#!/usr/bin/env bash
# ==============================================================================
# s3b_5762.sh — S3-b / A4 serial5762 백도어 연결 + WebProbe ESTAB 탐지 + 종료복원
#
#   흐름: read-only baseline(ESTAB 0) → serial5762.py 로 uav_ue:5762 백도어 TCP 연결
#         → WebProbe ss ESTAB≥1 확인(탐지원) → 연결종료 → ESTAB 0 복귀 확인.
#   안전: 연결만 수립(명령 발행 없음). 즉시 종료. 5762 는 서명검증 미경유 직결경로라
#         관측 목적으로만 접촉. 잔존 세션 발견 시 §5 ABORT.
#   지위: operator 승인 하 실행. 검증은 전부 read-only SSH.
# ==============================================================================
set -euo pipefail

SSH_KEY="${SSH_KEY:?set SSH_KEY in .env}"
TESTBED="${TESTBED:?set TESTBED (user@host) in .env}"
S5762_TOOL="~/dah_exec/CAMPAIGN/serial5762.py"
RUN_JSONL="${RUN_JSONL:-~/mdg/live_out/live/run.jsonl}"
SS_5762="ss -tnp state established '( sport = :5762 or dport = :5762 )'"

ro() { ssh -i "$SSH_KEY" "$TESTBED" "$@"; }
say() { printf '\n[s3b] %s\n' "$*"; }
die() { printf '\n[s3b][ABORT] %s\n' "$*" >&2; exit 1; }

# --- baseline (read-only): 백도어 LISTEN 존재 + ESTAB 0 ---------------------
say "S1 preflight (read-only): 5762 LISTEN + ESTAB baseline"
ro "ss -ltnp | grep ':5762' || true"
EST_BEFORE=$(ro "$SS_5762 2>/dev/null | grep -c ':5762'") || true
EST_BEFORE="${EST_BEFORE:-0}"
say "BEFORE 5762 ESTAB=$EST_BEFORE (기대 0)"
[ "$EST_BEFORE" -eq 0 ] 2>/dev/null || say "경고: baseline ESTAB≠0 — 기존 세션 존재"

# --- 복원 trap: 연결 도구 종료 + ESTAB 0 복귀 확인 -------------------------
cleanup() {
  say "복원: serial5762 연결 종료"
  ro "pkill -f 'serial5762.py' 2>/dev/null || true"
  local i est
  for i in 1 2 3 4 5; do
    est=$(ro "$SS_5762 2>/dev/null | grep -c ':5762'") || true
    est="${est:-0}"
    say "종료확인 $i: 5762 ESTAB=$est"
    if [ "$est" -eq 0 ] 2>/dev/null; then say "★ 5762 ESTAB 0 복귀 — 백도어 세션 정리 확인"; return 0; fi
    sleep 2
  done
  die "5762 ESTAB 잔존 — 백도어 세션 미정리 (§5 ABORT: operator web_backend 소켓 정리 / OPER pause 절차)"
}
trap 'cleanup' EXIT

# --- DO: 백도어 연결 (배경) --------------------------------------------------
say "DO: serial5762.py 로 uav_ue:5762 백도어 TCP 연결 (연결만, 명령 없음)"
ro "cd ~/dah_exec/CAMPAIGN && nohup python3 serial5762.py --connect-only > ~/s3b_5762.log 2>&1 & echo started pid=\$!"
sleep 3

# --- VERIFY (read-only): WebProbe ESTAB ------------------------------------
say "VERIFY: ss ESTAB (WebProbe 탐지원)"
EST_AFTER=$(ro "$SS_5762 2>/dev/null | grep -c ':5762'") || true
EST_AFTER="${EST_AFTER:-0}"
ro "$SS_5762 2>/dev/null | grep ':5762' || true"
say "AFTER 5762 ESTAB=$EST_AFTER (BEFORE=$EST_BEFORE)"
[ "$EST_AFTER" -ge 1 ] 2>/dev/null \
  && say "★ 5762 백도어 ESTAB 세션 확립 — WebProbe 탐지 대상 발생" \
  || say "경고: ESTAB 미확립 (도구 인자/포트 확인 — serial5762.py --help)"

say "VERIFY: run.jsonl WebProbe 5762 신호"
ro "grep -aiE 'web_probe|5762|backdoor' $RUN_JSONL | tail -3" \
  && say "★ MDG run.jsonl WebProbe 신호 확인" || say "경고: run.jsonl WebProbe 신호 미확인 (틱 지연 가능)"

# --- 복원은 EXIT trap(cleanup) 에서 수행 -----------------------------------
say "DO/VERIFY 완료 — EXIT trap 이 연결종료+ESTAB0 복귀 확인 수행"
