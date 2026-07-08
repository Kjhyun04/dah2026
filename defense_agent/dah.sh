#!/usr/bin/env bash
# dah.sh — defense_agent(MDG) 단일 런처(유일한 셸 진입점). 나머지 mdg/live/*.sh 는
#   테스트베드 온-호스트 검증 스텝일 뿐이다. 에이전트 본체는 파이썬(python -m mdg.*).
#   이 스크립트는 env 로딩(.env) + TESTBED/SSH_KEY export + 서브커맨드 디스패치만 감싼다.
#   사용: ./dah.sh <verify|test|campaign|autorun|live|viewer|status|help> [flags]
#
#   2대 불변식: ① 결정론 라우팅(제어흐름은 LLM 불가시)  ② leak-0 실행(비밀/프로세스 잔여 0).
#   기본은 전부 오프라인·read-only. 실 상태변경(단일 가역 DROP)은 MDG_ALLOW_LIVE=1 (operator-go).
set -uo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
export PYTHONDONTWRITEBYTECODE=1

_load_env() {
  # .env(.env.example 복사→값 채움) 자동 로드 → TESTBED/SSH_KEY 를 live/*.sh 로 export.
  [ -f .env ] && { set -a; . ./.env; set +a; }
  # live/status 는 TESTBED=user@host 형태를 요구 — .env 의 TESTBED_USER/HOST 로 합성(미설정 시 무해).
  if [ -z "${TESTBED:-}" ] && [ -n "${TESTBED_HOST:-}" ]; then
    export TESTBED="${TESTBED_USER:-ubuntu}@${TESTBED_HOST}"
  fi
  # MDG_ALLOW_LIVE(operator-go) → live/*.sh 가 읽는 ALLOW_LIVE 로 미러.
  [ -n "${MDG_ALLOW_LIVE:-}" ] && export ALLOW_LIVE="${MDG_ALLOW_LIVE}"
}

cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in

  verify)   # 무결성 게이트 단일 러너 (오프라인·무해, 테스트베드/비밀 불필요)
    exec $PY verify.py ;;

  test)     # pytest 회귀 (기준선 ~192 passed / 2 skipped)
    # 2 SKIP = langgraph 의존 그래프-컴파일 테스트로, langgraph 부재 시 예상된 SKIP(실패 아님).
    exec $PY -m pytest mdg/tests -q "$@" ;;

  campaign) # 오프라인 결정론 6공격 캠페인 → report.json (헤드라인 오프라인 증거)
    # live_execution_count 은 0 이어야 한다(테스트베드 무접속, 순수 결정론 재생).
    OUT="${1:-campaign_out}"; shift 2>/dev/null || true
    exec $PY -m mdg.campaign.e2e "$OUT" "$@" ;;

  autorun)  # 자율런 (DRY 기본: Backend allow_live=False → 모든 상태변경 DRY)
    # 실 actuation 은 MDG_ALLOW_LIVE truthy(operator-go) 일 때만 단일 가역 DROP 창 개방.
    _load_env
    OUT="${OUT:-./live_out}"; RID="${RUN_ID:-live}"
    exec $PY -m mdg.live_autorun --out "$OUT" --run-id "$RID" "$@" ;;

  live)     # 온-테스트베드 오케스트레이션 검증 (read-only 기본; ALLOW_LIVE=1 시 집행 창)
    _load_env
    : "${SSH_KEY:?set SSH_KEY in .env (live 서브커맨드 전용)}"
    : "${TESTBED:?set TESTBED_HOST/TESTBED_USER in .env (live 서브커맨드 전용)}"
    exec bash mdg/live/run_autonomous.sh "$@" ;;

  viewer)   # read-only 뷰어 (루프백 바인드 127.0.0.1 · PS-8) — run.jsonl 3패널
    _load_env
    SRC="${1:-live_out/live/run.jsonl}"; shift 2>/dev/null || true
    exec $PY -m mdg.viewer.app "$SRC" --host 127.0.0.1 --port "${PORT:-8787}" "$@" ;;

  status)   # read-only 테스트베드 스냅샷 (컨테이너 + run.jsonl 탐지 tail); 상태변경 0
    _load_env
    : "${SSH_KEY:?set SSH_KEY in .env}"; : "${TESTBED:?set TESTBED_HOST/TESTBED_USER in .env}"
    RJ="${RUN_JSONL:-~/mdg/live_out/live/run.jsonl}"
    echo "== 컨테이너 =="
    ssh -i "$SSH_KEY" "$TESTBED" "docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null | head -25"
    echo "== run.jsonl 탐지 tail =="
    ssh -i "$SSH_KEY" "$TESTBED" "grep -aE 'BACKDOOR_5762|Unauthorized_Command|PFCP_Delete_Attempt|backdoor_drop' $RJ 2>/dev/null | tail -5" \
      || echo "  (run.jsonl 미존재/미탐지)" ;;

  help|*)
    cat <<'H'
defense_agent(MDG) 런처 — ./dah.sh <명령>   (에이전트 본체는 python -m mdg.*)
  verify     무결성 게이트 단일 러너 (오프라인·무해)                  → verify.py
  test       pytest 회귀 (기준선 ~192 passed / 2 skipped; SKIP=langgraph 부재 예상)
  campaign   오프라인 결정론 6공격 캠페인 → report.json (live_execution_count=0)
  autorun    자율런 (DRY 기본; 실 DROP 은 MDG_ALLOW_LIVE=1 operator-go)
  live       온-테스트베드 오케스트레이션 검증 (read-only; ALLOW_LIVE=1 시 집행)  [.env 필요]
  viewer     read-only 뷰어 (127.0.0.1:8787 · 루프백 바인드 PS-8)
  status     read-only 테스트베드 스냅샷 (docker ps + 탐지 tail)              [.env 필요]
자세히: QUICKSTART.md
H
    ;;
esac
