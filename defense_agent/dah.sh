#!/usr/bin/env bash
# dah.sh — defense_agent(MDG) 단일 런처(유일한 셸 진입점). 나머지 mdg/live/*.sh 는
#   테스트베드 온-호스트 검증 스텝일 뿐이다. 에이전트 본체는 파이썬(python -m mdg.*).
#   이 스크립트는 env 로딩(.env) + TESTBED/SSH_KEY export + 서브커맨드 디스패치만 감싼다.
#   사용: ./dah.sh <verify|test|campaign|autorun|live|viewer|status|help> [flags]
#
#   2대 불변식: ① 결정론 라우팅(제어흐름은 LLM 불가시)  ② leak-0 실행(비밀/프로세스 잔여 0).
#   코드 기본(env 미설정 시)은 오프라인·read-only. 실 상태변경(가역 DROP/pause)은 MDG_ALLOW_LIVE=1(operator-go).
#   ★주의: 배포된 .env.example 은 SITL 자율복구 데모용으로 MDG_ALLOW_LIVE=1/MDG_OPERATOR_AUTO=1 로 실려 있어
#   `cp .env.example .env` 시 자율집행 포스처가 된다(monitor/autorun 이 stderr 로 LIVE 경고 배너 출력). 실기체/프로덕션=0.
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
  # MDG_OPERATOR_AUTO(샌드박스 OPER 자동승인, 신규) → .env 소싱(set -a)으로 이미 export 되나,
  # 미설정 시에도 파이썬 파서가 안전 기본 False 로 처리(명시만; 값 강제 안 함).
  export MDG_OPERATOR_AUTO="${MDG_OPERATOR_AUTO:-}"
}

cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in

  verify)   # 무결성 게이트 단일 러너 (오프라인·무해, 테스트베드/비밀 불필요)
    exec $PY verify.py ;;

  test)     # pytest 회귀 (기준선 ~192 passed / 2 skipped)
    # pytest 는 dev 의존 → 'pip install -e ".[dev]"'. 없으면 안내(감독관 친화).
    # langgraph 부재 시 그래프-컴파일 테스트만 SKIP(예상, 실패 아님).
    $PY -c "import pytest" 2>/dev/null || { echo "pytest 미설치 → 'pip install -e \".[dev]\"' 후 재실행 (또는 오프라인 러너: $PY mdg/tests/test_p1_engine.py)"; exit 1; }
    exec $PY -m pytest mdg/tests -q "$@" ;;

  campaign) # 오프라인 결정론 6공격 캠페인 → report.json (헤드라인 오프라인 증거)
    # live_execution_count 은 0 이어야 한다(테스트베드 무접속, 순수 결정론 재생).
    OUT="${1:-campaign_out}"; shift 2>/dev/null || true
    exec $PY -m mdg.campaign.e2e "$OUT" "$@" ;;

  autorun)  # 자율런 1회 (배치: quiescence/max_iters 에서 종료) — DRY 기본
    # 실 actuation 은 MDG_ALLOW_LIVE truthy(operator-go) 일 때만 단일 가역 DROP 창 개방.
    _load_env
    OUT="${OUT:-./live_out}"; RID="${RUN_ID:-live}"
    exec $PY -m mdg.live_autorun --out "$OUT" --run-id "$RID" "$@" ;;

  monitor)  # ★24/7 상시 감시 데몬 (quiescence 무시, Ctrl-C 까지 계속 관측) — 탐지모델 상시가동
    # 온-호스트 netns 관측(5762 ss / air-tap / PFCP)엔 sudo 필요 → 'sudo -E ./dah.sh monitor' 권장.
    _load_env
    OUT="${OUT:-./live_out}"; RID="${RUN_ID:-monitor}"
    echo "24/7 상시 감시 시작 (Ctrl-C 종료) · 틱 간격 ${INTERVAL:-2}s · MDG_ALLOW_LIVE=${MDG_ALLOW_LIVE:-0}(0=DRY) · MDG_OPERATOR_AUTO=${MDG_OPERATOR_AUTO:-0}(0=escalate)"
    exec $PY -m mdg.live_autorun --out "$OUT" --run-id "$RID" --forever --interval "${INTERVAL:-2}" "$@" ;;

  live)     # 온-테스트베드 오케스트레이션 검증 (read-only 기본; ALLOW_LIVE=1 시 집행 창)
    _load_env
    : "${SSH_KEY:?set SSH_KEY in .env (live 서브커맨드 전용)}"
    : "${TESTBED:?set TESTBED_HOST/TESTBED_USER in .env (live 서브커맨드 전용)}"
    exec bash mdg/live/run_autonomous.sh "$@" ;;

  viewer)   # read-only 뷰어 (루프백 바인드 127.0.0.1 · PS-8) — run.jsonl 3패널
    _load_env
    # 뷰어는 fail-secure(PS-8): 토큰 없으면 모든 데이터 라우트 401. 미설정 시 세션용 랜덤토큰
    # 자동생성(익명 거부 유지) 후 접속 URL 을 그대로 출력 → 감독관은 그 URL 만 브라우저에 붙이면 됨.
    if [ -z "${MDG_VIEWER_TOKEN:-}" ]; then
      export MDG_VIEWER_TOKEN="$(openssl rand -hex 16 2>/dev/null || echo "demo$$")"
      echo "뷰어 토큰(자동생성): $MDG_VIEWER_TOKEN"
    fi
    SRC="${1:-live_out/live/run.jsonl}"; shift 2>/dev/null || true
    echo "★ 브라우저: http://127.0.0.1:${PORT:-8787}/?token=${MDG_VIEWER_TOKEN}  (로컬은 ssh -L 후 localhost)"
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
  autorun    자율런 1회 (배치; quiescence/max_iters 에서 종료; DRY 기본)
  monitor    ★24/7 상시 감시 데몬 (평시 quiescence 무시, Ctrl-C 까지 계속) — netns 관측엔 sudo -E
  live       온-테스트베드 오케스트레이션 검증 (read-only; ALLOW_LIVE=1 시 집행)  [.env 필요]
  viewer     read-only 뷰어 (127.0.0.1:8787 · 루프백 바인드 PS-8)
  status     read-only 테스트베드 스냅샷 (docker ps + 탐지 tail)              [.env 필요]
자세히: QUICKSTART.md
H
    ;;
esac
