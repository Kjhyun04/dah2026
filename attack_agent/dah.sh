#!/usr/bin/env bash
# dah.sh — attack_agent 단일 런처(유일한 셸 진입점). 나머지 .sh 는 사이드카 내부 공격도구일 뿐이다.
#   에이전트 본체는 파이썬(run.py / run_live_gate5.py). 이 스크립트는 env 로딩 + 다중 netns 조율만 감싼다.
#   사용: ./dah.sh <verify|recon|campaign|land|viewer|status|help> [flags]
set -uo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
export PYTHONDONTWRITEBYTECODE=1

# 테스트베드 .env-aria(감독 ARIA 복호키) 경로 자동탐색: 클론 형제 dir(../testbed) → $HOME/testbed
#   → $HOME/dah2026/testbed. git clone(cp positioning 없이) 배포는 testbed 가 attack_agent 의 형제라,
#   기존 $HOME/testbed 하드코딩이 빗나가 "ARIA key 없음"으로 실패했음. (키는 절대 커밋 안 됨 — 런타임 로드)
_ARIA_F=""; _SIB="$(cd .. 2>/dev/null && pwd)"
for _f in "${_SIB}/testbed/.env-aria" "$HOME/testbed/.env-aria" "$HOME/dah2026/testbed/.env-aria"; do
  [ -f "$_f" ] && { _ARIA_F="$_f"; break; }
done

_load_env() {
  [ -f .env ] && { set -a; . .env; set +a; }                         # 배포 설정(.env.example 복사)
  [ -f .env.openrouter ] && { set -a; . .env.openrouter; set +a; }   # OPENROUTER_API_KEY
  if [ -z "${ARIA_KEY:-}" ] && [ -n "$_ARIA_F" ]; then                         # 감독 복호키(경로 자동탐색)
    export ARIA_KEY="$(grep -oE '[0-9a-fA-F]{64}' "$_ARIA_F" | head -1)"
  fi
}

cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in

  verify)   # 8개 무결성 게이트 단일 러너 (오프라인·무해)
    exec $PY verify.py ;;

  recon)    # 정찰 폐루프 (오프라인 mock 기본; 실측은 --backend local)
    _load_env
    exec $PY run.py --config configs/config.testbed.yaml --goal goals/goal.testbed.yaml "$@" ;;

  campaign) # ── 라이브 캠페인 + 독립 감독 (검증된 2-프로세스 오케스트레이션) ──
    # 감독 = gcs_proxy netns(nsenter)에서 14555 ARIA 복호  ·  캠페인 = 호스트 netns live LLM
    # (run_live_gate5 의 in-proc 감독은 netns 불일치라 반드시 분리 실행)
    _load_env
    CONFIG="${CONFIG:-configs/config.live.yaml}"; GOAL="${GOAL:-goals/goal.p4.yaml}"
    SUP_WINDOW="${SUP_WINDOW:-200}"; TAP="${TAP:-gcs_proxy}"
    : "${OPENROUTER_API_KEY:?export OPENROUTER_API_KEY (또는 .env.openrouter) 필요}"
    ARIA="$(grep -oE '[0-9a-fA-F]{64}' "${_ARIA_F:-/nonexistent}" 2>/dev/null | head -1)"
    [ -n "$ARIA" ] || { echo "ERROR: ARIA key 없음 — testbed .env-aria(../testbed | ~/testbed | ~/dah2026/testbed) 미발견. 테스트베드 bringup 을 먼저 실행하세요."; exit 1; }
    GCS_PID="$(docker inspect -f '{{.State.Pid}}' "$TAP" 2>/dev/null)"
    [ -n "$GCS_PID" ] || { echo "ERROR: tap 컨테이너 $TAP PID 해석 실패"; exit 1; }
    mkdir -p runs
    echo "GATE5_START $(date -u +%H:%M:%S) config=$CONFIG goal=$GOAL window=${SUP_WINDOW}s"
    sudo -n nsenter -t "$GCS_PID" -n env ARIA_KEY="$ARIA" \
      "$PY" run_supervisor_standalone.py "$GOAL" "$SUP_WINDOW" > runs/gate5_sup.log 2>&1 &
    SUP=$!; sleep 3
    echo "CAMPAIGN $(date -u +%H:%M:%S)"
    "$PY" run_live_gate5.py --config "$CONFIG" --goal "$GOAL" --skip-supervisor > runs/gate5_camp.log 2>&1
    echo "CAMPAIGN_EXIT=$? $(date -u +%H:%M:%S)"
    wait "$SUP"; echo "SUP_EXIT=$? $(date -u +%H:%M:%S)"
    "$PY" -c "from viewer.ingest import frames_from_evaluation, load_evaluation; import json; ev=load_evaluation('evaluation_live.json'); fr=frames_from_evaluation(ev or {}); open('supervisor_live.jsonl','w',encoding='utf-8').write(chr(10).join(json.dumps(x,ensure_ascii=False) for x in fr)); print('COMMS_FRAMES='+str(len(fr)))" 2>&1
    echo "== 결과 =="; grep -hE 'CAMPAIGN:|SUP_DONE' runs/gate5_camp.log runs/gate5_sup.log 2>/dev/null | tail -3
    echo "GATE5_DONE → run_live.jsonl · evaluation_live.json · supervisor_live.jsonl" ;;

  land)     # ── 지속 착륙 시각화 데모 (3중 증거) · 명시 승인 하 전용 ──
    TAP="${TAP:-gcs_proxy}"; VICTIM="${VICTIM:-uav_ue}"; ATTACKER="${ATTACKER:-attacker_ue}"; SUP_WINDOW="${SUP_WINDOW:-120}"
    mkdir -p runs; echo "LAND_START $(date -u +%H:%M:%S)"
    ARIA="$(grep -oE '[0-9a-fA-F]{64}' "${_ARIA_F:-/nonexistent}" 2>/dev/null | head -1)"
    GCS_PID="$(docker inspect -f '{{.State.Pid}}' "$TAP" 2>/dev/null)"
    UAV_IP="$(docker exec "$VICTIM" ip -4 -o addr show tun_srsue 2>/dev/null | grep -oE '10\.45\.[0-9]+\.[0-9]+' | head -1)"
    echo "resolved uav_ip=${UAV_IP:-<discover>} gcs_pid=${GCS_PID:-none}"
    SUP=""
    if [ -n "$GCS_PID" ] && [ -n "$ARIA" ]; then
      sudo -n nsenter -t "$GCS_PID" -n env ARIA_KEY="$ARIA" \
        "$PY" run_supervisor_standalone.py goals/goal.land.yaml "$SUP_WINDOW" > runs/land_sup.log 2>&1 &
      SUP=$!
    fi
    ( for i in $(seq 1 26); do echo "$(date -u +%H:%M:%S) $(curl -s -m3 http://127.0.0.1:8080/stats)"; sleep 5; done ) > runs/land_dash.log 2>&1 &
    POLL=$!; sleep 2
    echo "INJECT_LAUNCH $(date -u +%H:%M:%S)"
    docker run --rm -i --network "container:$ATTACKER" dahv2/air python3 - "$UAV_IP" < land_demo.py > runs/land_inject.log 2>&1
    echo "INJECT_EXIT=$? $(date -u +%H:%M:%S)"
    wait "$POLL" 2>/dev/null || true
    [ -n "$SUP" ] && { wait "$SUP" 2>/dev/null || true; }
    echo "== 착륙 결과 =="; grep -E 'BASELINE|INJECTED|LANDED' runs/land_inject.log 2>/dev/null | grep -vE 'Unable to find|Pulling|Digest' | head
    echo "LAND_DONE → runs/land_{inject,dash,sup}.log" ;;

  viewer)   # 뷰어 3패널 (127.0.0.1:8090)
    _load_env
    exec $PY -m viewer.server --action-log run_live.jsonl --evaluation evaluation_live.json \
      --comms-stream supervisor_live.jsonl --port 8090 --host 127.0.0.1 "$@" ;;

  status)   # 컨테이너 + 드론 상태
    echo "== 컨테이너 =="; docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null | head -25
    echo "== 드론 (5762 readback) =="
    docker run --rm --network container:uav_ue dahv2/air python3 -c "
from pymavlink import mavutil; import time
m=mavutil.mavlink_connection('tcp:127.0.0.1:5762'); m.wait_heartbeat(timeout=8)
hb=gp=None; end=time.time()+5
while time.time()<end and (hb is None or gp is None):
    x=m.recv_match(type=['HEARTBEAT','GLOBAL_POSITION_INT'],blocking=True,timeout=2)
    if not x: continue
    if x.get_type()=='HEARTBEAT' and x.get_srcComponent()==1: hb=x
    if x.get_type()=='GLOBAL_POSITION_INT': gp=x
print('  mode', hb.custom_mode if hb else None, 'armed', bool(hb.base_mode&128) if hb else None,
      'rel_alt', round(gp.relative_alt/1000,2) if gp else None)
" 2>/dev/null | grep -vE 'Unable to find|Pulling|Digest|Status:|docker.io|Downloaded' || echo "  (드론 상태 읽기 실패)" ;;

  help|*)
    cat <<'H'
attack_agent 런처 — ./dah.sh <명령>   (에이전트 본체는 python run.py / run_live_gate5.py)
  verify     8개 무결성 게이트 (오프라인·무해)
  recon      정찰 폐루프 (오프라인 mock)
  campaign   라이브 캠페인 + 독립 감독 (헤드라인)   [OPENROUTER_API_KEY 필요]
  land       지속 착륙 시각화 데모 (대시보드 고도↓)  [명시 승인 하]
  viewer     뷰어 3패널 (127.0.0.1:8090)
  status     컨테이너 + 드론 상태
자세히: QUICKSTART.md
H
    ;;
esac
