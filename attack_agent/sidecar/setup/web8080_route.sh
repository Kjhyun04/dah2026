#!/usr/bin/env bash
# web8080_route.sh — web_backend(172.30.0.20) UE풀 역경로 가역 주입 (Alt-2, netns 헬퍼).
# ============================================================================
# 오프라인 설계 산출물. 운영자가 테스트베드 서버에서만 신중히 실행한다.
# 드론/모드 주입 0 (순수 L3 라우팅). MAVLink/pymavlink/mode 무접촉.
#
# [근본원인] net_sgi=172.30.0.0/24. UE풀 복귀 게이트웨이 = epc_upf SGi = 172.30.0.2.
#   gcs_proxy(.10)·sgi_test(.100) 은 엔트리포인트에서 `ip route replace 10.45.0.0/16
#   via 172.30.0.2` 를 실행(NET_ADMIN 보유) → UE풀 복귀경로 有.
#   web_backend(.20) 은 이 역경로가 없고, 컨테이너에 CAP_NET_ADMIN 부재 →
#   스스로 `ip route add` 불가. 결과: attacker_ue(10.45.0.x)→.20:8080 요청은
#   도달하나 응답 패킷이 172.30.0.1 브리지로 새서 드롭 → half-open → connect 실패.
#   근거: attack_agent_구축과정/SESSION_RECOVERY_83c8f446_20260706.md:1228,
#         exec/logs/00_baseline.log:20,28, ROGUE_UE_REALISM_WORKFLOW.md:96.
#
# [설계] web_backend netns 를 공유하는 라벨드 장수 헬퍼가 NET_ADMIN 으로 경로만
#   외과 주입한다. web_backend 자체는 재생성·cap 변경 없음. 주입된 경로는
#   web_backend netns 소유이므로 헬퍼 제거 후에도 잔존, `ip route del` 로 정확 원복.
#
# [불변식] baseline 선-read 실패 시 미주입(3b) · teardown 은 trap EXIT(finally, #2) ·
#   `docker run --rm` 금지(#2, 장수 헬퍼+exec) · secret 0(R6 무관) · core/ 무접촉(#1·#5).
#
# [경고] `up` 은 recon 이 세우지 못하던 reach(WEB8080) 사실을 물리적으로 재개방한다.
#   이는 forceland(LAND 9·물리·비가역·risk HIGH) 의 require_any precond
#   (reach(gcs14556) ∨ reach(web8080)) 도 재충족시킬 수 있다. 본 스크립트는 모드
#   주입을 전혀 하지 않으나, 운영자는 후속 캠페인에서 forceland 를 반드시 HITL
#   승인 뒤에 유지해야 한다(불변식 3a). 순수 라우팅 도구는 드론안전 판정과 무관.
# ============================================================================
set -euo pipefail

# ---- 오버라이드 계약(환경변수) --------------------------------------------
WEB_C="${WEB_C:-web_backend}"          # 대상 컨테이너(응답경로가 없는 웹 백엔드)
UPF_GW="${UPF_GW:-172.30.0.2}"         # UE풀 복귀 게이트웨이(epc_upf SGi)
UE_POOL="${UE_POOL:-10.45.0.0/16}"     # UE 주소 풀(복귀 대상 프리픽스)
HELPER="${HELPER:-dah_route_web}"      # netns 공유 헬퍼 컨테이너명
HELPER_IMG="${HELPER_IMG:-dahv2/air-tools}"   # iproute2(ip) 포함 이미지
LABEL="dahv2.owner=attack_agent"           # 회수 라벨(불변식 R2)
STATE_DIR="${STATE_DIR:-$HOME/.dah/web8080_route}"
BASELINE="$STATE_DIR/baseline.routes"  # ip route show 덤프(선-read 게이트)
MARK="$STATE_DIR/injected.mark"        # 본 도구가 주입했음의 증거(원복 게이트)

# ---- 내부 함수 ------------------------------------------------------------
die(){ echo "FATAL: $*" >&2; exit 1; }

# 대상 컨테이너 실행확인. 미실행이면 어떤 조작도 하지 않고 중단(비파괴).
need_web(){
  [ "$(docker inspect -f '{{.State.Running}}' "$WEB_C" 2>/dev/null || echo false)" = true ] \
    || die "$WEB_C 미실행 — 중단(비파괴)"
}

# 장수 헬퍼 기동(멱등). 이미 있으면 재사용. `docker run --rm` 금지(불변식 #2).
helper_up(){
  if docker inspect "$HELPER" >/dev/null 2>&1; then
    [ "$(docker inspect -f '{{.State.Running}}' "$HELPER" 2>/dev/null || echo false)" = true ] \
      || docker start "$HELPER" >/dev/null
    return 0
  fi
  docker run -d --name "$HELPER" --label "$LABEL" \
    --network "container:$WEB_C" --cap-add NET_ADMIN \
    "$HELPER_IMG" sleep infinity >/dev/null
}

# teardown(불변식 #2·#3c: finally 로 헬퍼 회수, orphan 0). 실패 무시.
helper_down(){ docker rm -f "$HELPER" >/dev/null 2>&1 || true; }

# 헬퍼 netns(=web_backend netns) 안에서 명령 실행.
hx(){ docker exec "$HELPER" "$@"; }

# UE풀 역경로가 web_backend netns 라우팅 테이블에 이미 존재하는가.
has_route(){
  hx ip route show 2>/dev/null \
    | grep -Eq "^${UE_POOL//./\\.}[[:space:]].*via[[:space:]]${UPF_GW//./\\.}"
}

# baseline 덤프에 역경로가 이미 있었는가(주입 전 원상태 판정).
baseline_has_route(){
  [ -f "$BASELINE" ] && grep -Eq "${UE_POOL//./\\.}.*via.*${UPF_GW//./\\.}" "$BASELINE"
}

# ---- 서브커맨드 -----------------------------------------------------------

# baseline: web_backend netns 현재 라우팅 테이블 저장(선-read 게이트 확립).
cmd_baseline(){
  mkdir -p "$STATE_DIR"
  need_web
  trap helper_down EXIT
  helper_up
  hx ip route show > "$BASELINE"
  echo "baseline saved: $BASELINE"
  if baseline_has_route; then
    echo "NOTE: UE풀 역경로가 baseline 에 이미 존재 → up 는 no-op(원상태 보존)"
  else
    echo "NOTE: UE풀 역경로 부재 확인 → up 시 주입 대상"
  fi
}

# up: baseline 존재 시에만. baseline 에 역경로 부재일 때만 주입. 멱등.
cmd_up(){
  need_web
  [ -f "$BASELINE" ] || die "baseline 먼저 실행 (불변식 3b: 선-read 실패 시 미주입)"
  trap helper_down EXIT
  helper_up
  if baseline_has_route; then
    echo "baseline 에 이미 존재 — 무주입(원상태 보존, MARK 미기록)"
    exit 0
  fi
  if has_route; then
    echo "이미 주입됨(idempotent) — 재주입 생략"
  else
    hx ip route replace "$UE_POOL" via "$UPF_GW"
  fi
  has_route || die "주입 검증 실패 — 경로 미확인"
  : > "$MARK"
  echo "OK: $UE_POOL via $UPF_GW 주입 (원복 = $0 down)"
  echo "경고: reach(WEB8080) 재개방 → forceland precond 재충족 가능. forceland 는 HITL 유지."
}

# verify: 역경로 PRESENT/ABSENT + (dah_tools_ue 있으면) UE→.20:8080 read-only 도달확인.
cmd_verify(){
  need_web
  trap helper_down EXIT
  helper_up
  if has_route; then echo "route: PRESENT"; else echo "route: ABSENT"; fi
  # (선택) UE-vantage 도달확인: dah_tools_ue 사이드카가 있으면 read-only TCP connect.
  if docker inspect dah_tools_ue >/dev/null 2>&1; then
    docker exec dah_tools_ue python3 - <<'PY'
import socket
s = socket.socket(); s.settimeout(2.0)
try:
    s.connect(("172.30.0.20", 8080)); print("ue->web8080: OPEN"); s.close()
except Exception as e:
    print("ue->web8080:", type(e).__name__)
PY
  else
    echo "ue->web8080: SKIP (dah_tools_ue 미기동 — route 존재만으로 유효)"
  fi
}

# down: injected.mark 있을 때만 주입경로 삭제(baseline-존재 경로는 불삭제). mark 제거.
cmd_down(){
  need_web
  if [ ! -f "$MARK" ]; then
    echo "본 도구 주입 흔적 없음 — 경로 무변경(baseline 보존)"
    exit 0
  fi
  trap helper_down EXIT
  helper_up
  hx ip route del "$UE_POOL" via "$UPF_GW" 2>/dev/null || true
  rm -f "$MARK"
  echo "원복 완료: $UE_POOL via $UPF_GW 삭제, MARK 제거"
}

# status: baseline/mark/route 상태 요약.
cmd_status(){
  echo "baseline:        $([ -f "$BASELINE" ] && echo yes || echo no)"
  echo "injected-by-us:  $([ -f "$MARK" ] && echo yes || echo no)"
  need_web
  trap helper_down EXIT
  helper_up
  if has_route; then echo "route:           PRESENT"; else echo "route:           ABSENT"; fi
}

case "${1:-}" in
  baseline) cmd_baseline ;;
  up)       cmd_up ;;
  verify)   cmd_verify ;;
  down)     cmd_down ;;
  status)   cmd_status ;;
  *) echo "usage: $0 {baseline|up|verify|down|status}" >&2; exit 2 ;;
esac
