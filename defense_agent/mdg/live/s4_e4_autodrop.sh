#!/usr/bin/env bash
# ==============================================================================
# s4_e4_autodrop.sh — S4 / E4 자율 차단 실증 (단일 가역 상태변경, operator 승인)
#
#   흐름: read-only preflight(역할해석 + attacker≠UAV assert)
#         → attacker 지속 무서명 주입 → command 도메인 Red 유도
#         → MDG 자율 nsenter_input_drop 집행 (allow_live=True, uav_ue netns INPUT -s attacker)
#         → E4 effect_confirm: 주입 트래픽 실차단 + UAV C2(lo:14550) 무영향(self-DoS 0)
#         → revert(iptables -D) → 규칙 0 + 도달성 원복 확인.
#
#   ★ 유일한 라이브 상태변경 스텝. operator 서면 승인 + allow_live=True 창 안에서만.
#   ★ 안전 불변: DROP `-s` 는 반드시 attacker(IMSI002) IP, 절대 UAV(IMSI001) IP 아님.
#     assert 실패 시 집행 전 abort. revert 는 EXIT trap 으로 항상 보장(멱등 -D).
#
#   전제: MDG 자율런(run_autonomous.sh)이 allow_live=True 로 이미 기동돼 있음.
#         이 스크립트는 공격 주입 + read-only 검증 + 안전망 revert 를 오케스트레이션.
# ==============================================================================
set -euo pipefail

SSH_KEY="${SSH_KEY:?set SSH_KEY in .env}"
TESTBED="${TESTBED:?set TESTBED (user@host) in .env}"
UAV_IMSI="001010000000001"       # 보호대상
ATK_IMSI="001010000000002"       # 차단대상
TM1_TOOL="~/dah_exec/A_TM1/tm1_inject_oracle.py"
RUN_JSONL="${RUN_JSONL:-~/mdg/live_out/live/run.jsonl}"
ENFORCE_CONTAINER="${ENFORCE_CONTAINER:-uav_ue}"   # chokepoint netns (impl-constraint 확정: INPUT=live path)
DROP_POLL_MAX=20                 # MDG 자율 DROP 대기 폴 횟수 (×3s)

ro() { ssh -i "$SSH_KEY" "$TESTBED" "$@"; }
say() { printf '\n[s4] %s\n' "$*"; }
die() { printf '\n[s4][ABORT] %s\n' "$*" >&2; exit 1; }

# --- S1 preflight: 역할·엔드포인트 해석 (read-only) -------------------------
say "preflight (read-only): 역할해석 (attacker/UAV IP + enforce_pid)"
SMF=$(ro "docker ps --format '{{.Names}}' | grep -i smf | head -1") || die "smf 미탐지"

UAV_IP=$(ro "docker logs $SMF 2>&1 | grep -oE 'IMSI\\[$UAV_IMSI\\][^\\n]*IPv4\\[[0-9.]+\\]' | grep -oE 'IPv4\\[[0-9.]+\\]' | grep -oE '[0-9.]+' | tail -1") || true
ATK_IP=$(ro "docker logs $SMF 2>&1 | grep -oE 'IMSI\\[$ATK_IMSI\\][^\\n]*IPv4\\[[0-9.]+\\]' | grep -oE 'IPv4\\[[0-9.]+\\]' | grep -oE '[0-9.]+' | tail -1") || true
# tun-scan 교차확인(stage-2, read-only): UE-pool tun IP. SMF 세션 IP 와 다를 수 있음 — 둘 다 로그.
ENFORCE_PID=$(ro "docker inspect -f '{{.State.Pid}}' $ENFORCE_CONTAINER 2>/dev/null") || true

say "UAV_IP(IMSI001)=$UAV_IP"
say "ATK_IP(IMSI002)=$ATK_IP  <- DROP -s 대상"
say "ENFORCE_PID($ENFORCE_CONTAINER)=$ENFORCE_PID"

# --- ★ 안전 assert (fail-closed): 집행 전 반드시 통과 ----------------------
[ -n "$ATK_IP" ]     || die "attacker IP 미해석 — DROP 대상 불명, 집행 금지"
[ -n "$UAV_IP" ]     || die "UAV IP 미해석 — 보호대상 불명, 집행 금지"
[ -n "$ENFORCE_PID" ] && [ "$ENFORCE_PID" -gt 0 ] 2>/dev/null || die "enforce_pid 미해석 — 집행 금지"
[ "$ATK_IP" != "$UAV_IP" ] || die "attacker_ip == uav_ip — self-DoS 위험, 집행 금지"
# enforce netns(uav_ue) ≠ source(attacker) distinct 도 확인: uav_ue 는 UAV 컨테이너이며
# -s 는 attacker IP 이므로 2-endpoint 봉쇄 성립. UAV IP 가 -s 로 새지 않음을 재확인.
case "$ATK_IP" in "$UAV_IP") die "DROP -s 가 UAV IP — 절대 금지";; esac
say "★ 안전 assert 통과: DROP -s=$ATK_IP ≠ UAV=$UAV_IP, enforce_pid=$ENFORCE_PID"

DROP_MATCH="$ATK_IP.*DROP"       # iptables -S 규칙 매칭 (attacker 만)

# --- 도달성 baseline (read-only, collateral 0 조건) -------------------------
say "baseline: attacker→UAV 도달성 (collateral 0 조건 참고)"
ro "sudo nsenter --target $ENFORCE_PID --net -- iptables -w -S INPUT 2>/dev/null | grep -E '$DROP_MATCH' && echo '경고: 기존 DROP 존재' || echo 'INPUT 에 attacker DROP 없음(정상 baseline)'"

# --- ★ 안전망 revert: EXIT trap 으로 항상 attacker DROP 제거 (멱등) --------
safe_revert() {
  say "revert (안전망): enforce netns 에서 attacker DROP 제거 (멱등 -D)"
  # 도구 종료 먼저
  ro "pkill -f 'tm1_inject_oracle.py' 2>/dev/null || true"
  # attacker 규칙이 있으면 반복 -D. UAV IP 는 절대 건드리지 않음(-s=$ATK_IP 고정).
  local i left
  for i in 1 2 3 4 5; do
    ro "sudo nsenter --target $ENFORCE_PID --net -- iptables -w -D INPUT -s $ATK_IP -j DROP 2>/dev/null || true"
    left=$(ro "sudo nsenter --target $ENFORCE_PID --net -- iptables -w -S INPUT 2>/dev/null | grep -cE '$DROP_MATCH'") || true
    left="${left:-0}"
    say "revert 확인 $i: 잔존 attacker DROP=$left"
    [ "$left" -eq 0 ] 2>/dev/null && break
  done
  # 복원 재검증: 규칙 0 + UAV C2 정상
  local hb
  hb=$(ro "sudo timeout 4 nsenter --target ${UAV_PID:-$ENFORCE_PID} --net -- tcpdump -l -n -q -c 3 -i lo udp port 14550 2>/dev/null | grep -c ' IP '") || true
  say "복원 재검증: 잔존 attacker DROP=${left:-?}  UAV lo:14550 HB=${hb:-0}"
  [ "${left:-1}" -eq 0 ] 2>/dev/null || printf '\n[s4][경고] attacker DROP 잔존 — operator 수동 -D + allow_live=False 원복 필요\n' >&2
}
trap 'safe_revert' EXIT

UAV_PID=$(ro "docker inspect -f '{{.State.Pid}}' uav_ue 2>/dev/null") || UAV_PID="$ENFORCE_PID"

# --- DO: attacker 지속 무서명 주입 (command Red 유도) ----------------------
say "DO: attacker 지속 무서명 주입 (배경) → command 도메인 Red 유도"
ro "cd ~/dah_exec/A_TM1 && nohup python3 tm1_inject_oracle.py --unsigned --cmd DO_SET_MODE --loop --interval 0.5 > ~/s4_inject.log 2>&1 & echo inject_pid=\$!"

# uav_proxy 해석 + 서명검증 실패 카운터 BEFORE (E4 판정용 diff 기준)
UAVPX=$(ro "docker ps --format '{{.Names}}' | grep -i uav_proxy | head -1") || true
UAVPX="${UAVPX:-uav_proxy}"
sleep 3
FAIL_A=$(ro "docker logs $UAVPX --since 6s 2>&1 | grep -cE '서명검증 실패|SITL 차단'" 2>/dev/null) || true

# --- MDG 자율 DROP 대기 (read-only 폴) -------------------------------------
say "MDG 자율 nsenter_input_drop 집행 대기 (allow_live=True) — enforce netns INPUT -s $ATK_IP"
DROP_INSTALLED=0
for i in $(seq 1 $DROP_POLL_MAX); do
  RULES=$(ro "sudo nsenter --target $ENFORCE_PID --net -- iptables -w -S INPUT 2>/dev/null | grep -E '$DROP_MATCH' || true")
  APPLIED=$(ro "grep -a 'nsenter_input_drop' $RUN_JSONL 2>/dev/null | grep -a 'confirmed\\|applied' | tail -1 || true")
  say "폴 $i/$DROP_POLL_MAX: netns rule='${RULES:-none}'"
  if [ -n "$RULES" ]; then
    # ★ 설치된 규칙이 attacker 만 대상인지 재확인 (UAV IP 미포함)
    case "$RULES" in *"$UAV_IP"*) die "설치된 DROP 이 UAV IP 포함 — 즉시 revert (EXIT trap)";; esac
    DROP_INSTALLED=1; say "★ MDG 자율 DROP 설치 확인: $RULES"; break
  fi
  sleep 3
done
[ "$DROP_INSTALLED" -eq 1 ] || say "경고: 폴 한도 내 자율 DROP 미관측 (command Red 미도달 / allow_live off 가능)"

# --- VERIFY (read-only): E4 주입 트래픽 실차단 + self-DoS 0 -----------------
if [ "$DROP_INSTALLED" -eq 1 ]; then
  say "effect_confirm: DROP 후 주입 트래픽 차단 관측 (~8s 창)"
  sleep 8
  FAIL_B=$(ro "docker logs ${UAVPX:-uav_proxy} --since 8s 2>&1 | grep -cE '서명검증 실패|SITL 차단'" 2>/dev/null) || true
  FAIL_B="${FAIL_B:-0}"; FAIL_A="${FAIL_A:-0}"
  say "서명검증실패 rate: 주입직후=$FAIL_A  DROP후8s=$FAIL_B"
  # DROP 이 attacker 주입을 chokepoint 전에서 끊으면 uav_proxy 도달 자체가 감소 → 실패카운터 증가 정지
  [ "$FAIL_B" -le "$FAIL_A" ] 2>/dev/null \
    && say "★ E4: DROP 후 주입 트래픽 도달 감소(서명검증 실패 증가 정지) — 실차단 실증" \
    || say "관찰: 서명검증 실패 여전 — chokepoint/enforce netns 재확인 필요"

  # UAV C2 무영향 (self-DoS 0)
  HB=$(ro "sudo timeout 4 nsenter --target $UAV_PID --net -- tcpdump -l -n -q -c 3 -i lo udp port 14550 2>/dev/null | grep -c ' IP '") || true
  say "UAV C2 무영향: lo:14550 HB=${HB:-0} 라인 (self-DoS 0 조건: ≥1)"
  [ "${HB:-0}" -ge 1 ] 2>/dev/null || die "DROP 후 UAV HB 소멸 — self-DoS 의심, 즉시 revert (EXIT trap §5 ABORT)"
  say "★ UAV C2 정상 — self-DoS 0"

  say "VERIFY: run.jsonl applied[nsenter_input_drop].confirmed"
  ro "grep -a 'nsenter_input_drop' $RUN_JSONL | tail -3" || say "경고: run.jsonl drop 기록 미확인"
fi

# --- 복원은 EXIT trap(safe_revert) 에서 수행 (규칙 -D + 재검증) ------------
say "DO/VERIFY 완료 — EXIT trap 이 attacker DROP revert + 도달성 원복 확인 수행"
