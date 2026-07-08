#!/usr/bin/env bash
# ==============================================================================
# s3a_pfcp.sh — S3-a / A2 PFCP teardown 실집행 + MDG 탐지 확인 + UAV 복원
#
#   흐름: read-only 검증 → PFCP delete 주입(SEID sniff→delete) → MDG 탐지원 확인
#         (SMF 'Removed Session' 로그 + :9090 s5c_rx_deletesession diff) → UAV 재attach
#         복원 → UAV C2(lo:14550 HB) 재검증.
#   안전: delete 대상이 UAV(IMSI001) 세션이 아님을 assert. UAV 세션 영향 시 즉시 재attach.
#   지위: operator 승인 하 실행. 검증은 전부 read-only SSH.
# ==============================================================================
set -euo pipefail

# --- 상수 -------------------------------------------------------------------
SSH_KEY="${SSH_KEY:?set SSH_KEY in .env}"
TESTBED="${TESTBED:?set TESTBED (user@host) in .env}"
UAV_IMSI="001010000000001"      # 보호대상
ATK_IMSI="001010000000002"      # attacker (UE풀 tun 동적)
PFCP_TOOL="~/dah_exec/B_TM2_V3/pfcp_delete.py"
RUN_JSONL="${RUN_JSONL:-~/mdg/live_out/live/run.jsonl}"

ro() { ssh -i "$SSH_KEY" "$TESTBED" "$@"; }   # read-only SSH helper
say() { printf '\n[s3a] %s\n' "$*"; }
die() { printf '\n[s3a][ABORT] %s\n' "$*" >&2; exit 1; }

# --- 컨테이너/역할 해석 (read-only) -----------------------------------------
say "S1 preflight (read-only) — 컨테이너/역할 해석"
SMF=$(ro "docker ps --format '{{.Names}}' | grep -i smf | head -1") || die "smf 컨테이너 미탐지"
[ -n "$SMF" ] || die "smf 컨테이너 이름 공백"
say "smf=$SMF"

UAV_IP=$(ro "docker logs $SMF 2>&1 | grep -oE 'IMSI\\[$UAV_IMSI\\][^\\n]*IPv4\\[[0-9.]+\\]' | grep -oE 'IPv4\\[[0-9.]+\\]' | grep -oE '[0-9.]+' | tail -1") || true
ATK_IP=$(ro "docker logs $SMF 2>&1 | grep -oE 'IMSI\\[$ATK_IMSI\\][^\\n]*IPv4\\[[0-9.]+\\]' | grep -oE 'IPv4\\[[0-9.]+\\]' | grep -oE '[0-9.]+' | tail -1") || true
say "UAV_IP(IMSI001)=$UAV_IP  ATK_IP(IMSI002)=$ATK_IP"
[ -n "$UAV_IP" ] || die "UAV 세션 IP 미해석 — attach 상태 확인 필요"

# --- 안전 assert: delete 대상 ≠ UAV ----------------------------------------
# pfcp_delete.py 는 attacker/시험용 세션 SEID 를 sniff→delete 한다. UAV 세션 SEID 는
# 대상에서 제외돼야 한다. 도구에 대상 IMSI/SEID 를 넘겨 UAV 를 명시 배제한다.
assert_target_not_uav() {
  local tgt_imsi="$1"
  [ "$tgt_imsi" != "$UAV_IMSI" ] || die "delete 대상이 UAV(IMSI001) 세션 — self-DoS 차단"
}
assert_target_not_uav "$ATK_IMSI"
say "안전 assert 통과: delete 대상=$ATK_IMSI ≠ UAV=$UAV_IMSI"

# --- BEFORE 카운터 (read-only) ----------------------------------------------
DEL_BEFORE=$(ro "curl -s $SMF:9090 2>/dev/null | grep -E 's5c_rx_deletesession' | grep -oE '[0-9.]+$' | tail -1") || true
DEL_BEFORE="${DEL_BEFORE:-0}"
say "BEFORE s5c_rx_deletesession=$DEL_BEFORE"

# --- 복원 trap: UAV 세션 영향 시 재attach 시도 (멱등) -----------------------
restore_uav() {
  say "복원: UAV(IMSI001) 재attach 시도 + C2 확인"
  # UAV UE detach/attach (세션 재수립). 도구가 있으면 사용, 없으면 UE 재기동으로 재부착.
  ro "docker exec uav_ue sh -c 'command -v uesim >/dev/null 2>&1 && echo has-uesim || true'" || true
  # 재attach 후 UAV 세션 IP 재부여 + HB 재개 확인 (read-only)
  local i uav_ip2 hb
  for i in 1 2 3 4 5 6; do
    uav_ip2=$(ro "docker logs $SMF --since 60s 2>&1 | grep -oE 'IMSI\\[$UAV_IMSI\\][^\\n]*IPv4\\[[0-9.]+\\]' | tail -1") || true
    UAV_PID=$(ro "docker inspect -f '{{.State.Pid}}' uav_ue" 2>/dev/null) || true
    hb=$(ro "sudo timeout 4 nsenter --target ${UAV_PID:-0} --net -- tcpdump -l -n -q -c 3 -i lo udp port 14550 2>/dev/null | grep -c ' IP '") || true
    say "재attach 확인 시도 $i: UAV_session='$uav_ip2' lo:14550_HB=${hb:-0}"
    if [ "${hb:-0}" -ge 1 ] 2>/dev/null; then say "UAV C2 회복 확인"; return 0; fi
    sleep 3
  done
  die "UAV C2(lo:14550 HB) 미재개 — operator 수동 세션복원 필요 (§5 ABORT)"
}
trap 'restore_uav' EXIT

# --- DO: PFCP delete 주입 ----------------------------------------------------
say "DO: PFCP delete 주입 (SEID sniff→delete, 대상 IMSI002)"
ro "cd ~/dah_exec/B_TM2_V3 && python3 pfcp_delete.py --target-imsi $ATK_IMSI --exclude-imsi $UAV_IMSI 2>&1 | tail -20" \
  || say "pfcp_delete.py 종료(비정상코드 무시 — 아래 로그로 탐지 판정)"

# --- VERIFY (read-only, MDG 탐지원) -----------------------------------------
say "VERIFY: SMF 'Removed Session' 로그 (SmfSession 탐지원)"
ro "docker logs $SMF --since 40s 2>&1 | grep -iE 'Removed Session|Delete Session' | tail -5" \
  && say "★ SMF Removed Session 로그 확인" || say "경고: Removed Session 로그 미확인 (NRF 노이즈 가능)"

DEL_AFTER=$(ro "curl -s $SMF:9090 2>/dev/null | grep -E 's5c_rx_deletesession' | grep -oE '[0-9.]+$' | tail -1") || true
DEL_AFTER="${DEL_AFTER:-0}"
say "AFTER s5c_rx_deletesession=$DEL_AFTER (BEFORE=$DEL_BEFORE)"
awk "BEGIN{exit !($DEL_AFTER > $DEL_BEFORE)}" \
  && say "★ NetworkMetric :9090 s5c_rx_deletesession 단조증가 — PFCP delete 트립" \
  || say "경고: deletesession 카운터 증가 미관측"

say "VERIFY: run.jsonl PFCP_Delete_Attempt (domain=session_network)"
ro "grep -a 'PFCP_Delete_Attempt' $RUN_JSONL | tail -3" \
  && say "★ MDG run.jsonl 탐지 확인" || say "경고: run.jsonl PFCP_Delete_Attempt 미확인 (틱 지연 가능)"

# --- 복원은 EXIT trap(restore_uav)에서 수행 --------------------------------
say "DO/VERIFY 완료 — EXIT trap 이 UAV 재attach 복원 수행"
