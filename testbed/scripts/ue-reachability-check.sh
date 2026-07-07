#!/usr/bin/env bash
# DAH R3 — UE 격리 미비 취약점 실증 (읽기전용). Open5GS UPF는 UE-to-UE를 유저스페이스
# 스위칭 → 커널 iptables 격리 불가(검증됨). 아래는 공격 기준선 도달성 근거.
set -uo pipefail
UAV=10.45.0.3; ATK_HOST=attacker_ue; SGI_C2=172.30.0.10
p(){ docker exec "$1" ping -c2 -W2 "$2" >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED; }
echo "[UE 격리 점검] $(date -u +%FT%TZ)"
echo "  attacker_ue(10.45.0.4) -> UAV UE $UAV      : $(p $ATK_HOST $UAV)   # 취약: UE격리시 BLOCKED이어야"
echo "  attacker_ue -> SGi C2 $SGI_C2   : $(p $ATK_HOST $SGI_C2)   # 정상 도달(같은 APN=SGi)"
echo "  UAV UE      -> SGi C2 $SGI_C2   : $(p uav_ue $SGI_C2)   # C2 무영향 기준"
