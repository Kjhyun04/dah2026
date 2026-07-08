#!/usr/bin/env bash
# 31-verify-ran.sh — P3 검증 = 게이트 G0 (attach + PDCP 암호 협상)
set -uo pipefail
log(){ printf '\033[1;36m[G0]\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$*"; FAIL=1; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$*"; }
FAIL=0

log "1) 컨테이너 가동 (ran_enb, uav_ue)"
for c in ran_enb uav_ue; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && ok "$c up" || bad "$c 미가동"
done

log "2) UE attach — tun_srsue IP 할당 (10.45.0.x)"
IP="$(docker exec uav_ue ip -o -4 addr show tun_srsue 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
if echo "$IP" | grep -qE '^10\.45\.'; then ok "tun_srsue = $IP"; else bad "tun IP 없음 (attach 실패)"; fi

log "3) MME attach 완료 로그"
docker logs epc 2>&1 | grep -qiE 'Attach complete' && ok "MME 'Attach complete'" || warn "MME attach 로그 미확인(재기동 로그일 수 있음)"

log "4) PDCP 암호 협상 = EEA2/EIA2 (CONFIG_SPEC C)"
docker exec ran_enb sh -c 'grep -qiE "Selected EEA2|128-EEA2" /tmp/enb.log 2>/dev/null' \
  && ok "AS/PDCP 암호 = EEA2 (AES)" || bad "AS 암호 EEA2 아님 — [expert] eea_pref_list 확인"
docker exec ran_enb sh -c 'grep -qiE "Selected EIA2|128-EIA2" /tmp/enb.log 2>/dev/null' \
  && ok "AS 무결성 = EIA2" || warn "EIA2 미확인"
docker exec ran_enb sh -c 'grep -iE "Selected EEA|Selected EIA|Configuring security" /tmp/enb.log 2>/dev/null | tail -3' | sed 's/^/      /' || true

echo
[ "$FAIL" -eq 0 ] && log "G0 통과 ✅ — P4(베어러+SGi) 진입 가능" || { log "G0 실패 ✗ — 로그 확인"; exit 1; }
