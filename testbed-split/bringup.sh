#!/usr/bin/env bash
# bringup.sh — 현재 테스트베드(분리코어 epc-split + Rogue-UE 2셀/2UE) 원-커맨드 콜드스타트.
#   근거: RECOVERY_C2_AFTER_RESTORE.md(검증 순서·ZMQ desync 회피) + 각 up 스크립트. (설계 로드맵은 아카이브 분리됨)
#   ★ 절대금지 준수: monolithic up-all.sh/docker-compose.epc.yml 미사용 · eNB·UE 동시 재생성 금지 · --remove-orphans 금지.
#   사용:  bash ~/testbed-split/bringup.sh          # 실제 생성
#          bash ~/testbed-split/bringup.sh --check  # 비파괴 사전검증(아무것도 안 바꿈)
set -uo pipefail
TB="$HOME/testbed"; SPLIT="$HOME/testbed-split"
RAN="$TB/compose/docker-compose.ran.yml"
SGI="$TB/compose/docker-compose.sgi.yml"
EPC="$SPLIT/compose/docker-compose.epc-split.yml"
cd "$TB"
log(){ printf "\n\033[1;35m===== %s =====\033[0m\n" "$*"; }

wait_tun(){ local IP; for i in $(seq 1 30); do IP="$(docker exec "$1" ip -o -4 addr show tun_srsue 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"; [ -n "${IP:-}" ] && { echo "  $1 tun=$IP"; return 0; }; sleep 2; done; echo "  WARN $1 tun 미생성 — docker logs $1"; }
prov(){ local n; n="$(docker exec epc_mongo mongosh open5gs --quiet --eval "db.subscribers.countDocuments({imsi:'$1'})" 2>/dev/null | tail -1)"; if [ "$n" = "1" ]; then echo "  IMSI=$1 skip(등록됨)"; else docker exec -e DB_URI="mongodb://epc_mongo/open5gs" epc_hss open5gs-dbctl add "$1" "$2" "$3" >/dev/null 2>&1 && echo "  +IMSI=$1" || echo "  WARN IMSI=$1 등록실패(epc_hss dbctl)"; fi; }

# ─────────────────────────── 비파괴 사전검증(--check) ───────────────────────────
if [ "${1:-}" = "--check" ]; then
  echo "== bringup 사전검증 (dry-run · 비파괴 · 아무것도 변경 안 함) =="
  fail=0
  echo "[1] 참조 파일 실재"
  for f in "$EPC" "$RAN" "$SGI" scripts/70-aria-up.sh scripts/80-web-up.sh scripts/71-verify-aria.sh scripts/81-verify-web.sh scripts/10-build-images.sh images/web compose/configs/ran/ue2.conf; do
    [ -e "$f" ] && echo "   ok  $f" || { echo "   FAIL 없음: $f"; fail=1; }
  done
  [ -s "$TB/.mav-sign-key" ] && echo "   ok  .mav-sign-key 존재" || echo "   auto-gen 예정 .mav-sign-key (bringup 실행 시 fresh 생성 — git clone 배포 정상)"
  echo "[2] compose 유효성(docker compose config)"
  docker compose -f "$EPC" config -q 2>/dev/null && echo "   ok  epc-split" || { echo "   FAIL epc-split 파싱"; fail=1; }
  docker compose -f "$RAN" config -q 2>/dev/null && echo "   ok  ran" || { echo "   FAIL ran 파싱"; fail=1; }
  docker compose -f "$SGI" config -q 2>/dev/null && echo "   ok  sgi" || { echo "   FAIL sgi 파싱"; fail=1; }
  echo "[3] RAN 서비스 4종(ran_enb·ran_enb2·uav_ue·attacker_ue)"
  svc="$(docker compose -f "$RAN" config --services 2>/dev/null | tr '\n' ' ')"
  for s in ran_enb ran_enb2 uav_ue attacker_ue; do echo "$svc" | grep -qw "$s" && echo "   ok  $s" || { echo "   FAIL 서비스 없음: $s"; fail=1; }; done
  echo "[4] 이미지(없으면 bringup가 자동빌드)"
  for i in dahv2/epc dahv2/ran dahv2/air dahv2/web; do docker image inspect "$i:latest" >/dev/null 2>&1 && echo "   ok  $i:latest" || echo "   build-필요 $i (자동)"; done
  echo "[5] 네트워크(external; 없으면 bringup가 생성)"
  for n in net_cellular net_sgi; do docker network inspect "$n" >/dev/null 2>&1 && echo "   ok  $n 존재" || echo "   create-예정 $n (자동)"; done
  echo "[6] provision 경로(split: epc_hss open5gs-dbctl → epc_mongo)"
  if docker ps --format '{{.Names}}' | grep -qx epc_hss; then
    docker exec epc_hss sh -c 'command -v open5gs-dbctl' >/dev/null 2>&1 && echo "   ok  epc_hss 에 open5gs-dbctl 존재" || { echo "   FAIL epc_hss 에 open5gs-dbctl 없음"; fail=1; }
    docker exec epc_mongo mongosh open5gs --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && echo "   ok  epc_mongo 도달" || echo "   WARN epc_mongo 미도달(현재)"
  else
    echo "   (epc_hss 미기동 — 이 경로는 EPC 기동 후 유효, 정적 확인 불가)"
  fi
  echo "[7] IMSI 정합 + 금지패턴 자기점검"
  grep -q '001010000000002' compose/configs/ran/ue2.conf 2>/dev/null && echo "   ok  attacker IMSI(001010000000002) 정합" || { echo "   FAIL ue2.conf IMSI 불일치"; fail=1; }
  # 주석·grep(자기참조) 라인 제외한 실제 명령에서만 금지패턴 탐지
  if grep -vE '^[[:space:]]*#|grep ' "$SPLIT/bringup.sh" | grep -qE 'docker-compose\.epc\.yml|up-all\.sh|--remove-orphans'; then echo "   FAIL 금지패턴(monolithic/orphans) 실사용"; fail=1; else echo "   ok  금지패턴 실사용 없음(monolithic epc.yml/up-all/--remove-orphans)"; fi
  echo
  [ "$fail" = 0 ] && { echo "== CHECK PASS (사전검증 통과 — 실제 실행 준비됨) =="; exit 0; } || { echo "== CHECK FAIL =="; exit 1; }
fi

# ─────────────────────────── 실제 콜드스타트 ───────────────────────────
# 0-pre) 서명키 자기치유(judge-runnable): git clone 배포는 시크릿(.mav-sign-key) 미포함이므로,
#   없으면 여기서 fresh 생성한다(64-hex, proxy sign/verify 가 같은 파일을 마운트 → 인스턴스 내 자체정합).
#   이미 존재하면(기존 서버와 '키 동일'로 전송한 경우 등) 보존한다. .env-aria 는 70-aria-up 이 동일 방식.
SIGN_KEY="$TB/.mav-sign-key"
if [ -s "$SIGN_KEY" ]; then
  echo "  .mav-sign-key 존재(보존)"
else
  openssl rand -hex 32 > "$SIGN_KEY" && chmod 600 "$SIGN_KEY" && echo "  .mav-sign-key 생성(fresh 64-hex · 자체정합)"
fi

# 0) external 네트워크 보장(split-epc 기동 전 필수). net_core 는 split compose 가 생성.
log "0/7 네트워크"
docker network inspect net_cellular >/dev/null 2>&1 || docker network create --subnet 10.44.0.0/24 net_cellular
docker network inspect net_sgi      >/dev/null 2>&1 || docker network create --subnet 172.30.0.0/24 net_sgi
for i in dahv2/epc dahv2/ran dahv2/air dahv2/web; do docker image inspect "$i:latest" >/dev/null 2>&1 || { log "이미지 빌드"; bash scripts/10-build-images.sh; docker build -t dahv2/web:latest images/web; break; }; done

log "1/7 분리코어 EPC"
docker compose -f "$EPC" up -d
for i in $(seq 1 30); do docker logs epc_upf 2>&1 | grep -q "PFCP associated" && break; sleep 2; done
docker logs epc_hss 2>&1 | grep -q "CONNECTED TO ..mme" && echo "  S6a OK" || echo "  (S6a 확인요)"
docker logs epc_upf 2>&1 | grep -q "PFCP associated" && echo "  PFCP OK" || echo "  (PFCP 확인요)"

log "2/7 가입자 등록(uav+attacker · idempotent)"
prov 001010000000001 00112233445566778899aabbccddeeff 63bfa50ee6523365ff14c1f45f88737d
prov 001010000000002 000102030405060708090a0b0c0d0e0f e8ed289deba952e4283b54e88e6183ca

log "3/7 RAN attach (★eNB→20s→UE 순차: ZMQ desync 회피)"
docker rm -f ran_enb uav_ue ran_enb2 attacker_ue >/dev/null 2>&1 || true
docker compose -f "$RAN" up -d ran_enb;  sleep 20
docker compose -f "$RAN" up -d uav_ue;       wait_tun uav_ue
docker compose -f "$RAN" up -d ran_enb2; sleep 20
docker compose -f "$RAN" up -d attacker_ue;  wait_tun attacker_ue

log "4/7 SGi 컨테이너 + 라우트 재적용"
docker compose -f "$SGI" up -d; sleep 3
docker exec sgi_test    ip route replace 10.45.0.0/16 via 172.30.0.2 >/dev/null 2>&1 || true
docker exec uav_ue      ip route replace 172.30.0.0/24 dev tun_srsue >/dev/null 2>&1 || true
docker exec attacker_ue ip route replace 172.30.0.0/24 dev tun_srsue >/dev/null 2>&1 || true
docker exec uav_ue ping -c2 -W2 172.30.0.10 >/dev/null 2>&1 && echo "  UE→SGi(gcs_proxy .10) 도달 OK" || echo "  (UE→SGi 미도달 — attach 확인)"

log "5/7 ARIA C2 lockstep (SITL+GPS+proxy+gcs)"; bash scripts/70-aria-up.sh
log "6/7 웹 대시보드(8080)"; bash scripts/80-web-up.sh

log "7/7 검증 (SITL 부팅 40s 대기 · 실기능 게이트만)"; sleep 40
bash scripts/71-verify-aria.sh || true
bash scripts/81-verify-web.sh  || true
echo
printf "\033[1;32m완료.\033[0m 컨테이너 %s개. 안정성: docker logs -f gcs_c2 로 2~3분 양방향 유지 확인.\n" "$(docker ps -q | wc -l)"
echo "대시보드: ssh -i <key> -L 8080:127.0.0.1:8080 ubuntu@<IP> → http://localhost:8080"
