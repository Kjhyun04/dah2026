#!/bin/bash
# epc 엔트리포인트 — stock Open5GS 2.8 설정을 CONFIG_SPEC 값으로 패치 + ogstun + NF 기동.
set -e
EPC_IP="${EPC_IP:-10.44.0.10}"
cd /etc/open5gs

echo "[epc] 설정 패치 (PLMN 001/01 · TAC 7 · EEA2/EIA2 · 외부 바인드 · mongo)"
# S1AP 외부 바인드(eNB 도달) — s1ap 블록의 127.0.0.2 만 0.0.0.0 으로
sed -i '/s1ap:/,/address:/ s/127\.0\.0\.2/0.0.0.0/' mme.yaml
# PLMN / TAC
sed -i 's/mcc: 999/mcc: 001/g; s/mnc: 70/mnc: 01/g' mme.yaml
sed -i 's/^\( *\)tac: 1$/\1tac: 7/' mme.yaml
# PDCP 암호 우선순위 (EEA2 우선)
sed -i 's/^\( *\)ciphering_order.*/\1ciphering_order : [ EEA2, EEA1, EEA0 ]/' mme.yaml
# S1-U(SGW-U GTP-U) 외부 바인드 — gtpu 블록의 127.0.0.6 을 EPC IP 로(UPF 2152와 충돌 회피)
sed -i "/gtpu:/,/address:/ s/127\.0\.0\.6/$EPC_IP/" sgwu.yaml
# 가입자 DB (별도 mongo 컨테이너)
sed -i 's#mongodb://localhost/open5gs#mongodb://epc_mongo/open5gs#' hss.yaml pcrf.yaml

echo "[epc] ogstun (UPF 데이터 평면, UE풀 10.45.0.0/16)"
ip tuntap add name ogstun mode tun 2>/dev/null || true
ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
ip link set ogstun up
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "[epc] MongoDB(epc_mongo) 준비 대기 (HSS/PCRF 초기화 레이스 방지)"
for i in $(seq 1 60); do
  mongosh "mongodb://epc_mongo/open5gs" --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break
  sleep 1
done

echo "[epc] NF 기동 (hss·pcrf → sgwc·smf → sgwu·upf → mme)"
for d in hssd pcrfd sgwcd smfd sgwud upfd; do
  /usr/bin/open5gs-"$d" & sleep 1
done
sleep 2
echo "[epc] MME 포그라운드 기동 (S1AP)"
exec /usr/bin/open5gs-mmed
