#!/bin/bash
# epc-split-entrypoint.sh — 역할(ROLE)별 Open5GS NF 기동 (분리 코어).
# stock Open5GS 2.8 설정을 net_core 주소로 패치 + freeDiameter .conf(ListenOn/ConnectTo) 패치 + NF별 데몬.
# 라이브 원본 stock 설정 실측(2026-07-02) 기반. 클론에서 게이트 G-split-A/B/C로 최종 수렴.
#
# stock 주소(실측): mme gtpc/metrics=127.0.0.2, sgwc=127.0.0.3, smf=127.0.0.4, sgwu pfcp=127.0.0.6,
#   upf=127.0.0.7 / freeDiameter: mme ListenOn 127.0.0.2·hss ConnectTo 127.0.0.8 / hss 127.0.0.8 /
#   smf ListenOn 127.0.0.4·pcrf ConnectTo 127.0.0.9 / pcrf 127.0.0.9 (Diameter는 No_TLS).
set -e
cd /etc/open5gs
log(){ echo "[split:$ROLE] $*"; }

# net_core 고정 매핑 (compose와 일치)
MME=10.50.0.2; SGWC=10.50.0.3; SMF=10.50.0.4; SGWU=10.50.0.6; UPF=10.50.0.7; HSS=10.50.0.8; PCRF=10.50.0.9
# 사용자평면 GTP-U는 전부 net_cellular(단일주소) — eNB·sgwu·upf 동일 L2에서 S1-U/S5-U (F-TEID 교차망 회피)
S1U_IP=${S1U_IP:-10.44.0.16}; U_GTPU=${U_GTPU:-10.44.0.17}

common_patch(){  # CONFIG_SPEC: PLMN 001/01 · TAC 7
  sed -i 's/mcc: 999/mcc: 001/g; s/mnc: 70/mnc: 01/g' "$1" 2>/dev/null || true
  sed -i 's/^\( *\)tac: 1$/\1tac: 7/' "$1" 2>/dev/null || true
}
mongo_patch(){ sed -i 's#mongodb://localhost/open5gs#mongodb://epc_mongo/open5gs#' "$@" 2>/dev/null || true; }
wait_mongo(){ for i in $(seq 1 60); do mongosh "mongodb://epc_mongo/open5gs" --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 1; done; }

case "$ROLE" in
  hss)   # Diameter S6a (mme와 연동). ListenOn 127.0.0.8→HSS, ConnectTo mme 127.0.0.2→MME
    mongo_patch hss.yaml
    sed -i "s/127\.0\.0\.8/$HSS/g; s/127\.0\.0\.2/$MME/g" /etc/freeDiameter/hss.conf
    wait_mongo; log "HSS 기동 (Diameter $HSS)"; exec /usr/bin/open5gs-hssd
    ;;
  pcrf)  # Diameter Gx (smf와 연동). ListenOn 127.0.0.9→PCRF, ConnectTo smf 127.0.0.4→SMF
    mongo_patch pcrf.yaml
    sed -i "s/127\.0\.0\.9/$PCRF/g; s/127\.0\.0\.4/$SMF/g" /etc/freeDiameter/pcrf.conf
    wait_mongo; log "PCRF 기동 (Diameter $PCRF)"; exec /usr/bin/open5gs-pcrfd
    ;;
  mme)   # S1AP(외부) + S11(net_core) + S6a(→hss)
    common_patch mme.yaml
    sed -i '/s1ap:/,/address:/ s/127\.0\.0\.2/0.0.0.0/' mme.yaml               # S1AP 외부(eNB)
    sed -i "s/127\.0\.0\.2/$MME/g; s/127\.0\.0\.3/$SGWC/g; s/127\.0\.0\.4/$SMF/g" mme.yaml  # gtpc(S11)+metrics
    sed -i "s/127\.0\.0\.2/$MME/g; s/127\.0\.0\.8/$HSS/g" /etc/freeDiameter/mme.conf         # Diameter
    log "MME 기동 (S1AP 0.0.0.0 · S11 $MME · S6a→$HSS)"; exec /usr/bin/open5gs-mmed
    ;;
  sgwc)  # S11(net_core) + PFCP(→sgwu)
    sed -i "s/127\.0\.0\.3/$SGWC/g; s/127\.0\.0\.6/$SGWU/g" sgwc.yaml
    log "SGW-C 기동 (S11+PFCP $SGWC → sgwu $SGWU)"; exec /usr/bin/open5gs-sgwcd
    ;;
  smf)   # PFCP(→upf) + Gx(→pcrf)
    common_patch smf.yaml
    sed -i "s/127\.0\.0\.4/$SMF/g; s/127\.0\.0\.7/$UPF/g" smf.yaml            # pfcp/gtpc/gtpu/sbi/metrics + upf peer
    sed -i "s/127\.0\.0\.4/$SMF/g; s/127\.0\.0\.9/$PCRF/g" /etc/freeDiameter/smf.conf
    log "SMF 기동 (PFCP $SMF → upf $UPF · Gx→$PCRF)"; exec /usr/bin/open5gs-smfd
    ;;
  sgwu)  # PFCP(net_core) + GTP-U 단일(net_cellular — eNB·upf 모두 net_cellular에서 도달)
    # PFCP 블록만 net_core로 (stock pfcp/gtpu 둘 다 127.0.0.6이라 범위 분리 필수)
    sed -i "/pfcp:/,/gtpu:/ s/127\.0\.0\.6/$SGWU/" sgwu.yaml
    # GTP-U 블록: net_cellular 단일. stock gtpu=127.0.0.6
    sed -i "/gtpu:/,\$ s/^\( *\)- address: 127\.0\.0\.6/\1- address: ${S1U_IP}/" sgwu.yaml
    log "SGW-U 기동 (PFCP $SGWU · GTP-U $S1U_IP)"
    exec /usr/bin/open5gs-sgwud
    ;;
  upf)   # PFCP(net_core) + GTP-U(net_cellular, sgwu와 S5-U) + SGi(ogstun)
    sed -i "/gtpu:/,/session:/ s/127\.0\.0\.7/${U_GTPU}/" upf.yaml   # GTP-U → net_cellular
    sed -i "s/127\.0\.0\.7/$UPF/g" upf.yaml                          # PFCP/metrics → net_core
    ip tuntap add name ogstun mode tun 2>/dev/null || true
    ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
    ip link set ogstun up
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    log "UPF 기동 (PFCP+GTP-U $UPF · SGi ogstun 10.45.0.1/16)"; exec /usr/bin/open5gs-upfd
    ;;
  *) echo "[split] unknown ROLE=$ROLE"; exit 1 ;;
esac
