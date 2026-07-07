# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# dahv2/pfcp-poc — B 계층(코어망 PFCP/측면이동) 툴링 사이드카 · 골격(skeleton)
#
#   역할(doc13 §2·§3): tools_core = scapy 기반 PFCP PoC. pfcp_delete/pfcp_flood/
#   pivot_exploit/learn_seid/capture_s1u(registry sidecar="core") 를 baked 하여
#   `docker exec` 로 구동하는 장수 사이드카.
#
#   ★ vantage(doc13 §3): 이 사이드카의 네트워크 시야는 **net_core (pivot 후)** 다
#     (pivot 전 net_core 격리 ✗). 공격 원점 foothold 는 attacker_ue.
#     README.md "실행 전제(netns/네트워크 공유 + docker exec)" 참조.
#
#   ★ 이 이미지는 실행 주체가 아니다 — CMD 는 sleep, 실제 스크립트는 host 실행기가
#     `docker exec` 로만 호출(누수 0 · 종료계약). 금지: `docker run --rm` 단명 사이드카.
#
#   ★★ 오프라인 골격 — 실제 build/scp/배포는 통제단계. exec/ 는 통제단계에서 채운다.
# ─────────────────────────────────────────────────────────────────────────────

FROM ubuntu:22.04

LABEL org.dah.image="dahv2/pfcp-poc" \
      org.dah.role="tooling-sidecar" \
      org.dah.layer="B" \
      org.dah.note="offline-skeleton; exec filled at control stage"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── 시스템 패키지 ────────────────────────────────────────────────────────────
#   python3            : scapy(PFCP 패킷 크래프팅) 런타임
#   procps             : pkill(JOB 마커 정밀 종료, R1)
#   iproute2           : ss/ip(net_core 도달 확인·포트 발견)
#   util-linux         : setsid(R1)
#   coreutils          : timeout(R1)
#   tcpdump            : S1-U 캡처(오프라인 파싱, doc18 G-b — capture_s1u)
#   libpcap 은 tcpdump 의존으로 함께 설치됨(scapy L2 송수신).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        procps \
        iproute2 \
        util-linux \
        coreutils \
        tcpdump \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ── scapy 핀(골격 · 통제단계에서 host 와 정합 조정) ───────────────────────────
ARG SCAPY_VERSION=2.5.0
RUN pip3 install --break-system-packages "scapy==${SCAPY_VERSION}"

# ── baked PoC 스크립트 트리(exec_binding 정본) ────────────────────────────────
#   core_exec/ 하위(registry sidecar="core"): pfcp_delete.py · pfcp_flood.py ·
#   learn_seid.py · capture_s1u.sh · pivot_exploit.sh. 통제단계에서 read-only scp.
#   README.md 참조 — 이 저장소에는 경로 계약만 있고 스크립트는 만들지 않는다.
COPY exec/ /opt/dah/exec/

ENV PYTHONPATH=/opt/dah/exec \
    PYTHONUNBUFFERED=1
WORKDIR /opt/dah/exec

# 장수 사이드카: 살아만 있고 실제 작업은 host 실행기의 `docker exec` 로만.
CMD ["sleep", "infinity"]
