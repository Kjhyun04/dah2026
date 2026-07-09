# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# dahv2/air-tools — A/D 계층 툴링 사이드카 (pymavlink + OpenSSL(ARIA) · arducopter 불요)
#   ★ 빌드 태그 = dahv2/air-tools (./dah.sh build-tools). 테스트베드 SITL 이미지 dahv2/air 와 태그 구분.
#
#   역할(doc13 §2): tools_ue / tools_sgi 가 공유하는 "장수(long-lived) 툴링 사이드카".
#   attacker_ue 에는 python3·nc 조차 없으므로(srsRAN 이미지, doc13 §0) 도구 일체를
#   이 이미지에 baked → `docker exec <sidecar> <script>` 로만 구동한다.
#
#   ★ 이 이미지는 실행 주체가 아니다 — CMD 는 sleep 로 살아만 있고, 실제 스크립트는
#     전부 host 측 실행기가 `docker exec` 로 호출한다(누수 0 · 종료계약, doc09/§4).
#   ★ 금지: `docker run --rm` 단명 사이드카 · ENTRYPOINT 에서 공격 스크립트 자동실행.
#
#   ★★ 이 Dockerfile 은 오프라인 골격이다 — 실제 `docker build` 는 통제단계에서 수행.
#      vendor/aria_gcm.py 와 exec/ 스크립트 트리는 통제단계에서 read-only scp 로 채운다
#      (README.md "vendor / baked 스크립트 채움" 참조). 이 저장소는 테스트베드 무접속.
# ─────────────────────────────────────────────────────────────────────────────

FROM ubuntu:22.04

# 이미지 정체 라벨(R2). 런타임 사이드카 라벨(dahv2.owner=agent, dahv2.run_id=$RUN)은
# `docker create/run --label …` 로 실행기가 부여한다(이미지가 아니라 컨테이너 속성).
LABEL org.dah.image="dahv2/air-tools" \
      org.dah.role="tooling-sidecar" \
      org.dah.layer="A,D" \
      org.dah.note="offline-skeleton; vendor+exec filled at control stage"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── 시스템 패키지 ────────────────────────────────────────────────────────────
#   python3            : pymavlink · vendored AriaGCM(ctypes) 런타임
#   openssl / libssl3  : ARIA-256-GCM(EVP) — AriaGCM 이 libcrypto 를 ctypes 로 호출
#   procps             : pkill(JOB 마커 정밀 종료, R1) — 넓은 grep kill 금지
#   iproute2           : ss(포트 발견, doc14 §3) · ip(tun_srsue UE풀 IP 추출)
#   util-linux         : setsid(세션 분리 → in-container timeout kill, R1)
#   coreutils          : timeout(컨테이너 안 하드 타임아웃, R1)
#   ca-certificates    : pip TLS
#   arducopter/SITL 는 설치하지 않는다(우리는 클라이언트 측 툴링만).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        openssl \
        libssl3 \
        procps \
        iproute2 \
        util-linux \
        coreutils \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ── pymavlink 핀(R3 ③: host 주입기 ↔ 사이드카 버전 정합) ─────────────────────
#   host 에 설치된 pymavlink 와 **정확히 동일** 버전이어야 golden-frame 이 성립한다.
#   통제단계 build 시 `--build-arg PYMAVLINK_VERSION=<host와 동일>` 로 맞춘다.
ARG PYMAVLINK_VERSION=2.4.49
# ubuntu:22.04 pip(22.x)은 PEP668 미표기 → --break-system-packages 불요·미지원(제거).
RUN pip3 install "pymavlink==${PYMAVLINK_VERSION}"

# ── R3 ② build-time 방어: openssl libcrypto 가 aria-256-gcm 을 지원하는지 확인 ──
#   미지원 이미지가 만들어지는 것을 build 단계에서 차단(vendor 파일과 무관, EVP만 확인).
#   (init 의 R3 preflight 는 이 검사를 사이드카 안에서 runtime 으로 한 번 더 수행.)
RUN python3 - <<'PY'
import ctypes, ctypes.util
lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
lib.EVP_get_cipherbyname.restype = ctypes.c_void_p
lib.EVP_get_cipherbyname.argtypes = [ctypes.c_char_p]
if not lib.EVP_get_cipherbyname(b"aria-256-gcm"):
    raise SystemExit("FATAL(R3): openssl libcrypto lacks aria-256-gcm")
print("OK(R3): aria-256-gcm available in libcrypto")
PY

# ── vendor: testbed proxy/mav_aria_proxy.AriaGCM (ctypes over OpenSSL) ──────
#   ★ 이 저장소의 vendor/aria_gcm.py 는 **placeholder**(import 시 예외)다.
#     실제 파일은 통제단계에서 read-only scp(testbed/proxy/mav_aria_proxy.py 에서
#     AriaGCM+봉투파서만, doc18 D8)로 덮어쓴다. README.md 참조.
COPY vendor/ /opt/dah/vendor/

# ── baked 공격 스크립트 트리(exec_binding 정본, doc18 C5) ─────────────────────
#   dah_exec/ · ext_exec/ 하위 스크립트(registry.py script= 경로). 이 저장소에는
#   골격만 있고(또는 비어 있고), 통제단계에서 read-only scp 로 채운다. README.md 참조.
COPY exec/ /opt/dah/exec/
# baked 스크립트는 host 실행기가 argv[0] 로 직접 실행(shebang) → 실행권한 필요.
RUN chmod -R a+rx /opt/dah/exec

ENV PYTHONPATH=/opt/dah/vendor:/opt/dah/exec \
    PYTHONUNBUFFERED=1
WORKDIR /opt/dah/exec

# 장수 사이드카: 스스로는 아무 것도 실행하지 않고 살아만 있는다.
# 실제 작업은 host 실행기의 `docker exec` 로만 들어온다(R1 timeout/JOB 마커 안에서).
CMD ["sleep", "infinity"]
