# air — ArduPilot Copter SITL + pymavlink/MAVProxy + OpenSSL(ARIA).
#   install-prereqs(root 거부·venv PATH) 회피 → 빌드 의존성 명시 설치 후 waf 직접 빌드.
#   fan-out은 MAVProxy(--out). 컨테이너: uav_sitl · uav_gps · uav_proxy · gcs_c2 · gcs_proxy 공유.
ARG UBUNTU=22.04
FROM ubuntu:${UBUNTU}
ARG ARDUPILOT_TAG=Copter-4.5.7
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates openssl tzdata \
      build-essential make pkg-config \
      python3 python3-pip python3-dev python3-setuptools python3-wheel python-is-python3 \
      iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*

# ArduPilot SITL 빌드/런타임 파이썬 의존성 (empy는 3.3.x 고정 — 4.x 비호환)
RUN pip3 install --no-cache-dir "empy==3.3.4" pexpect future pymavlink MAVProxy lxml

# ArduPilot SITL (Copter, --board sitl)
RUN git clone --depth 1 --branch ${ARDUPILOT_TAG} https://github.com/ArduPilot/ardupilot.git /ardupilot && \
    cd /ardupilot && git submodule update --init --recursive --depth 1
RUN cd /ardupilot && ./waf configure --board sitl && ./waf copter

ENV PATH="/ardupilot/build/sitl/bin:${PATH}"
CMD ["bash"]
