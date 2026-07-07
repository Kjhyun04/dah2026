# ran — srsRAN_4G (srsenb/srsue), ZMQ 가상 RF 활성. 소스 빌드, 태그 pin.
# 컨테이너: ran_enb · uav_ue 가 이 이미지 공유.
ARG UBUNTU=22.04
FROM ubuntu:${UBUNTU}
ARG SRSRAN_TAG=release_23_11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      git build-essential cmake pkg-config ca-certificates \
      libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev \
      libzmq3-dev iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${SRSRAN_TAG} https://github.com/srsran/srsRAN_4G.git /srsran && \
    mkdir -p /srsran/build && cd /srsran/build && \
    cmake ../ -DENABLE_ZEROMQ=ON && make -j"$(nproc)" && make install && ldconfig
CMD ["bash"]
