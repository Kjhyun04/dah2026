# epc — Open5GS (4G EPC 전 NF 바이너리) + 프로비저닝 도구(open5gs-dbctl, mongosh).
# 단일 컨테이너로 NF 7종을 프로세스로 구동(freeDiameter는 127.0.0.x/No_TLS 로 loopback 작동).
ARG UBUNTU=22.04
FROM ubuntu:${UBUNTU}
ARG OPEN5GS_VER=
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      software-properties-common gnupg ca-certificates curl \
      iproute2 iptables iputils-ping tcpdump && \
    add-apt-repository -y ppa:open5gs/latest && apt-get update && \
    if [ -n "$OPEN5GS_VER" ]; then apt-get install -y open5gs="$OPEN5GS_VER"; \
    else apt-get install -y open5gs; fi && \
    dpkg -s open5gs | grep -i '^Version' && \
    rm -rf /var/lib/apt/lists/*
# 프로비저닝: open5gs-dbctl(가입자 등록) + mongosh(DB 접근)
RUN curl -fsSL https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl \
      -o /usr/bin/open5gs-dbctl && chmod +x /usr/bin/open5gs-dbctl && \
    curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb.gpg --dearmor && \
    echo "deb [ signed-by=/usr/share/keyrings/mongodb.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
      > /etc/apt/sources.list.d/mongodb.list && \
    apt-get update && apt-get install -y --no-install-recommends mongodb-mongosh && \
    rm -rf /var/lib/apt/lists/*
CMD ["bash"]
