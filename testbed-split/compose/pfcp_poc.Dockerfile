# PFCP PoC 전용 이미지 (scapy contrib.pfcp). dahv2/air에 scapy 없어 별도.
# 빌드:  docker build -t dahv2/pfcp-poc -f pfcp_poc.Dockerfile .
# 실행:  docker run -i --rm --network net_core -v ~/dah_exec:/exec dahv2/pfcp-poc \
#          python3 /exec/B_TM2_V3/pfcp_delete.py delete --target 10.50.0.7 --node-id 10.50.0.99 --seid 0x...
FROM python:3.11-slim
RUN pip install --no-cache-dir scapy && apt-get update -q \
    && apt-get install -y -q tcpdump iproute2 proxychains4 >/dev/null 2>&1 || true
WORKDIR /exec
CMD ["python3", "-c", "print('pfcp-poc ready: mount ~/dah_exec at /exec, run pfcp_delete.py')"]
